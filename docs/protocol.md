```
purple                                                          November 2026
Protocol version: invite v2, content v1, queue v2
Status: Draft, describes the implementation in this repository


                     The purple Messaging Protocol
```

## Abstract

This document describes how purple clients exchange end-to-end encrypted messages
through an untrusted box store. It covers invites, the 1:1 and group encryption layers,
how messages are split into fixed-size packets, how packets are addressed and stored,
the client-to-store protocol, and how clients reach the store over Tor or, with the
user's consent, directly.

## Status of This Memo

This is a description of the protocol as implemented, not an Internet Standard, and it
has not been reviewed by anyone outside the project. The formats are not stable. When
the code and this document disagree, the code is right and this document has a bug.

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Protocol Overview
4. Common Encodings
5. Queues and Packet Sealing
6. Fragmentation
7. Invites
8. One-to-One Sessions
9. Groups
10. Box Addressing
11. Store Protocol
12. Reaching the Store
13. Client Behaviour
14. Security Considerations
15. IANA Considerations
16. References

Appendix A. Constants

## 1. Introduction

purple aims to hide who talks to whom from an adversary who can watch and modify all
network traffic and who may also run the server. Content confidentiality alone is not
enough for that, so the protocol has three goals:

1. The store learns nothing from the contents of what it holds. Every box holds 1536
   bytes that are indistinguishable from random, at an address that can't be linked to any
   other box by looking at it. What the store can still work out from who reads and writes
   which box, and when, is in Section 14.1.
2. To someone watching a user's connection, traffic looks the same whether the user is
   talking or idle. Clients write at a constant average rate, pad their reads, and get
   replies of one size.
3. Nothing a user registers anywhere identifies them. There are no accounts, usernames,
   phone numbers or device IDs. Contacts are added by exchanging an invite out of band. A
   user does have one long-term identity key, which their contacts and fellow group
   members see (Section 14.2).

The protocol has no server-side logic beyond "store this packet at this address if the
address is free" and "return what is at this address". All structure (who a box belongs
to, which boxes form a conversation, what order they go in) exists only on the clients.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear
in all capitals, as shown here.

All integers are unsigned and big-endian. `||` is concatenation. `HKDF(salt, ikm, info,
L)` is HKDF-SHA256 [RFC5869] extract-then-expand producing `L` bytes.

Box
: A write-once slot at the store that holds exactly one packet.

Packet
: Exactly 1536 bytes, the contents of one box.

Stream
: An append-only sequence of boxes numbered from 0, identified by a 32-byte stream seed.

Queue
: A stream together with the key that seals its packets. Both derive from a 32-byte
  queue secret.

Store
: The server that holds boxes. purple's own store is `purple-memory-alpha` (named
  `purple-store` before November 2026), published as a Tor onion service. Katzenpost's
  Pigeonhole storage can stand in for it.

Inviter, Accepter
: The user who creates an invite, and the user who accepts it.

Creator
: The user who created a group. Only the creator changes a group's membership.

## 3. Protocol Overview

```
   +---------------------------------------------------------------+
   | Content: text, hello, group control       (Sections 8.3, 9.4) |
   +---------------------------------------------------------------+
   | 1:1: libsignal PQXDH + triple ratchet               (Sect. 8) |
   | Group: MLS, X-Wing ciphersuite                      (Sect. 9) |
   +---------------------------------------------------------------+
   | Fragments: 1496 bytes each, 14-byte header           (Sect. 6) |
   +---------------------------------------------------------------+
   | Sealed packet: XChaCha20-Poly1305, 1536 bytes        (Sect. 5) |
   +---------------------------------------------------------------+
   | Box address: HKDF(stream seed, index)               (Sect. 10) |
   +---------------------------------------------------------------+
   | Store protocol: Put / Get                           (Sect. 11) |
   +---------------------------------------------------------------+
   | Tor onion service, or Noise NK over TCP             (Sect. 12) |
   +---------------------------------------------------------------+
```

A conversation between two users is two queues, one per direction. Each side writes its
messages into consecutive boxes of its send stream and reads the other side's stream in
order.

Connecting goes like this:

```
   Inviter (Bob)                    Store                  Accepter (Alice)
   -------------                    -----                  ----------------
   create invite I = (IK_B, K, store)
   write prekey bundle to
   bundle(K)[0..]  ---------------> boxes
                                                  <-- I (QR code / pasted text)
                                    boxes <-------- read bundle(K)[0..]
                                                    verify bundle against IK_B
                                                    start session (PQXDH)
                                                    pick secrets S_ab, S_ba
                                    boxes <-------- write Hello(S_ab, S_ba)
                                                    to intro(K)[0..]
   read intro(K)[0..] <------------ boxes
   finish PQXDH, learn S_ab, S_ba
   ...from now on: Alice writes queue(S_ab), Bob writes queue(S_ba)...
```

Groups use MLS. The creator invites contacts over their existing 1:1 sessions. Once in, all
members read and write one shared stream per MLS epoch, whose secret comes from the MLS
exporter.

## 4. Common Encodings

### 4.1. Length-prefixed fields

Unless a section says otherwise, a variable-length field is a 4-byte length followed by
that many bytes. A list is a 4-byte count followed by its items. Strings are UTF-8.

Decoders MUST reject truncated input and trailing bytes.

### 4.2. Frames

Messages on a byte stream (Section 11) are framed as a 4-byte length and a body. A
receiver MUST check the length against the largest frame it accepts before allocating
anything, and MUST treat a longer frame as a protocol error.

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Body length                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Body (variable)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 5. Queues and Packet Sealing

### 5.1. Key derivation

A queue secret `QS` is 32 bytes. It yields the stream seed and the sealing key:

```
   seed = HKDF(salt = "purple queue v2", ikm = QS, info = "stream", L = 32)
   key  = HKDF(salt = "purple queue v2", ikm = QS, info = "key",    L = 32)
```

Only the seed is ever given to the network process or the transport. The key can't be
derived from the seed, so nothing outside the key-holding process can read or forge a
queue's packets.

Secrets derived from other key material (Section 7.2) use:

```
   QS' = HKDF(salt = "purple queue v2", ikm = IKM, info = "derive:" || label, L = 32)
```

### 5.2. Sealed packets

A packet for box `i` of a queue carries exactly 1496 bytes of plaintext:

```
   nonce  = 24 random bytes
   ct     = XChaCha20-Poly1305(key, nonce, plaintext, aad = uint64(i))
   packet = nonce || ct                  (24 + 1496 + 16 = 1536 bytes)
```

Binding the index into the AAD means a packet copied to another position in the same
stream fails to open. The receiver MUST open box `i` with AAD `uint64(i)` and MUST drop a
packet that fails to authenticate.

## 6. Fragmentation

Every message, whatever its layer, is split into fragments that each fill one sealed
packet's plaintext (1496 bytes):

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                       Message ID (64)                         +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Fragment index        |         Fragment count        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Data length          |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                  Data, then zero padding                      |
   ~                  (1482 bytes in total)                        ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The message ID is 8 random bytes, fresh per message. Index and count are 16-bit, data
length is 16-bit. Fragments of one message go into consecutive boxes of one stream.

A sender MUST fill every fragment but the last with exactly 1482 data bytes. An empty
message is one fragment with no data. A message MUST NOT need more than 64 fragments
(94848 bytes). This gives every message exactly one valid encoding.

A receiver MUST reject a fragment where:

- the count is 0 or over 64,
- the index is not below the count,
- the data length runs past the fragment,
- any padding byte is non-zero,
- a non-final fragment is not full, or
- the final fragment of a multi-fragment message is empty.

The receiver reassembles per stream and accepts fragments in any order. An exact
duplicate of a fragment already held is ignored; a different fragment for the same
(message ID, index), or a changed count, is an error. A receiver SHOULD hold at most 32
incomplete messages per stream, dropping the oldest when a new one arrives, so a peer
that never finishes its messages can only waste its own stream.

## 7. Invites

### 7.1. Format

An invite is shown as a QR code or pasted as text. Its binary form (version 2) is:

```
   +---------+--------------------+-------------+-------+------------------+
   | Version | Identity key (33)  | Invite key  | Store | Store data       |
   |   (1)   | libsignal encoding |    (32)     |  (1)  | (Store = 3 only) |
   +---------+--------------------+-------------+-------+------------------+
```

- Version: 2. Version 1 invites didn't name a store and MUST be refused when pasted.
- Identity key: the inviter's libsignal identity key, a type byte and 32 bytes.
- Invite key `K`: 32 random bytes, fresh per invite.
- Store kind: 0 in-memory test network, 1 local dev provider, 2 Namenlos (Katzenpost),
  3 onion store.
- Store data, for kind 3: a 1-byte length and that many bytes of printable ASCII, at
  most 62 (a v3 onion host and ".onion").

The text form is the string `purple1` followed by the binary form in hex. Parsers MUST
accept either case of hex and ignore surrounding whitespace. The longest invite is 130
bytes, or 267 characters as text.

An accepter MUST refuse an invite whose store isn't the one it uses, because the
inviter's bundle would never be found there.

### 7.2. Invite queues

Two queues derive from the invite key:

```
   bundle queue: QS_bundle = derive(K, "bundle")
   intro queue:  QS_intro  = derive(K, "intro")
```

where `derive` is the construction in Section 5.1.

Anyone who sees the invite can read these queues. That is acceptable because the bundle is
public key material that is checked against the identity key in the invite, and the intro
message is sealed to the inviter's prekeys (Section 8.1), so only the inviter can open it.

### 7.3. Prekey bundle

When creating an invite, the inviter generates a one-time X25519 prekey, a signed X25519
prekey and a signed ML-KEM-1024 prekey, keeps the private halves, and writes the bundle
as one message (Section 6) to the bundle queue starting at box 0:

```
   uint32 one-time prekey ID      | uint16 len | one-time public key
   uint32 signed prekey ID        | uint16 len | signed public key
                                  | uint16 len | signed prekey signature
   uint32 Kyber prekey ID         | uint16 len | Kyber public key
                                  | uint16 len | Kyber prekey signature
```

Field lengths in the bundle are 16-bit, unlike Section 4.1. The identity key is not in
the bundle; the accepter takes it from the invite. The bundle's registration ID and
device ID are both 1 (see Section 8.1 for why every client uses these values).

The accepter MUST rebuild the bundle with the invite's identity key and let libsignal
verify both signatures before starting a session. A store that swaps in its own bundle
fails this check.

## 8. One-to-One Sessions

### 8.1. Handshake

The accepter processes the bundle with libsignal's PQXDH, which gives a session whose
first outgoing message is a PreKey message. The accepter then:

1. picks two fresh random queue secrets, `S_ab` (accepter to inviter) and `S_ba` (inviter
   to accepter),
2. encrypts a Hello (Section 8.3) carrying both,
3. seals the resulting PreKey message to the inviter's prekeys (below),
4. writes the sealed intro to the intro queue from box 0.

The inviter reads the intro queue, opens the seal, decrypts the PreKey message (which
completes PQXDH and consumes the one-time prekeys) and takes the two secrets from the
Hello. Both sides then forget the invite queues, and the inviter deletes the invite's
signed prekey.

A PreKey message carries its sender's identity key in the clear, and anyone who saw the
invite can read the intro queue. So the accepter seals it to the signed X25519 prekey
`SPK` and the ML-KEM prekey from the bundle, after libsignal has verified both:

```
   (e, E)      = fresh X25519 key pair
   dh          = X25519(e, SPK)
   (ss, kem)   = ML-KEM-1024.Encapsulate(Kyber prekey)
   key         = HKDF(salt = "purple intro seal v1", ikm = dh || ss,
                      info = E || SPK || kem, L = 32)
   sealed      = XChaCha20-Poly1305(key, nonce = 0, tagged PreKey message, aad = "")

   intro = 0x03 | uint32 signed prekey ID | uint32 Kyber prekey ID
                | E | kem | sealed            (each length-prefixed, Section 4.1)
```

`E`, `SPK` and `kem` are in libsignal's serialization. The key is used once, since `e` is
fresh, so the nonce is fixed. The inviter MUST refuse an intro that isn't sealed, that
doesn't open, or whose PreKey message names a different signed prekey than the seal.
Tag 3 MUST be rejected anywhere but the intro queue.

libsignal puts the sender's registration ID in the clear inside a PreKey message. Every
client MUST use registration ID 1 and device ID 1 for itself, both in the bundles it
publishes as inviter and in the PreKey messages it sends as accepter, since a per-install
value would let anyone who reads the intro queue recognise the accepter.

The Hello MUST be the first content on the intro queue. Any other content there is an
error, and a Hello received anywhere else MUST be rejected.

### 8.2. Encrypted messages

After the handshake each message is encrypted with libsignal's triple ratchet (the double
ratchet combined with the SPQR post-quantum ratchet) and carried as:

```
   +-----+-------------------------------------------+
   | Tag | libsignal serialized message (variable)   |
   +-----+-------------------------------------------+
     Tag 1: PreKeySignalMessage (carries the PQXDH handshake)
     Tag 2: SignalMessage (ordinary ratchet message)
```

Any other tag MUST be rejected. A tag 1 message only ever travels inside a sealed intro
(Section 8.1). That byte string is one message for fragmentation and goes
into the sender's send queue at the sender's next unused index.

### 8.3. Content

The plaintext inside a 1:1 message is:

```
   +---------+------+------------------------+
   | Version | Kind | Fields (kind-specific) |
   |   (1)   | (1)  |                        |
   +---------+------+------------------------+
```

Version is 1. Kinds:

| Kind | Name | Fields |
|---|---|---|
| 1 | Hello | 32-byte `S_ab`, then 32-byte `S_ba`, nothing else |
| 2 | Text | The rest of the plaintext, raw |
| 3 | GroupRequest | group name |
| 4 | GroupAccept | group name, MLS key package |
| 5 | GroupWelcome | group name, MLS Welcome, list of (identity key, name) |
| 6 | GroupLeave | group name |

Kinds 3 to 6 use the encoding in Section 4.1. Unknown versions or kinds MUST be rejected.

### 8.4. Verifying a contact

An invite is only as trustworthy as the channel it travelled over. Someone who changes it
on the way can sit between the two users, and someone who reads it can accept it first. To
detect both, each client can show a number for a contact:

```
   h      = SHA-512("purple fingerprint v1" || low || high)
   number = twelve groups of five decimal digits; group i is
            uint40(h[5i .. 5i+5]) mod 100000
```

where `low` and `high` are the two users' serialized identity keys (33 bytes each) in
byte order. Both users see the same number if and only if each holds the other's real
identity key. Users SHOULD compare it over a channel an attacker on the invite's channel
doesn't control, such as in person.

## 9. Groups

### 9.1. MLS configuration

Groups use MLS [RFC9420] with:

- ciphersuite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (X-Wing KEM, which has no
  IANA code point yet, so only OpenMLS-based clients interoperate),
- the ratchet tree extension in Welcome messages,
- pure ciphertext wire format: every handshake and application message is a
  PrivateMessage,
- two past epochs whose application messages still decrypt (MLS `max_past_epochs`),
- at most 50 members.

MLS messages are TLS-serialized `MLSMessage` structures.

### 9.2. Credentials

Each member generates a fresh Ed25519 signing key per group. The member's credential is a
BasicCredential whose identity is:

```
   identity key (33) || XEdDSA signature (64)
   signature over: "purple mls signing key v1" || MLS signature public key
```

The signature is made with the member's libsignal identity key. Every member MUST verify
the credential of every leaf against the leaf's signature key when it joins and after
every commit. Without this, a creator could attach anyone's identity key to a key the
creator holds.

### 9.3. Epoch streams

Each epoch has one stream that every member reads and writes:

```
   QS_epoch = MLS-Exporter("purple group stream v1", context = "", L = 32)
```

All group messages (application messages and commits) are fragmented into this stream.
When an epoch changes, every member starts the new epoch's stream at box 0. Members keep
reading the previous streams so messages sent just before a commit still arrive. A
client SHOULD drop an old stream once its next box has read as empty for 600 seconds and
none of the client's own writes to it are still unconfirmed. When it enters a new epoch,
it keeps the current stream and the two previous epochs' streams (matching the two past
epochs MLS can still decrypt, Section 9.1), and drops older ones unless they still hold
its own unconfirmed writes. So the usual bound is three streams, but a stream with writes
in flight is kept past it until they settle.

Several members can write to the same box. Section 13.3 covers how writers resolve that.

### 9.4. Membership

Only the creator commits. Since commits come from one member, they never conflict and need
no ordering. Members change only their own leaf, through Update proposals (below).

Adding a contact `C` to group `G`:

1. The creator sends `GroupRequest(G)` to `C` over their 1:1 session.
2. If `C` agrees, `C` generates a signing key and credential (Section 9.2) and answers
   `GroupAccept(G, key_package)`.
3. The creator MUST check that it asked `C`, that the group has room, that the key
   package is valid, that its credential names `C`'s identity key, and that `C` isn't a
   member already. All checks happen before anything is written to the group stream: a
   box left unfilled would stall every member's in-order read.
4. If the group already has other members, the creator sends a group application message
   `Names([(IK_C, name)])`, so members learn the newcomer's name before the commit.
5. The creator commits the Add to the current stream. A creator alone in the group writes
   no commit, since nobody would read it.
6. The creator sends `GroupWelcome(G, welcome, roster)` to `C` over 1:1. The roster is the
   creator's names for current members, by serialized identity key.

On receiving a Welcome, `C` MUST check every member's credential and that the creator
(the 1:1 peer who sent the Welcome) is a member.

Removing: the creator commits a Remove. A member who wants to leave sends
`GroupLeave(G)` over 1:1 and the creator commits the removal. A member MUST reject a
commit whose sender is not the creator.

Key updates: each member replaces its leaf key about once a day. When 24 hours have passed
since its leaf last changed, a member sends an MLS Update proposal to the current epoch's
stream, at most one per epoch. Every member MUST keep each Update proposal whose new
leaf's credential verifies to the sender's identity key, only the first such proposal
from each sender in the order read, because the creator's commit names proposals by
reference and every member must hold the same ones; it MUST ignore any other proposal. Kept proposals stay outside the MLS proposal store (an OpenMLS client can't send
application messages while that store is non-empty) and are loaded into it just before a
commit is built or processed. The creator commits the kept proposals 5 minutes after the
first one arrives, with an update path, which also replaces its own leaf; with no
proposals for 24 hours it commits a path alone. Before committing, the creator MUST leave
out any proposal with which the commit can't be built, so one member can't block commits.
Add and Remove commits carry no proposals. Any epoch change discards kept proposals, and
a proposal for an ended epoch fails with a wrong-epoch error and MUST be ignored; its
sender proposes again in the new epoch.

### 9.5. Group content

The plaintext of an MLS application message is:

```
   uint8 version (1) | uint8 kind | fields
     kind 1 Text:  body (length-prefixed)
     kind 2 Names: list of (identity key, name)
```

Receivers MUST drop an application message whose sender is not a member in the receiver's
current epoch. MLS still decrypts messages from the last two epochs, and a removed member
keeps those epochs' keys; without this rule they could go on posting until two more
commits had passed. The price is that a message a member sent just before being removed
is lost if it arrives after the removal.

Receivers MUST ignore Names from anyone but the creator. Names are display hints: a
member shows its own name for a member who is also its contact, and the creator's name
otherwise. Names MUST be 1 to 32 characters from `[A-Za-z0-9_-]`. The names "me" and
"unknown" are reserved and MUST be ignored.

## 10. Box Addressing

The client process that talks to the network sees stream seeds and indices. The store sees
neither. Each transport maps a box to an address with a one-way function:

```
   purple-memory-alpha, dev provider:
     addr = HKDF(salt = "purple box address v1", ikm = seed, info = uint64(index), L = 32)

   Pigeonhole (Katzenpost):
     bacap_seed = HKDF(salt = "purple pigeonhole box v1", ikm = seed,
                       info = uint64(index), L = 32)
```

On Pigeonhole each purple box is its own one-box BACAP stream derived from
`bacap_seed`, so any box costs the same to reach and replicas see unrelated box IDs.

Without the seed, one box's address says nothing about any other box's address.

## 11. Store Protocol

### 11.1. Messages

The client and store exchange frames (Section 4.2) whose body is:

```
   +-----+------------------+-----------------------------------------+
   | Tag | Box address (32) | Packet or padding (1536), all but Get   |
   +-----+------------------+-----------------------------------------+
```

| Tag | Name | Direction | After the address |
|---|---|---|---|
| 1 | Put | client to store | packet |
| 2 | Get | client to store | nothing |
| 3 | Found | store to client | packet |
| 4 | Empty | store to client | 1536 zero bytes |
| 5 | Stored | store to client | 1536 zero bytes |
| 6 | Taken | store to client | 1536 zero bytes |

Every reply from the store is 1569 bytes, whatever it says. Otherwise the size of what
comes back would tell anyone watching the client's connection whether a read found a box,
which is to say when the user receives a message. The zeros travel inside the encrypted
link to the store (Section 12).

The largest frame body is 1569 bytes. Any other tag, a wrong length, non-zero padding, or
trailing bytes is a protocol error. A client that sends a store-to-client message is in
error and the store closes the connection.

The store answers each request with exactly one reply, in request order: Put gets Stored
or Taken, Get gets Found or Empty. A client MAY send several requests before reading
replies; purple sends up to 16.

### 11.2. Store semantics

- Boxes are write-once. A Put to an address that holds a live packet changes nothing and
  is answered Taken.
- Reads don't consume. A Get returns the packet to anyone who asks, any number of times.
- Boxes expire. A box older than the retention period (default 7 days) reads as Empty and
  can be written again. When the store is over its size cap (default 50 GB) it deletes
  its oldest boxes first.
- The store SHOULD rate-limit writes per connection. purple-memory-alpha allows 10 a
  second with a burst of 10, and delays rather than refuses writes past that. Only Puts
  count. A client that pipelines more than 10 Puts at once (Section 11.1 allows 16) sees
  the replies past the tenth slow down, and the Gets behind them wait too, since replies
  come in order. purple clients write about 2 packets a second in total, spread over many
  connections, so in practice they stay under the limit.
- The store SHOULD close a connection that has sent nothing for 5 minutes.

purple-memory-alpha keeps boxes in one append-only segment file per hour, each record
being the 8-byte storage time, the address and the packet, so expiry and the size cap
delete whole files.

## 12. Reaching the Store

### 12.1. Tor

By default the client reaches the store's onion service through a local C tor, over
SOCKS5 with username authentication. tor runs with `IsolateSOCKSAuth`, so each distinct
username gets its own circuit. The username is the stream's isolation key:

```
   iso = hex(HKDF(salt = "purple tor isolation v1", ikm = seed, info = "", L = 16))
```

Every request for one stream goes over one connection on that stream's circuit, so a slow
circuit holds up only its own stream. Cover writes and padding reads (Section 13.2) go
over a random existing connection, or the circuit named `cover` if there is none, so they
never build circuits of their own.

### 12.2. Fallback

If Tor can't bootstrap, the client tries routes in this order, moving on when a route
makes no bootstrap progress for one minute:

1. Tor without bridges
2. built-in obfs4 bridges
3. Snowflake
4. built-in WebTunnel bridges

A route whose pluggable transport isn't installed is skipped. After the last one the
client reports itself blocked and waits for the user, who can paste bridge lines or ask
for a direct connection. Every start begins again at step 1.

### 12.3. Direct connection

A store MAY also listen on a TCP port for clients that can't use Tor at all. The client's
store config then holds that IP address, port and the store's static X25519 public key.

The direct link runs the Noise Protocol Framework [Noise] pattern
`Noise_NK_25519_ChaChaPoly_BLAKE2s`, with the client as initiator, an empty prologue and
empty handshake payloads. The client pins the store's static key, so no one in between can
pose as the store. Every Noise message, handshake and transport alike, is sent as a 2-byte
length and the ciphertext. Store protocol frames (Section 11) run inside the transport
messages.

A client MUST NOT connect directly unless the user explicitly chose to after Tor was
blocked, and that choice MUST NOT persist past the current run. The client SHOULD tell the
user what it costs: the store sees the client's IP address, and if both sides of a
conversation connect directly, it sees one IP address write a box and the other read it,
which tells it the two talk.

In purple, only a separate relay process ever opens the TCP connection, and only to the
one configured address. The network process runs Noise through it, so the relay sees only
ciphertext.

## 13. Client Behaviour

### 13.1. Writing

Packets go out at the ticks of a Poisson process, with a mean gap of 500 ms over Tor (2
packets a second), each gap clamped to between 1 ms and 10 times the mean. At each tick
the client writes its oldest queued real packet or, with nothing queued, a cover packet:
1536 random bytes to the address of a random (seed, index). A sealed real packet and a
cover packet look the same to everyone but the recipient.

A cover packet lands on a real stream's box only if a random 256-bit address matches one
in use, which can be ignored in practice. If it did happen first, the reader would fail to
open the cover packet and move past it (Section 13.2), and the real writer would get Taken
(Section 13.3). On a group stream the writer reseals into the next free box. On a 1:1
stream the writer reports the message as lost.

On Pigeonhole the Katzenpost client daemon sends its own decoy traffic, so purple writes
no cover packets there.

A real write that gets no answer is retried after 1 s, doubling to a maximum of 60 s,
until it lands. A cover write is tried once.

### 13.2. Reading

Every 2 seconds the client asks for the next box of every stream it reads. While a stream
holds an incomplete message, it also reads ahead: it asks for boxes next+1 through
next+16 that it doesn't already hold, and never further. This round is padded with reads of random addresses up to a
multiple of 16 and shuffled, so the store sees how many reads a client makes only to the
nearest 16. The client keeps at most 256 reads in flight.

Over Tor, each read waits a random time uniformly chosen in [0, 2 s) before it is sent,
so one client's reads, which go out together each poll, reach the store on their separate
circuits at unrelated times.

When a box turns up, the client reads the boxes it now wants straight away, without
waiting for the next poll and without padding.

A read that gets no answer is tried twice and then counts as Empty.

An Empty reply MUST NOT advance the stream: the client asks for the same box again next
poll. Section 13.3 depends on this, since a resealed or rewritten packet may land in a
box after a reader has already found it empty.

A receiver handles box `i` of a stream only when it is that stream's next box, holding
boxes read ahead until their turn. A box that holds a packet which fails to open or parse
still advances the stream, so one bad box can't block it. A receiver accepts boxes from
next through next+16 and MUST reject anything beyond, which is exactly the read-ahead
window, so a client never rejects its own read-ahead.

### 13.3. Taken boxes

A Taken reply means the box already held a packet. The client reads the box and:

- if it holds the packet the client wrote, the earlier write landed and nothing more is
  needed,
- if it reads as Empty, the store hasn't caught up, and the client writes the packet
  again,
- if it holds someone else's packet on a group stream, another member got there first.
  The client opens its own packet, reseals the fragment for the next free box after that
  one, and writes it there. Reading members skip packets they wrote themselves, by
  comparing a SHA-256 hash of each packet they wrote.
- if it holds someone else's packet on a 1:1 stream, only one user writes that stream, so
  something is wrong. The client reports the message as lost.

Two members who write the same group box therefore both get through, in some order that
every reader sees the same way.

### 13.4. State before sending

A client MUST save its state durably before sending any packet produced by the step that
changed that state. A crash after sending but before saving would otherwise restart from
an older ratchet state and could reuse a message key, or write a different packet into a
box that already holds one.

## 14. Security Considerations

### 14.1. What the store learns

The store sees fixed-size random packets at addresses that don't relate to each other,
the time each write and read arrives, and which Tor connection it arrives on. Over Tor it
doesn't see client IP addresses. It never sees content. From the pattern of requests,
though, a store that wants to can work out a good deal:

- Which writes are real. A cover packet goes to a random address that nobody ever reads. A
  real box was being polled every 2 seconds before it was written and is read afterwards.
  So cover traffic hides a user's activity from the network, not from the store, which
  sees when each stream carries a message and how many boxes long it is.
- Which reads are real. A real read asks for the same address until it fills; a padding
  read asks once. The store can count the streams in use.
- Which boxes form a stream, since each stream has its own circuit and connection.
- Which streams belong to one client, roughly. A client's connections all appear when
  purple starts and go when it stops. The read jitter and Poisson writes blur timing
  within a session but not that. Over days this groups a user's streams into one
  pseudonymous client.
- Which clients talk, once it has those groups: both ends of a stream touch the same
  boxes. A group stream is read by every member, so it also sees group sizes.

Over Tor none of this has an IP address attached. It gets one if a user connects
directly (Section 12.3), or if the store works with someone who watches users'
connections. Hiding the request pattern itself would take a mixnet in front of the store
or private information retrieval; purple has neither on this path.

The store can always drop, delay or refuse packets. Clients can't detect a store that
pretends a box is empty. Forging or moving packets fails authentication (Section 5.2).

### 14.2. Known leaks

- Follow-up reads after a box turns up (Section 13.2) are not padded, so a burst of reads
  right after a poll suggests that a stream had something in it.
- Read-ahead for long messages makes the real read count for that poll larger, which the
  padding hides only to the nearest 16.
- A client's constant send rate tells an observer purple is running, though not whether
  the user is talking.
- A user has one identity key. It is in every invite they make and every group credential
  they hold, so their contacts and fellow group members can tell, by comparing notes, that
  they know the same person.
- 1:1 queue secrets last as long as the contact. Someone who later obtains a device's
  vault and the store's records can tell when that conversation's past messages were sent.
- The seal on the intro (Section 8.1) hides the accepter's identity key from whoever saw
  the invite, but the prekey IDs on the bundle and on the seal are a counter, so they
  still show that person how many invites the inviter had made before this one.
- In direct mode the store sees the client's IP address (Section 12.3).
- Anyone who sees an invite can tell when it was used, by watching its bundle and intro
  queues. Invites SHOULD be passed over a channel the user trusts and used once.
- A member whose client hasn't run for longer than the box retention (7 days) misses the
  commits made meanwhile, since their boxes have expired, and stays in the old epoch.
  With daily key updates there is always such a commit. The client warns at start and the
  creator has to remove and re-add the member.

### 14.3. Cryptographic choices

1:1 sessions get post-quantum protection from PQXDH with ML-KEM-1024 and the SPQR ratchet.
Groups use X-Wing (X25519 combined with ML-KEM-768). On the Namenlos mixnet, the Sphinx
packet layer itself uses classical X25519.

Group members' identities rest on the identity-key signature in their credential
(Section 9.2), checked by every member, not on trust in the creator. The creator does
control who is in the group and the display names members see for people they don't know.

Daily key updates give members post-compromise security within about a day: a leaf key
stolen from a member's device stops decrypting new epochs once that member's next update
is committed. A creator that refuses to commit updates can withhold this.

### 14.4. Endpoint security

Endpoint compromise is out of scope for this protocol. purple's implementation splits the
client into sandboxed processes so that the process holding keys has no network access and
the process with network access holds no keys, but that is a property of the
implementation, not of the protocol.

## 15. IANA Considerations

This document has no IANA actions.

## 16. References

### 16.1. Normative References

[RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
  RFC 2119, March 1997.

[RFC5869]
: Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function
  (HKDF)", RFC 5869, May 2010.

[RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
  RFC 8174, May 2017.

[RFC9420]
: Barnes, R., Beurdouche, B., Robert, R., Millican, J., Omara, E., and K. Cohn-Gordon,
  "The Messaging Layer Security (MLS) Protocol", RFC 9420, July 2023.

[Noise]
: Perrin, T., "The Noise Protocol Framework", revision 34, 2018.

[PQXDH]
: Kret, E. and R. Schmidt, "The PQXDH Key Agreement Protocol", Signal, 2023.

### 16.2. Informative References

[RFC8439]
: Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, June 2018.

[Loopix]
: Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., and G. Danezis, "The Loopix Anonymity
  System", USENIX Security 2017.

[libsignal]
: Signal, "libsignal", https://github.com/signalapp/libsignal.

[OpenMLS]
: OpenMLS, https://github.com/openmls/openmls.

[Katzenpost]
: Katzenpost, https://katzenpost.network/.

## Appendix A. Constants

| Name | Value |
|---|---|
| Packet length | 1536 bytes |
| Sealed plaintext length | 1496 bytes |
| Fragment header | 14 bytes |
| Fragment data | 1482 bytes |
| Fragments per message, max | 64 |
| Incomplete messages held per stream | 32 |
| Stream seed length | 32 bytes |
| Invite, max | 130 bytes / 267 characters |
| Group members, max | 50 |
| Past MLS epochs kept (see note) | 2 |
| Old epoch stream drain time | 600 s |
| Member key update interval | 24 h |
| Update batching window | 5 min |
| Stale group warning | 7 days |
| Write rate over Tor, mean | 2 packets/s |
| Poll interval | 2 s |
| Read padding multiple | 16 |
| Read-ahead | 16 boxes |
| Reads in flight, max | 256 |
| Read jitter window | 2 s |
| Requests batched per connection | 16 |
| Store write limit per connection | 10/s |
| Store idle timeout | 5 min |
| Box retention | 7 days |
| Store size cap, default | 50 GB |
| Route stall timeout | 1 min |
| Store connection timeout | 2 min |

Note: two past epochs is how far back MLS still decrypts, and also how many old epoch
streams a client normally keeps. A client keeps an older stream beyond that while its own
writes to it are unconfirmed (Section 9.3), so it isn't a hard bound on streams.
