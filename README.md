# purple

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-purple)](https://www.gnu.org/licenses/agpl-3.0.html)
[![Rust 1.97+](https://img.shields.io/badge/rust-1.97%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Edition 2024](https://img.shields.io/badge/edition-2024-blue)](https://doc.rust-lang.org/edition-guide/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)](#requirements)
[![Status: experimental](https://img.shields.io/badge/status-experimental-red)](#status)

An end-to-end encrypted messenger for people who want to hide who they talk to, not only
what they say.

purple assumes the network is hostile. Your ISP, the server operator, or a state watching
the wires should learn as little as possible: no phone numbers, no usernames, no contact
directory, and traffic that looks the same whether you're chatting or idle.

## What it does

- 1:1 chats and group chats, plus files and images
- Contacts are added by invite only (`/invite`, `/accept`), there is no user directory
- Messages go to a box store reached as a Tor onion service, at a constant packet rate
  with cover traffic, so timing doesn't give away when you're talking
- If Tor is blocked, purple tries bridges, then asks before connecting to the store
  directly
- Your keys and history live in an encrypted vault, unlocked with a passphrase and
  optionally sealed to your TPM

Crypto comes from [libsignal](https://github.com/signalapp/libsignal) for 1:1 sessions and
[OpenMLS](https://github.com/openmls/openmls) with a post-quantum (X-Wing) ciphersuite for
groups.

## How it's put together

Each job runs in its own process and its own bubblewrap sandbox, with seccomp and
Landlock on top. The process that holds keys never touches the network, and the one that
touches the network never sees a key.

| Crate | Was | Job |
|---|---|---|
| `purple` | | Launcher: starts everything below, sandboxed, and wires up their sockets |
| `purple-data` | `purple-core` | Keys, crypto and the encrypted vault. No network, no display |
| `purple-subspace` | `purple-net` | Talks to the box store. Never holds keys |
| `purple-lcars` | `purple-ui` | Terminal UI. No network, no keys |
| `purple-cloak` | `purple-torctl` | Drives tor's control port and the bridge fallback |
| `purple-transporter` | `purple-relay` | Direct (non-Tor) connection to the store, started only if you ask |
| `purple-memory-alpha` | `purple-store` | The box store server, published as an onion service |
| `purple-combadge` | `purple-ipc` | Messages and framing between the processes |
| `purple-shields` | `purple-harden` | Hardening every process applies at startup |
| `purple-holodeck` | `purple-devprovider` | Local stand-in network for running several instances on one machine |

The component names are a nod to Star Trek: The Next Generation and Picard. "Was" gives
the name each crate had before November 2026, which older commits use.

## Requirements

- Linux with unprivileged user namespaces (for bubblewrap)
- Rust 1.97 or newer
- [`bwrap`](https://github.com/containers/bubblewrap) and [`tor`](https://www.torproject.org/)
  on your `PATH`
- A Wayland session

## Getting started

Build everything:

```sh
cargo build --release
```

Run the self-test, which uses an in-memory network and finishes in a few seconds:

```sh
./target/release/purple --no-ui
```

To chat for real you need a store. Run `purple-memory-alpha` on a machine with tor,
publish its socket as an onion service, then tell the client where it is in
`~/.config/purple/store.conf`:

```
onion <56-char-address>.onion:<port>
# optional, for when Tor is blocked:
# direct <ip>:<port> <store's 64-hex-char Noise public key>
```

Then start the TUI:

```sh
./target/release/purple
```

Type `/help` once it's open. The commands you'll want first are `/invite NAME` and
`/accept NAME INVITE`.

## Status

Early and experimental. The protocol and vault format can still change without a
migration path, and nothing here has been audited. Please don't rely on it for anything
that matters yet.

## License

[AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.html), because libsignal is.
