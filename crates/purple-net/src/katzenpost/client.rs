//! A client for kpclientd's thin-client socket.
//!
//! The protocol is length-prefixed CBOR maps over a Unix socket, each map holding one
//! key that names the message. On connect the daemon sends its connection status (with
//! the Pigeonhole geometry) and a PKI document; the client answers with a session token.
//! After that every request carries a random query ID, and the reply names it, so many
//! requests can be in flight at once. One thread reads replies and hands each to the
//! caller waiting on its query ID.
//!
//! Only the calls purple needs are here: BACAP keypairs from a seed, encrypting a read or
//! write for one box, and the daemon's ARQ that sends it to a courier and waits.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use purple_ipc::{read_frame, write_frame};
use rand::RngCore;

use super::cbor::Value;

/// Largest frame either side sends. Matches the daemon's `thin.MaxMessageSize`; PKI
/// documents with post-quantum signatures are large.
const MAX_FRAME: usize = 40 * 1024 * 1024;
const QUERY_ID_LEN: usize = 16;
/// How many messages to wait through for one step of the handshake. The daemon may push a
/// PKI document at any time, so other messages are skipped.
const MAX_HANDSHAKE_MESSAGES: usize = 16;

/// Replica error codes in a `start_resending_encrypted_message` reply.
const BOX_NOT_FOUND: u64 = 1;
const TOMBSTONE: u64 = 11;

type QueryId = [u8; QUERY_ID_LEN];
/// Callers waiting for replies, by query ID. `None` once the connection is gone.
type Pending = Arc<Mutex<Option<HashMap<QueryId, Sender<Value>>>>>;

/// A connection to kpclientd.
#[derive(Debug)]
pub struct Client {
    writer: Mutex<UnixStream>,
    pending: Pending,
    max_payload: usize,
}

/// A BACAP stream's capabilities and its first box, all opaque to purple.
#[derive(Clone, Debug)]
pub struct Keypair {
    /// Lets the holder write the stream's boxes.
    pub write_cap: Vec<u8>,
    /// Lets the holder read and verify them.
    pub read_cap: Vec<u8>,
    /// The stream's first box.
    pub first_index: Vec<u8>,
}

/// A read or write for one box, encrypted for the courier and the replicas.
#[derive(Debug)]
pub struct Envelope {
    ciphertext: Vec<u8>,
    descriptor: Vec<u8>,
    hash: Vec<u8>,
}

/// What a box read through the courier found.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetched {
    /// What the box holds.
    Box(Vec<u8>),
    /// Never written, expired, or deleted.
    Nothing,
}

impl Client {
    /// Connect to the daemon at `path` and complete the handshake.
    ///
    /// # Errors
    /// Fails if the daemon can't be reached or the handshake goes wrong.
    pub fn connect(path: &Path) -> io::Result<Self> {
        Self::handshake(UnixStream::connect(path)?)
    }

    fn handshake(mut stream: UnixStream) -> io::Result<Self> {
        let status = recv_until(&mut stream, "connection_status_event")?;
        let max_payload = status
            .get("pigeonhole_geometry")
            .and_then(|geometry| geometry.get("MaxPlaintextPayloadLength"))
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid("kpclientd sent no Pigeonhole geometry"))?;
        recv_until(&mut stream, "new_pki_document_event")?;

        // A fresh token each time: purple doesn't resume sessions across restarts.
        let mut token = [0u8; QUERY_ID_LEN];
        rand::rng().fill_bytes(&mut token);
        send(
            &mut stream,
            "session_token",
            Value::map([("client_instance_token", Value::Bytes(token.to_vec()))]),
        )?;
        recv_until(&mut stream, "session_token_reply")?;

        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        spawn_reply_reader(stream.try_clone()?, Arc::clone(&pending));
        Ok(Self {
            writer: Mutex::new(stream),
            pending,
            max_payload,
        })
    }

    /// The most a box can hold, from the daemon's Pigeonhole geometry.
    #[must_use]
    pub const fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// The BACAP keypair for `seed`.
    ///
    /// # Errors
    /// Fails if the daemon fails or the connection is gone.
    pub fn new_keypair(&self, seed: &[u8; 32]) -> io::Result<Keypair> {
        let reply = self.call("new_keypair", vec![("seed", Value::Bytes(seed.to_vec()))])?;
        Ok(Keypair {
            write_cap: field(&reply, "write_cap")?,
            read_cap: field(&reply, "read_cap")?,
            first_index: field(&reply, "first_message_index")?,
        })
    }

    /// Encrypt writing `plaintext` to box `index` of the stream `write_cap` belongs to.
    ///
    /// # Errors
    /// Fails if the daemon fails or the connection is gone.
    pub fn encrypt_write(
        &self,
        plaintext: &[u8],
        write_cap: &[u8],
        index: &[u8],
    ) -> io::Result<Envelope> {
        let reply = self.call(
            "encrypt_write",
            vec![
                ("plaintext", Value::Bytes(plaintext.to_vec())),
                ("write_cap", Value::Bytes(write_cap.to_vec())),
                ("message_box_index", Value::Bytes(index.to_vec())),
            ],
        )?;
        envelope(&reply)
    }

    /// Encrypt reading box `index` of the stream `read_cap` belongs to.
    ///
    /// # Errors
    /// Fails if the daemon fails or the connection is gone.
    pub fn encrypt_read(&self, read_cap: &[u8], index: &[u8]) -> io::Result<Envelope> {
        let reply = self.call(
            "encrypt_read",
            vec![
                ("read_cap", Value::Bytes(read_cap.to_vec())),
                ("message_box_index", Value::Bytes(index.to_vec())),
            ],
        )?;
        envelope(&reply)
    }

    /// Send an encrypted write and wait for the courier's acknowledgement. The daemon
    /// retransmits until it gets one. A box that already exists counts as written.
    ///
    /// # Errors
    /// Fails if the write is refused or the connection is gone.
    pub fn send_write(&self, envelope: &Envelope, write_cap: &[u8]) -> io::Result<()> {
        let mut fields = resend_fields(envelope);
        fields.push(("write_cap", Value::Bytes(write_cap.to_vec())));
        let reply = self.call_resend(fields, None, &envelope.hash)?;
        match error_code(&reply) {
            0 => Ok(()),
            code => Err(io::Error::other(format!("box write failed: error {code}"))),
        }
    }

    /// Send an encrypted read and wait for what the box holds, giving up (and telling the
    /// daemon to stop retransmitting) after `timeout`. A box that hasn't been written
    /// answers at once; the daemon doesn't wait for it to appear.
    ///
    /// # Errors
    /// Fails on a timeout, if the read is refused, or if the connection is gone.
    pub fn send_read(
        &self,
        envelope: &Envelope,
        read_cap: &[u8],
        index: &[u8],
        timeout: Duration,
    ) -> io::Result<Fetched> {
        let mut fields = resend_fields(envelope);
        fields.extend([
            ("read_cap", Value::Bytes(read_cap.to_vec())),
            ("message_box_index", Value::Bytes(index.to_vec())),
            ("no_retry_on_box_id_not_found", Value::Bool(true)),
        ]);
        let reply = self.call_resend(fields, Some(timeout), &envelope.hash)?;
        match error_code(&reply) {
            0 => Ok(Fetched::Box(
                reply
                    .get("plaintext")
                    .and_then(Value::as_bytes)
                    .unwrap_or_default()
                    .to_vec(),
            )),
            BOX_NOT_FOUND | TOMBSTONE => Ok(Fetched::Nothing),
            code => Err(io::Error::other(format!("box read failed: error {code}"))),
        }
    }

    fn call_resend(
        &self,
        fields: Vec<(&str, Value)>,
        timeout: Option<Duration>,
        hash: &[u8],
    ) -> io::Result<Value> {
        let result = self.request("start_resending_encrypted_message", fields, timeout);
        if matches!(&result, Err(err) if err.kind() == io::ErrorKind::TimedOut) {
            // Best effort: if this fails, the connection is gone and the daemon drops
            // the retransmission with it.
            self.send_only(
                "cancel_resending_encrypted_message",
                vec![("envelope_hash", Value::Bytes(hash.to_vec()))],
            )
            .ok();
        }
        result
    }

    /// Send a request and wait for its reply; a nonzero `error_code` is an error.
    fn call(&self, name: &str, fields: Vec<(&str, Value)>) -> io::Result<Value> {
        let reply = self.request(name, fields, None)?;
        match error_code(&reply) {
            0 => Ok(reply),
            code => Err(io::Error::other(format!(
                "kpclientd {name} failed: error {code}"
            ))),
        }
    }

    fn request(
        &self,
        name: &str,
        mut fields: Vec<(&str, Value)>,
        timeout: Option<Duration>,
    ) -> io::Result<Value> {
        let mut query_id = [0u8; QUERY_ID_LEN];
        rand::rng().fill_bytes(&mut query_id);
        let (tx, rx) = mpsc::channel();
        self.pending
            .lock()
            .map_err(poisoned)?
            .as_mut()
            .ok_or_else(disconnected)?
            .insert(query_id, tx);
        fields.push(("query_id", Value::Bytes(query_id.to_vec())));
        let sent = send(
            &mut *self.writer.lock().map_err(poisoned)?,
            name,
            Value::map(fields),
        );
        let reply = sent.and_then(|()| wait(&rx, timeout));
        if reply.is_err()
            && let Some(pending) = self.pending.lock().map_err(poisoned)?.as_mut()
        {
            pending.remove(&query_id);
        }
        reply
    }

    fn send_only(&self, name: &str, mut fields: Vec<(&str, Value)>) -> io::Result<()> {
        let mut query_id = [0u8; QUERY_ID_LEN];
        rand::rng().fill_bytes(&mut query_id);
        fields.push(("query_id", Value::Bytes(query_id.to_vec())));
        send(
            &mut *self.writer.lock().map_err(poisoned)?,
            name,
            Value::map(fields),
        )
    }
}

fn wait(rx: &mpsc::Receiver<Value>, timeout: Option<Duration>) -> io::Result<Value> {
    let Some(timeout) = timeout else {
        return rx.recv().map_err(|_| disconnected());
    };
    rx.recv_timeout(timeout).map_err(|err| match err {
        RecvTimeoutError::Timeout => {
            io::Error::new(io::ErrorKind::TimedOut, "kpclientd took too long")
        }
        RecvTimeoutError::Disconnected => disconnected(),
    })
}

fn resend_fields(envelope: &Envelope) -> Vec<(&'static str, Value)> {
    vec![
        ("reply_index", Value::Uint(0)),
        (
            "envelope_descriptor",
            Value::Bytes(envelope.descriptor.clone()),
        ),
        (
            "message_ciphertext",
            Value::Bytes(envelope.ciphertext.clone()),
        ),
        ("envelope_hash", Value::Bytes(envelope.hash.clone())),
    ]
}

fn envelope(reply: &Value) -> io::Result<Envelope> {
    Ok(Envelope {
        ciphertext: field(reply, "message_ciphertext")?,
        descriptor: field(reply, "envelope_descriptor")?,
        hash: field(reply, "envelope_hash")?,
    })
}

fn field(reply: &Value, key: &'static str) -> io::Result<Vec<u8>> {
    reply
        .get(key)
        .and_then(Value::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("reply has no {key}")))
}

fn error_code(reply: &Value) -> u64 {
    reply.get("error_code").and_then(Value::as_u64).unwrap_or(0)
}

fn send(stream: &mut UnixStream, name: &str, body: Value) -> io::Result<()> {
    write_frame(stream, &Value::map([(name, body)]).encode(), MAX_FRAME)
}

fn recv(stream: &mut UnixStream) -> io::Result<Value> {
    let frame = read_frame(stream, MAX_FRAME)?.ok_or_else(disconnected)?;
    Value::decode(&frame)
}

/// Read until message `name` arrives, and return its body.
fn recv_until(stream: &mut UnixStream, name: &str) -> io::Result<Value> {
    for _ in 0..MAX_HANDSHAKE_MESSAGES {
        let msg = recv(stream)?;
        if let Some((got, body)) = msg.message()
            && got == name
        {
            return Ok(body.clone());
        }
    }
    Err(invalid("kpclientd's handshake went wrong"))
}

/// Hand each reply to whoever waits on its query ID, and drop everything else (status
/// updates, new PKI documents, replies nobody waits for). When the connection ends, every
/// waiting caller gets an error.
fn spawn_reply_reader(mut stream: UnixStream, pending: Pending) {
    thread::spawn(move || {
        while let Ok(msg) = recv(&mut stream) {
            let Some((name, reply)) = msg.message() else {
                continue;
            };
            if !name.ends_with("_reply") {
                continue;
            }
            let Some(query_id) = reply
                .get("query_id")
                .and_then(Value::as_bytes)
                .and_then(|id| QueryId::try_from(id).ok())
            else {
                continue;
            };
            let waiter = match pending.lock() {
                Ok(mut pending) => pending.as_mut().and_then(|p| p.remove(&query_id)),
                Err(_) => break,
            };
            if let Some(waiter) = waiter {
                // The caller may have timed out and gone; that's fine.
                waiter.send(reply.clone()).ok();
            }
        }
        // Dropping the senders wakes every waiting caller with an error.
        if let Ok(mut pending) = pending.lock() {
            pending.take();
        }
    });
}

fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "lost the connection to kpclientd",
    )
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn poisoned<T>(_: PoisonError<T>) -> io::Error {
    io::Error::other("kpclientd client lock poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Send the way kpclientd does: every field of its response type, all null but one.
    fn daemon_send(stream: &mut UnixStream, name: &str, body: Value) -> io::Result<()> {
        let msg = Value::map([
            ("session_token_reply", Value::Null),
            ("shutdown_event", Value::Null),
            (name, body),
            ("message_sent_event", Value::Null),
        ]);
        write_frame(stream, &msg.encode(), MAX_FRAME)
    }

    /// A fake daemon on the other end of a socket pair: does the handshake, then answers
    /// each request with `answer`.
    fn fake_daemon(answer: fn(&str, &Value) -> Option<Value>) -> (Client, thread::JoinHandle<()>) {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let daemon = thread::spawn(move || {
            let geometry = Value::map([("MaxPlaintextPayloadLength", Value::Uint(1677))]);
            daemon_send(
                &mut theirs,
                "connection_status_event",
                Value::map([
                    ("is_connected", Value::Bool(false)),
                    ("pigeonhole_geometry", geometry),
                ]),
            )
            .unwrap();
            daemon_send(
                &mut theirs,
                "new_pki_document_event",
                Value::map([("payload", Value::Bytes(vec![0xa0]))]),
            )
            .unwrap();
            let token = recv(&mut theirs).unwrap();
            assert_eq!(token.message().unwrap().0, "session_token");
            daemon_send(
                &mut theirs,
                "session_token_reply",
                Value::map([("resumed", Value::Bool(false))]),
            )
            .unwrap();
            while let Ok(msg) = recv(&mut theirs) {
                let (name, request) = msg.message().unwrap();
                let (name, request) = (name.to_owned(), request.clone());
                let Some(mut reply) = answer(&name, &request) else {
                    continue;
                };
                if let Value::Map(entries) = &mut reply {
                    entries.push((
                        Value::Text("query_id".into()),
                        request.get("query_id").unwrap().clone(),
                    ));
                }
                daemon_send(&mut theirs, &format!("{name}_reply"), reply).unwrap();
            }
        });
        (Client::handshake(ours).unwrap(), daemon)
    }

    fn answers(name: &str, request: &Value) -> Option<Value> {
        let bytes = |b: &[u8]| Value::Bytes(b.to_vec());
        match name {
            "new_keypair" => Some(Value::map([
                ("write_cap", request.get("seed")?.clone()),
                ("read_cap", bytes(b"r")),
                ("first_message_index", bytes(b"i")),
            ])),
            "encrypt_read" | "encrypt_write" => Some(Value::map([
                ("message_ciphertext", bytes(b"c")),
                ("envelope_descriptor", bytes(b"d")),
                ("envelope_hash", bytes(&[9; 32])),
            ])),
            "start_resending_encrypted_message" if request.get("read_cap").is_some() => {
                match request.get("message_box_index")?.as_bytes()? {
                    b"full" => Some(Value::map([("plaintext", bytes(b"hello"))])),
                    b"empty" => Some(Value::map([("error_code", Value::Uint(BOX_NOT_FOUND))])),
                    b"broken" => Some(Value::map([("error_code", Value::Uint(4))])),
                    _ => None, // never answered
                }
            }
            "start_resending_encrypted_message" => Some(Value::map([])),
            _ => None,
        }
    }

    #[test]
    fn handshake_reads_the_geometry() {
        let (client, _) = fake_daemon(answers);
        assert_eq!(client.max_payload(), 1677);
    }

    #[test]
    fn calls_get_their_own_replies() {
        let (client, _) = fake_daemon(answers);
        let keypair = client.new_keypair(&[5; 32]).unwrap();
        assert_eq!(keypair.write_cap, [5; 32]);
        assert_eq!(keypair.first_index, b"i");

        let envelope = client.encrypt_read(b"r", b"full").unwrap();
        let wait = Duration::from_secs(5);
        let read = |index: &[u8]| client.send_read(&envelope, b"r", index, wait);
        assert_eq!(read(b"full").unwrap(), Fetched::Box(b"hello".to_vec()));
        assert_eq!(read(b"empty").unwrap(), Fetched::Nothing);
        assert!(read(b"broken").is_err());

        let write = client.encrypt_write(b"x", b"w", b"i").unwrap();
        client.send_write(&write, b"w").unwrap();
    }

    #[test]
    fn concurrent_calls_are_routed_by_query_id() {
        let (client, _) = fake_daemon(answers);
        let client = Arc::new(client);
        let threads: Vec<_> = (0..8u8)
            .map(|n| {
                let client = Arc::clone(&client);
                thread::spawn(move || {
                    for _ in 0..20 {
                        assert_eq!(client.new_keypair(&[n; 32]).unwrap().write_cap, [n; 32]);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn reads_time_out() {
        let (client, _) = fake_daemon(answers);
        let envelope = client.encrypt_read(b"r", b"silent").unwrap();
        let err = client
            .send_read(&envelope, b"r", b"silent", Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // The connection still works afterwards.
        assert!(client.new_keypair(&[1; 32]).is_ok());
    }

    #[test]
    fn waiting_calls_fail_when_the_daemon_goes_away() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        spawn_reply_reader(ours.try_clone().unwrap(), Arc::clone(&pending));
        let client = Client {
            writer: Mutex::new(ours),
            pending,
            max_payload: 1677,
        };
        let closer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(theirs);
        });
        assert!(client.new_keypair(&[0; 32]).is_err());
        closer.join().unwrap();
        assert!(client.new_keypair(&[0; 32]).is_err());
    }
}
