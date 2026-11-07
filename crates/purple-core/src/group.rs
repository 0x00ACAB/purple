//! One group: its MLS state and the streams of boxes its members share.
//!
//! Each epoch has one stream, whose secret comes from the MLS exporter. Every member writes
//! to it and reads it in order. A commit moves everyone to the next epoch's stream at box
//! 0; the old stream is still read until it has been empty for [`DRAIN_SECS`], so messages
//! sent just before the commit still arrive. Only the creator commits, so commits never
//! conflict and nothing has to order them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use libsignal_protocol::IdentityKey;
use openmls::prelude::{
    ContentType, GroupId, KeyPackage, LeafNodeParameters, MlsGroup, ProcessMessageError,
    ProcessedMessageContent, Proposal, ProtocolMessage, QueuedProposal, Sender, StagedWelcome,
    ValidationError,
};
use openmls_traits::OpenMlsProvider;
use purple_ipc::{BoxRef, Packet, StreamSeed};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::credential;
use crate::messenger::{Outgoing, outgoing, valid_name};
use crate::mls::{self, PAST_EPOCHS, Provider, SigningKey, mls_error};
use crate::queue::{Queue, QueueSecret};
use crate::session::{Account, Error, Result};

/// Most members a group may have. The Welcome for the 50th is about 78 KB, which still fits
/// one message.
pub const MAX_MEMBERS: usize = 50;
/// How long a member's leaf key lives before they propose a fresh one.
pub const UPDATE_SECS: u64 = 24 * 3600;
/// How long the creator holds update proposals before committing them, so proposals sent
/// close together share one commit.
pub const BATCH_SECS: u64 = 5 * 60;
/// A member whose purple last ran longer ago than this may have missed a commit whose
/// boxes the store has expired (it keeps boxes 7 days).
pub const STALE_SECS: u64 = 7 * 24 * 3600;
/// How often the last-seen time is saved while purple runs.
const SEEN_SAVE_SECS: u64 = 3600;
/// An old epoch's stream is dropped once it has read as empty for this long. A write takes
/// up to half a minute on Namenlos and is retried for longer, so this is generous.
pub const DRAIN_SECS: u64 = 600;

const EXPORTER_LABEL: &str = "purple group stream v1";
/// Names purple shows on its own: this user, and a member nobody named.
const RESERVED_NAMES: [&str; 2] = ["me", "unknown"];
const SECRET_LEN: usize = 32;

const CONTENT_VERSION: u8 = 1;
const KIND_TEXT: u8 = 1;
const KIND_NAMES: u8 = 2;

/// What goes inside an MLS application message.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupContent {
    /// A text message.
    Text(Vec<u8>),
    /// The creator's names for members, by identity key, so members who aren't each
    /// other's contacts have something to call each other.
    Names(Vec<(Vec<u8>, String)>),
}

impl GroupContent {
    /// Encode for an application message.
    ///
    /// # Errors
    /// Fails only on absurd lengths.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::default();
        w.u8(CONTENT_VERSION);
        match self {
            Self::Text(body) => {
                w.u8(KIND_TEXT);
                w.bytes(body)?;
            }
            Self::Names(names) => {
                w.u8(KIND_NAMES);
                w.len(names.len())?;
                for (identity, name) in names {
                    w.bytes(identity)?;
                    w.bytes(name.as_bytes())?;
                }
            }
        }
        Ok(w.finish())
    }

    /// Decode an application message's contents.
    ///
    /// # Errors
    /// Fails on an unknown version or kind, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != CONTENT_VERSION {
            return Err(Error::Malformed("unknown group content version"));
        }
        let content = match r.u8()? {
            KIND_TEXT => Self::Text(r.bytes()?.to_vec()),
            KIND_NAMES => {
                let mut names = Vec::new();
                for _ in 0..r.len()? {
                    names.push((r.bytes()?.to_vec(), r.string()?));
                }
                Self::Names(names)
            }
            _ => return Err(Error::Malformed("unknown group content kind")),
        };
        r.finish()?;
        Ok(content)
    }
}

/// What one MLS message read from a group's streams meant.
#[derive(Debug)]
pub enum Received {
    /// A member sent text.
    Text {
        /// The sender's identity key, checked against their credential.
        from: IdentityKey,
        /// The text.
        body: Vec<u8>,
    },
    /// The creator named members.
    Names(Vec<(Vec<u8>, String)>),
    /// The creator added or removed members.
    Membership {
        /// Identity keys added.
        added: Vec<IdentityKey>,
        /// Identity keys removed.
        removed: Vec<IdentityKey>,
    },
    /// The creator removed this user.
    Removed,
    /// The creator added a member whose credential doesn't hold up.
    Forged,
    /// Nothing for the user: an update proposal (stored), or something ignored.
    Nothing,
}

/// One epoch's stream.
pub struct GroupStream {
    secret: QueueSecret,
    /// Next box to read.
    pub next_read: u64,
    /// Next box this user believes is free to write.
    next_write: u64,
    /// Boxes this user wrote that haven't been read back, with each packet's hash.
    mine: BTreeMap<u64, [u8; 32]>,
    /// When the next box was first found empty, for an old stream.
    empty_since: Option<u64>,
}

impl fmt::Debug for GroupStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupStream")
            .field("next_read", &self.next_read)
            .finish_non_exhaustive()
    }
}

fn digest(packet: &Packet) -> [u8; 32] {
    Sha256::digest(packet.as_bytes()).into()
}

impl GroupStream {
    const fn new(secret: QueueSecret) -> Self {
        Self {
            secret,
            next_read: 0,
            next_write: 0,
            mine: BTreeMap::new(),
            empty_since: None,
        }
    }

    /// The stream seed and sealing key.
    ///
    /// # Errors
    /// Fails only if HKDF does.
    pub fn queue(&self) -> Result<Queue> {
        self.secret.queue()
    }

    /// The next box was read.
    pub(crate) fn advance(&mut self) -> Result<()> {
        self.next_read = self
            .next_read
            .checked_add(1)
            .ok_or(Error::State("stream index exhausted"))?;
        self.empty_since = None;
        Ok(())
    }

    /// Box `index` was read and holds `packet`. Returns whether it's one this user wrote,
    /// so it can be skipped.
    ///
    /// Someone else's packet in a box this user also wrote leaves the record in place: this
    /// user's packet hasn't landed, and moves on when its write is reported taken.
    pub(crate) fn read_back(&mut self, index: u64, packet: &Packet) -> bool {
        if self.mine.get(&index) == Some(&digest(packet)) {
            self.mine.remove(&index);
            return true;
        }
        false
    }

    /// Fragment and seal `message` for the next boxes this user believes are free.
    fn place(&mut self, message: &[u8]) -> Result<Outgoing> {
        let first = self.next_write.max(self.next_read);
        let (out, next) = outgoing(&self.queue()?, first, message)?;
        for (at, packet) in &out.writes {
            self.mine.insert(at.index, digest(packet));
        }
        self.next_write = next;
        Ok(out)
    }

    /// Box `index` turned out to hold someone else's packet. Seal what this user meant to
    /// put there (`kept`) for the next free box instead.
    pub(crate) fn replace(&mut self, index: u64, kept: &Packet) -> Result<(BoxRef, Packet)> {
        let queue = self.queue()?;
        let fragment = queue.open(index, kept)?;
        self.mine.remove(&index);
        let after = index
            .checked_add(1)
            .ok_or(Error::State("stream index exhausted"))?;
        let at = self.next_write.max(self.next_read).max(after);
        let packet = queue.seal(at, &fragment)?;
        self.mine.insert(at, digest(&packet));
        self.next_write = at
            .checked_add(1)
            .ok_or(Error::State("stream index exhausted"))?;
        Ok((
            BoxRef {
                stream: queue.stream(),
                index: at,
            },
            packet,
        ))
    }
}

/// A key package for joining a group, and the signing key inside it.
///
/// # Errors
/// Fails if key generation or signing fails.
pub(crate) fn key_package(provider: &Provider, account: &Account) -> Result<(SigningKey, Vec<u8>)> {
    let key = SigningKey::generate(provider)?;
    let credential = credential::issue(account, key.public())?;
    let bundle = KeyPackage::builder()
        .build(
            mls::CIPHERSUITE,
            provider,
            &key.signer(provider),
            credential,
        )
        .map_err(mls_error)?;
    let bytes = mls::encode_message(bundle.key_package().clone())?;
    Ok((key, bytes))
}

/// One group this user belongs to.
pub struct Group {
    mls: MlsGroup,
    key: SigningKey,
    /// The contact who created the group, or `None` if this user did.
    creator: Option<String>,
    /// The current epoch's stream first, then older ones still being read.
    streams: Vec<GroupStream>,
    /// The creator's names for members, by serialized identity key.
    names: BTreeMap<Vec<u8>, String>,
    /// Contacts asked to join who haven't answered (creator only).
    asked: BTreeSet<String>,
    /// This user's leaf key changed in a commit merged since the last tick, which stamps
    /// the time into `last_update`.
    landed: bool,
    /// The epoch this user's own update proposal waits in, if any.
    proposed_in: Option<u64>,
    /// When this user's leaf key last changed (unix seconds).
    last_update: u64,
    /// When the creator commits the update proposals it holds (creator only).
    batch_until: Option<u64>,
    /// When purple last ran with this group (unix seconds), saved about hourly. `None`
    /// until the first tick after an upgrade from snapshot version 5.
    last_seen: Option<u64>,
    /// Update proposals read in this epoch, this user's own included: the first from each
    /// sender that keeps their identity, so every member holds the same ones. They stay out of
    /// OpenMLS's proposal store, because OpenMLS refuses to send while it holds any; they
    /// go in only just before an update commit is built or processed.
    held: Vec<QueuedProposal>,
}

/// What a tick asked of a group: a packet to write, and whether its state changed.
#[derive(Debug, Default)]
pub(crate) struct Tick {
    pub(crate) out: Option<Outgoing>,
    pub(crate) changed: bool,
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("creator", &self.creator)
            .finish_non_exhaustive()
    }
}

impl Group {
    /// A new group with this user as its only member and creator.
    pub(crate) fn create(provider: &Provider, account: &Account) -> Result<Self> {
        let key = SigningKey::generate(provider)?;
        let credential = credential::issue(account, key.public())?;
        let mls = MlsGroup::new(
            provider,
            &key.signer(provider),
            &mls::create_config(),
            credential,
        )
        .map_err(mls_error)?;
        let mut group = Self {
            mls,
            key,
            creator: None,
            streams: Vec::new(),
            names: BTreeMap::new(),
            asked: BTreeSet::new(),
            landed: true,
            proposed_in: None,
            last_update: 0,
            batch_until: None,
            last_seen: None,
            held: Vec::new(),
        };
        group.enter_epoch(provider)?;
        Ok(group)
    }

    /// Join from the creator's Welcome. Every member's credential is checked, and the
    /// creator must be one of them.
    pub(crate) fn join(
        provider: &Provider,
        key: SigningKey,
        creator: String,
        creator_identity: &IdentityKey,
        welcome: &[u8],
        names: Vec<(Vec<u8>, String)>,
    ) -> Result<Self> {
        let welcome = mls::decode_welcome(welcome)?;
        let mls = StagedWelcome::new_from_welcome(provider, &mls::join_config(), welcome, None)
            .map_err(mls_error)?
            .into_group(provider)
            .map_err(mls_error)?;
        let mut group = Self {
            mls,
            key,
            creator: Some(creator),
            streams: Vec::new(),
            names: BTreeMap::new(),
            asked: BTreeSet::new(),
            landed: true,
            proposed_in: None,
            last_update: 0,
            batch_until: None,
            last_seen: None,
            held: Vec::new(),
        };
        let checked = group.identities().and_then(|members| {
            if members.contains(creator_identity) {
                Ok(())
            } else {
                Err(Error::State(
                    "the Welcome is for a group its sender isn't in",
                ))
            }
        });
        if let Err(err) = checked.and_then(|()| group.enter_epoch(provider)) {
            group.delete(provider)?;
            return Err(err);
        }
        group.learn_names(names);
        Ok(group)
    }

    /// The creator, if it isn't this user.
    pub(crate) fn creator(&self) -> Option<&str> {
        self.creator.as_deref()
    }

    /// This user's leaf encryption key, to see it change.
    #[cfg(test)]
    pub(crate) fn leaf_key(&self) -> Vec<u8> {
        mls::own_leaf_key(&self.mls).unwrap()
    }

    pub(crate) fn member_count(&self) -> usize {
        self.mls.members().count()
    }

    /// Every member's identity key, after checking each member's credential.
    pub(crate) fn identities(&self) -> Result<Vec<IdentityKey>> {
        self.mls
            .members()
            .map(|member| credential::verify(&member.credential, &member.signature_key))
            .collect()
    }

    /// Record that `contact` was asked to join. False if they already were.
    pub(crate) fn ask(&mut self, contact: String) -> bool {
        self.asked.insert(contact)
    }

    /// Forget that `contact` was asked. Returns whether they had been.
    pub(crate) fn cancel_ask(&mut self, contact: &str) -> bool {
        self.asked.remove(contact)
    }

    pub(crate) fn asked_count(&self) -> usize {
        self.asked.len()
    }

    /// The creator's name for `identity`.
    pub(crate) fn name_for(&self, identity: &IdentityKey) -> Option<&str> {
        self.names.get(&*identity.serialize()).map(String::as_str)
    }

    /// Take names from the creator, ignoring any that aren't safe to show. "me" and
    /// "unknown" are what purple itself shows for this user and for nameless members, so a
    /// creator can't hand them to someone else.
    pub(crate) fn learn_names(&mut self, names: Vec<(Vec<u8>, String)>) {
        for (identity, name) in names {
            if valid_name(&name) && !RESERVED_NAMES.contains(&name.as_str()) {
                self.names.insert(identity, name);
            }
        }
    }

    /// Add the contact whose key package this is; they must be `expected`. Returns the
    /// commit for the current stream (`None` if this user was alone, since nobody would
    /// read it) and the Welcome to send them. The messenger checks and adds in two steps
    /// (see [`Self::check_key_package`]); this is the one-call form for tests.
    #[cfg(test)]
    pub(crate) fn add(
        &mut self,
        provider: &Provider,
        key_package: &[u8],
        expected: &IdentityKey,
    ) -> Result<(Option<Outgoing>, Vec<u8>)> {
        let checked = self.check_key_package(provider, key_package, expected)?;
        self.add_checked(provider, checked)
    }

    /// Everything that can go wrong with adding this key package, checked before anything
    /// is written: this user must be the creator, the group not full, and the key package
    /// valid, from `expected`, and not from a member already.
    pub(crate) fn check_key_package(
        &self,
        provider: &Provider,
        key_package: &[u8],
        expected: &IdentityKey,
    ) -> Result<KeyPackage> {
        if self.creator.is_some() {
            return Err(Error::State("only the group's creator adds members"));
        }
        if self.member_count() >= MAX_MEMBERS {
            return Err(Error::State("groups are capped at 50 members"));
        }
        let key_package = mls::decode_key_package(provider, key_package)?;
        let leaf = key_package.leaf_node();
        let identity = credential::verify(leaf.credential(), leaf.signature_key().as_slice())?;
        if identity != *expected {
            return Err(Error::State("that key package isn't from this contact"));
        }
        if self.identities()?.contains(&identity) {
            return Err(Error::State("already a member"));
        }
        Ok(key_package)
    }

    /// Add a key package [`Self::check_key_package`] accepted.
    pub(crate) fn add_checked(
        &mut self,
        provider: &Provider,
        key_package: KeyPackage,
    ) -> Result<(Option<Outgoing>, Vec<u8>)> {
        let alone = self.member_count() == 1;
        let before = mls::own_leaf_key(&self.mls)?;
        let (commit, welcome, _) = self
            .mls
            .add_members_without_update(provider, &self.key.signer(provider), &[key_package])
            .map_err(mls_error)?;
        self.mls.merge_pending_commit(provider).map_err(mls_error)?;
        let commit = if alone {
            None
        } else {
            Some(self.current()?.place(&mls::encode_message(commit)?)?)
        };
        self.enter_epoch(provider)?;
        self.note_leaf(&before)?;
        Ok((commit, mls::encode_message(welcome)?))
    }

    /// Remove the member with this identity key. Returns the commit for the current stream.
    pub(crate) fn remove(
        &mut self,
        provider: &Provider,
        identity: &IdentityKey,
    ) -> Result<Outgoing> {
        if self.creator.is_some() {
            return Err(Error::State("only the group's creator removes members"));
        }
        let own = self.mls.own_leaf_index();
        let leaf = self
            .mls
            .members()
            .find(|member| {
                member.index != own
                    && credential::verify(&member.credential, &member.signature_key)
                        .is_ok_and(|found| found == *identity)
            })
            .map(|member| member.index)
            .ok_or(Error::State("not a member of this group"))?;
        let before = mls::own_leaf_key(&self.mls)?;
        let (commit, _, _) = self
            .mls
            .remove_members(provider, &self.key.signer(provider), &[leaf])
            .map_err(mls_error)?;
        self.mls.merge_pending_commit(provider).map_err(mls_error)?;
        let out = self.current()?.place(&mls::encode_message(commit)?)?;
        self.enter_epoch(provider)?;
        self.note_leaf(&before)?;
        Ok(out)
    }

    /// Encrypt `content` for the group, placed in the current stream.
    pub(crate) fn send(&mut self, provider: &Provider, content: &GroupContent) -> Result<Outgoing> {
        let message = self
            .mls
            .create_message(provider, &self.key.signer(provider), &content.encode()?)
            .map_err(mls_error)?;
        self.current()?.place(&mls::encode_message(message)?)
    }

    /// Propose a fresh leaf key for this user, placed in the current stream. The creator
    /// commits it (see [`Self::commit_updates`]). One proposal per epoch.
    pub(crate) fn propose_update(&mut self, provider: &Provider) -> Result<Outgoing> {
        if self.creator.is_none() {
            return Err(Error::State("the creator updates its key by committing"));
        }
        let epoch = self.mls.epoch().as_u64();
        if self.proposed_in == Some(epoch) {
            return Err(Error::State("an update is already waiting for the creator"));
        }
        let (proposal, _) = self
            .mls
            .propose_self_update(
                provider,
                &self.key.signer(provider),
                LeafNodeParameters::default(),
            )
            .map_err(mls_error)?;
        // OpenMLS keeps its own copy in the store, which would stop this user sending.
        let own = self
            .mls
            .pending_proposals()
            .next()
            .cloned()
            .ok_or(Error::State("OpenMLS kept no copy of the proposal"))?;
        self.mls
            .remove_pending_proposal(provider.storage(), own.proposal_reference_ref())
            .map_err(mls_error)?;
        self.held.push(own);
        let out = self.current()?.place(&mls::encode_message(proposal)?)?;
        self.proposed_in = Some(epoch);
        Ok(out)
    }

    /// Commit every update proposal held, with a path that also replaces this user's own
    /// leaf key. Creator only. Returns the commit for the current stream, or `None` if
    /// this user is alone in the group.
    pub(crate) fn commit_updates(&mut self, provider: &Provider) -> Result<Option<Outgoing>> {
        if self.creator.is_some() {
            return Err(Error::State("only the group's creator commits"));
        }
        self.batch_until = None;
        if self.member_count() == 1 {
            self.held.clear();
            return Ok(None);
        }
        let usable = self.usable_held(provider)?;
        self.load(provider, &usable)?;
        let before = mls::own_leaf_key(&self.mls)?;
        let built = self
            .mls
            .commit_to_pending_proposals(provider, &self.key.signer(provider));
        let (commit, _, _) = match built {
            Ok(built) => built,
            Err(err) => {
                self.unload(provider)?;
                return Err(mls_error(err));
            }
        };
        self.mls.merge_pending_commit(provider).map_err(mls_error)?;
        let out = self.current()?.place(&mls::encode_message(commit)?)?;
        self.enter_epoch(provider)?;
        self.note_leaf(&before)?;
        Ok(Some(out))
    }

    /// Run this group's timers at `now` (unix seconds): stamp a leaf update that landed,
    /// propose one when this member's is due, and for the creator, commit held proposals
    /// once the batching window ends, or a self-update after a quiet day.
    pub(crate) fn tick(&mut self, provider: &Provider, now: u64) -> Result<Tick> {
        let mut tick = Tick::default();
        if self.landed {
            self.landed = false;
            self.last_update = now;
            tick.changed = true;
        }
        if self
            .last_seen
            .is_none_or(|seen| now.saturating_sub(seen) >= SEEN_SAVE_SECS)
        {
            self.last_seen = Some(now);
            tick.changed = true;
        }
        let due = now.saturating_sub(self.last_update) >= UPDATE_SECS;
        if self.creator.is_some() {
            if due && self.proposed_in != Some(self.mls.epoch().as_u64()) {
                tick.out = Some(self.propose_update(provider)?);
                tick.changed = true;
            }
            return Ok(tick);
        }
        if !self.held.is_empty() && self.batch_until.is_none() {
            self.batch_until = Some(now.saturating_add(BATCH_SECS));
            tick.changed = true;
        }
        let batch_over = self.batch_until.is_some_and(|until| now >= until);
        if batch_over || (due && self.member_count() > 1) {
            tick.out = self.commit_updates(provider)?;
            tick.changed = true;
        }
        Ok(tick)
    }

    /// Whether this user, a member, last ran purple with this group more than
    /// [`STALE_SECS`] before `now`.
    pub(crate) fn stale(&self, now: u64) -> bool {
        self.creator.is_some()
            && self
                .last_seen
                .is_some_and(|seen| now.saturating_sub(seen) > STALE_SECS)
    }

    /// The held proposals an update commit can carry. OpenMLS checks an Update's leaf
    /// (capabilities, key reuse) only when a commit is built, and one bad Update fails the
    /// whole commit, so if they don't all build together, each is kept only if it still
    /// builds with the ones kept before it.
    fn usable_held(&mut self, provider: &Provider) -> Result<Vec<QueuedProposal>> {
        let all = self.held.clone();
        if self.builds(provider, &all)? {
            return Ok(all);
        }
        let mut usable = Vec::new();
        for proposal in all {
            usable.push(proposal);
            if !self.builds(provider, &usable)? {
                usable.pop();
            }
        }
        Ok(usable)
    }

    /// Whether an update commit of `proposals` can be built. Nothing is committed, and the
    /// proposal store is left empty.
    fn builds(&mut self, provider: &Provider, proposals: &[QueuedProposal]) -> Result<bool> {
        self.load(provider, proposals)?;
        let signer = self.key.signer(provider);
        let built = self
            .mls
            .commit_builder()
            .load_psks(provider.storage())
            .map_err(mls_error)
            .map(|builder| {
                builder
                    .build(provider.rand(), provider.crypto(), &signer, |_| true)
                    .is_ok()
            });
        self.unload(provider)?;
        built
    }

    /// Put `proposals` into OpenMLS's proposal store.
    fn load(&mut self, provider: &Provider, proposals: &[QueuedProposal]) -> Result<()> {
        for proposal in proposals {
            self.mls
                .store_pending_proposal(provider.storage(), proposal.clone())
                .map_err(mls_error)?;
        }
        Ok(())
    }

    /// Empty OpenMLS's proposal store again, so this user can send.
    fn unload(&mut self, provider: &Provider) -> Result<()> {
        self.mls
            .clear_pending_proposals(provider.storage())
            .map_err(mls_error)
    }

    /// After a merge: if this user's leaf key changed, the next tick stamps the time.
    fn note_leaf(&mut self, before: &[u8]) -> Result<()> {
        if mls::own_leaf_key(&self.mls)? != before {
            self.landed = true;
        }
        Ok(())
    }

    /// Whether an Update proposal keeps its sender's purple identity: the new leaf's
    /// credential verifies to `from`.
    fn keeps_identity(proposal: &Proposal, from: &IdentityKey) -> bool {
        let Proposal::Update(update) = proposal else {
            return false;
        };
        let leaf = update.leaf_node();
        credential::verify(leaf.credential(), leaf.signature_key().as_slice())
            .is_ok_and(|identity| identity == *from)
    }

    /// Handle one whole MLS message read from this group's streams. `creator` is the
    /// creator's identity key; commits from anyone else are refused.
    pub(crate) fn receive(
        &mut self,
        provider: &Provider,
        message: &[u8],
        creator: &IdentityKey,
    ) -> Result<Received> {
        let protocol = mls::decode_protocol(message)?;
        if protocol.content_type() != ContentType::Commit {
            return self.receive_protocol(provider, protocol, creator);
        }
        // The commit may name held proposals, which OpenMLS must find in its store. A
        // merge empties the store; anything else leaves them to be taken out again.
        let held = self.held.clone();
        self.load(provider, &held)?;
        let received = self.receive_protocol(provider, protocol, creator);
        if self.mls.is_active() && self.mls.has_pending_proposals() {
            self.unload(provider)?;
        }
        received
    }

    fn receive_protocol(
        &mut self,
        provider: &Provider,
        protocol: ProtocolMessage,
        creator: &IdentityKey,
    ) -> Result<Received> {
        let is_proposal = protocol.content_type() == ContentType::Proposal;
        let processed = match self.mls.process_message(provider, protocol) {
            Ok(processed) => processed,
            // A proposal from an epoch that has ended was committed then or dropped with
            // it; its sender proposes again in the new epoch.
            Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch))
                if is_proposal =>
            {
                return Ok(Received::Nothing);
            }
            Err(err) => return Err(mls_error(err)),
        };
        if !matches!(processed.sender(), Sender::Member(_)) {
            return Ok(Received::Nothing);
        }
        // The credential OpenMLS checked the message against, from the epoch it was sent
        // in. The leaf may belong to someone else by now: a removed member's leaf is the
        // first one a new member gets. Every leaf's credential was verified when it entered
        // the group.
        let from = credential::identity(processed.credential())?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                match GroupContent::decode(&app.into_bytes())? {
                    GroupContent::Text(body) => Ok(Received::Text { from, body }),
                    GroupContent::Names(names) if from == *creator => Ok(Received::Names(names)),
                    GroupContent::Names(_) => Ok(Received::Nothing),
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if from != *creator {
                    return Err(Error::State(
                        "only the creator may change a group's members",
                    ));
                }
                let before = self.identities()?;
                let own_before = mls::own_leaf_key(&self.mls)?;
                self.mls
                    .merge_staged_commit(provider, *staged)
                    .map_err(mls_error)?;
                if !self.mls.is_active() {
                    return Ok(Received::Removed);
                }
                let Ok(after) = self.identities() else {
                    return Ok(Received::Forged);
                };
                self.enter_epoch(provider)?;
                self.note_leaf(&own_before)?;
                Ok(Received::Membership {
                    added: after
                        .iter()
                        .filter(|id| !before.contains(id))
                        .copied()
                        .collect(),
                    removed: before
                        .iter()
                        .filter(|id| !after.contains(id))
                        .copied()
                        .collect(),
                })
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                // Members may only replace their own leaf, as themselves. Every member
                // holds it, since the creator's commit names proposals by reference. Only a
                // sender's first counts: a cap on the total would let one member crowd out
                // the others, and leave a member who proposed short of one the commit names.
                let first = !self
                    .held
                    .iter()
                    .any(|held| held.sender() == queued.sender());
                if first && Self::keeps_identity(queued.proposal(), &from) {
                    self.held.push(*queued);
                }
                Ok(Received::Nothing)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_)
            | ProcessedMessageContent::OwnPrivateMessage
            | ProcessedMessageContent::OwnPendingCommit => Ok(Received::Nothing),
        }
    }

    /// The current stream first, then older ones still being read.
    pub(crate) fn streams(&self) -> &[GroupStream] {
        &self.streams
    }

    /// The stream with this seed.
    pub(crate) fn stream_mut(&mut self, seed: StreamSeed) -> Result<Option<&mut GroupStream>> {
        for stream in &mut self.streams {
            if stream.queue()?.stream() == seed {
                return Ok(Some(stream));
            }
        }
        Ok(None)
    }

    /// Box `at`, the next box of one of this group's streams, read as empty at `now`. An
    /// old stream that has been empty for [`DRAIN_SECS`] is dropped. Returns whether one
    /// was.
    pub(crate) fn note_empty(&mut self, at: &BoxRef, now: u64) -> Result<bool> {
        let mut found = None;
        for (position, stream) in self.streams.iter().enumerate() {
            if stream.queue()?.stream() == at.stream && stream.next_read == at.index {
                found = Some(position);
            }
        }
        let Some(position) = found.filter(|&position| position > 0) else {
            return Ok(false);
        };
        let Some(stream) = self.streams.get_mut(position) else {
            return Ok(false);
        };
        // Keep it while this user still has packets in it they haven't seen land: a write
        // reported taken later is resealed into this stream.
        if !stream.mine.is_empty() {
            return Ok(false);
        }
        let since = *stream.empty_since.get_or_insert(now);
        if now.saturating_sub(since) < DRAIN_SECS {
            return Ok(false);
        }
        self.streams.remove(position);
        Ok(true)
    }

    /// Forget the group, including its MLS state.
    pub(crate) fn delete(mut self, provider: &Provider) -> Result<()> {
        self.mls.delete(provider.storage()).map_err(mls_error)
    }

    fn current(&mut self) -> Result<&mut GroupStream> {
        self.streams
            .first_mut()
            .ok_or(Error::State("group has no stream"))
    }

    /// Start reading and writing the current epoch's stream, keeping [`PAST_EPOCHS`] old
    /// ones to drain.
    fn enter_epoch(&mut self, provider: &Provider) -> Result<()> {
        let secret = Zeroizing::new(
            self.mls
                .export_secret(provider.crypto(), EXPORTER_LABEL, &[], SECRET_LEN)
                .map_err(mls_error)?,
        );
        let bytes: [u8; SECRET_LEN] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("exporter secret has the wrong length"))?;
        self.streams.insert(
            0,
            GroupStream::new(QueueSecret::from_bytes(Zeroizing::new(bytes))),
        );
        // Proposals belong to the epoch that ended.
        self.held.clear();
        self.batch_until = None;
        // Keep the current stream and PAST_EPOCHS old ones, and any older one that still has
        // packets of this user's in flight.
        let keep = PAST_EPOCHS.saturating_add(1);
        let mut position = 0usize;
        self.streams.retain(|stream| {
            position = position.saturating_add(1);
            position <= keep || !stream.mine.is_empty()
        });
        Ok(())
    }

    /// Write this group's state (not its MLS state, which the provider holds).
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        w.bytes(self.mls.group_id().as_slice())?;
        self.key.encode(w)?;
        match &self.creator {
            None => w.u8(0),
            Some(creator) => {
                w.u8(1);
                w.bytes(creator.as_bytes())?;
            }
        }
        w.len(self.streams.len())?;
        for stream in &self.streams {
            w.bytes(stream.secret.as_bytes())?;
            w.u64(stream.next_read);
            w.u64(stream.next_write);
            w.len(stream.mine.len())?;
            for (index, hash) in &stream.mine {
                w.u64(*index);
                w.bytes(hash)?;
            }
            match stream.empty_since {
                None => w.u8(0),
                Some(since) => {
                    w.u8(1);
                    w.u64(since);
                }
            }
        }
        w.len(self.names.len())?;
        for (identity, name) in &self.names {
            w.bytes(identity)?;
            w.bytes(name.as_bytes())?;
        }
        w.len(self.asked.len())?;
        for contact in &self.asked {
            w.bytes(contact.as_bytes())?;
        }
        w.u64(self.last_update);
        w.u8(u8::from(self.landed));
        write_option(w, self.proposed_in);
        write_option(w, self.batch_until);
        write_option(w, self.last_seen);
        w.len(self.held.len())?;
        for proposal in &self.held {
            w.bytes(&serde_json::to_vec(proposal).map_err(mls_error)?)?;
        }
        Ok(())
    }

    /// Restore a group written by [`Self::encode`] into a snapshot of `version`, loading
    /// its MLS state from `provider`. Version 5 groups have no update timers: a member
    /// proposes on its first tick, and a creator starts its day from its first tick.
    pub(crate) fn decode(r: &mut Reader<'_>, provider: &Provider, version: u8) -> Result<Self> {
        let id = GroupId::from_slice(r.bytes()?);
        let mls = MlsGroup::load(provider.storage(), &id)
            .map_err(mls_error)?
            .ok_or(Error::Malformed("group state missing from MLS storage"))?;
        let key = SigningKey::decode(r)?;
        let creator = match r.u8()? {
            0 => None,
            1 => Some(r.string()?),
            _ => return Err(Error::Malformed("bad creator marker")),
        };
        let mut streams = Vec::new();
        for _ in 0..r.len()? {
            let secret: [u8; SECRET_LEN] = r
                .bytes()?
                .try_into()
                .map_err(|_| Error::Malformed("stream secret has the wrong length"))?;
            let mut stream = GroupStream::new(QueueSecret::from_bytes(Zeroizing::new(secret)));
            stream.next_read = r.u64()?;
            stream.next_write = r.u64()?;
            for _ in 0..r.len()? {
                let index = r.u64()?;
                let hash = r
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::Malformed("packet hash has the wrong length"))?;
                stream.mine.insert(index, hash);
            }
            stream.empty_since = match r.u8()? {
                0 => None,
                1 => Some(r.u64()?),
                _ => return Err(Error::Malformed("bad drain marker")),
            };
            streams.push(stream);
        }
        if streams.is_empty() {
            return Err(Error::Malformed("group has no stream"));
        }
        let mut names = BTreeMap::new();
        for _ in 0..r.len()? {
            names.insert(r.bytes()?.to_vec(), r.string()?);
        }
        let mut asked = BTreeSet::new();
        for _ in 0..r.len()? {
            asked.insert(r.string()?);
        }
        let (last_update, landed, proposed_in, batch_until, last_seen) = if version >= 6 {
            (
                r.u64()?,
                r.u8()? != 0,
                read_option(r)?,
                read_option(r)?,
                read_option(r)?,
            )
        } else {
            (0, creator.is_none(), None, None, None)
        };
        let mut held = Vec::new();
        if version >= 6 {
            for _ in 0..r.len()? {
                held.push(
                    serde_json::from_slice(r.bytes()?)
                        .map_err(|_| Error::Malformed("bad held proposal"))?,
                );
            }
        }
        Ok(Self {
            mls,
            key,
            creator,
            streams,
            names,
            asked,
            landed,
            proposed_in,
            last_update,
            batch_until,
            last_seen,
            held,
        })
    }
}

fn write_option(w: &mut Writer, value: Option<u64>) {
    match value {
        None => w.u8(0),
        Some(value) => {
            w.u8(1);
            w.u64(value);
        }
    }
}

fn read_option(r: &mut Reader<'_>) -> Result<Option<u64>> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.u64()?)),
        _ => Err(Error::Malformed("bad option marker")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{FRAGMENT_DATA_LEN, MAX_FRAGMENTS, Reassembler};

    struct Member {
        provider: Provider,
        account: Account,
    }

    fn member() -> Member {
        Member {
            provider: Provider::new().unwrap(),
            account: Account::generate().unwrap(),
        }
    }

    fn seed(stream: &GroupStream) -> StreamSeed {
        stream.queue().unwrap().stream()
    }

    /// Put `out`'s fragments back together into the MLS message they carry.
    fn message(stream: &GroupStream, out: &Outgoing) -> Vec<u8> {
        let queue = stream.queue().unwrap();
        let mut r = Reassembler::default();
        let mut whole = None;
        for (at, packet) in &out.writes {
            whole = r.push(&queue.open(at.index, packet).unwrap()).unwrap();
        }
        whole.unwrap()
    }

    /// Alice creates a group and adds Bob.
    fn pair() -> (Member, Group, Member, Group) {
        let alice = member();
        let bob = member();
        let mut group = Group::create(&alice.provider, &alice.account).unwrap();
        let (bob_key, key_package) = key_package(&bob.provider, &bob.account).unwrap();
        let (commit, welcome) = group
            .add(&alice.provider, &key_package, &bob.account.identity_key())
            .unwrap();
        assert!(commit.is_none(), "nobody else was there to read it");
        let joined = Group::join(
            &bob.provider,
            bob_key,
            "alice".into(),
            &alice.account.identity_key(),
            &welcome,
            Vec::new(),
        )
        .unwrap();
        (alice, group, bob, joined)
    }

    #[test]
    fn creator_and_joiner_share_a_stream_and_messages() {
        let (alice, mut group, bob, mut joined) = pair();
        assert_eq!(seed(&group.streams()[0]), seed(&joined.streams()[0]));
        assert_eq!(joined.creator(), Some("alice"));
        assert_eq!(group.creator(), None);

        let out = group
            .send(&alice.provider, &GroupContent::Text(b"hi bob".to_vec()))
            .unwrap();
        let bytes = message(&joined.streams()[0], &out);
        let got = joined
            .receive(&bob.provider, &bytes, &alice.account.identity_key())
            .unwrap();
        assert!(matches!(got, Received::Text { from, body }
            if from == alice.account.identity_key() && body == b"hi bob"));
    }

    #[test]
    fn a_key_package_from_someone_else_is_refused() {
        let alice = member();
        let (bob, carol) = (member(), member());
        let mut group = Group::create(&alice.provider, &alice.account).unwrap();
        let (_, carols) = key_package(&carol.provider, &carol.account).unwrap();
        assert!(
            group
                .add(&alice.provider, &carols, &bob.account.identity_key())
                .is_err()
        );
        assert_eq!(group.member_count(), 1);
    }

    #[test]
    fn a_commit_moves_everyone_to_a_new_stream_and_late_messages_still_arrive() {
        let (alice, mut group, bob, mut joined) = pair();
        let carol = member();
        let old = seed(&joined.streams()[0]);
        let creator = alice.account.identity_key();

        // Bob sends in epoch 1 without having seen the commit that follows.
        let late = joined
            .send(&bob.provider, &GroupContent::Text(b"late".to_vec()))
            .unwrap();
        let (_, kp) = key_package(&carol.provider, &carol.account).unwrap();
        let (commit, _) = group
            .add(&alice.provider, &kp, &carol.account.identity_key())
            .unwrap();
        let commit = commit.unwrap();
        assert_eq!(
            commit.writes[0].0.stream, old,
            "the commit goes in the old stream"
        );

        let bytes = message(&joined.streams()[0], &commit);
        let got = joined.receive(&bob.provider, &bytes, &creator).unwrap();
        assert!(matches!(got, Received::Membership { added, removed }
            if added == [carol.account.identity_key()] && removed.is_empty()));
        assert_ne!(seed(&joined.streams()[0]), old);
        assert_eq!(seed(&joined.streams()[1]), old, "still drained");

        let late_bytes = message(&group.streams()[1], &late);
        let late_got = group
            .receive(&alice.provider, &late_bytes, &creator)
            .unwrap();
        assert!(matches!(late_got, Received::Text { body, .. } if body == b"late"));
    }

    #[test]
    fn a_late_message_is_credited_to_its_sender_even_after_their_leaf_is_reused() {
        let (alice, mut group, bob, mut bobs) = pair();
        let (carol, dana) = (member(), member());
        let creator = alice.account.identity_key();
        let (carol_key, kp) = key_package(&carol.provider, &carol.account).unwrap();
        let (commit, welcome) = group
            .add(&alice.provider, &kp, &carol.account.identity_key())
            .unwrap();
        bobs.receive(
            &bob.provider,
            &message(&bobs.streams()[0], &commit.unwrap()),
            &creator,
        )
        .unwrap();
        let mut carols = Group::join(
            &carol.provider,
            carol_key,
            "alice".into(),
            &creator,
            &welcome,
            Vec::new(),
        )
        .unwrap();

        // Bob sends, then is removed, and Dana takes his leaf.
        let late = bobs
            .send(&bob.provider, &GroupContent::Text(b"from bob".to_vec()))
            .unwrap();
        let late_stream = seed(&bobs.streams()[0]);
        let removal = group
            .remove(&alice.provider, &bob.account.identity_key())
            .unwrap();
        let (_, danas) = key_package(&dana.provider, &dana.account).unwrap();
        let (adding, _) = group
            .add(&alice.provider, &danas, &dana.account.identity_key())
            .unwrap();
        for change in [removal, adding.unwrap()] {
            let stream = carols.streams()[0].queue().unwrap().stream();
            let at = carols
                .streams()
                .iter()
                .position(|s| seed(s) == stream)
                .unwrap();
            carols
                .receive(
                    &carol.provider,
                    &message(&carols.streams()[at], &change),
                    &creator,
                )
                .unwrap();
        }
        let old = carols
            .streams()
            .iter()
            .position(|s| seed(s) == late_stream)
            .unwrap();
        let got = carols
            .receive(
                &carol.provider,
                &message(&carols.streams()[old], &late),
                &creator,
            )
            .unwrap();
        assert!(
            matches!(&got, Received::Text { from, .. } if *from == bob.account.identity_key()),
            "{got:?}"
        );
    }

    #[test]
    fn only_the_creator_may_commit() {
        let (alice, mut group, bob, mut joined) = pair();
        // Bob commits on his own (OpenMLS lets any member); Alice must refuse it.
        let commit = joined
            .mls
            .self_update(
                &bob.provider,
                &joined.key.signer(&bob.provider),
                LeafNodeParameters::default(),
            )
            .unwrap()
            .into_commit();
        let bytes = mls::encode_message(commit).unwrap();
        let epoch = group.mls.epoch();
        assert!(
            group
                .receive(&alice.provider, &bytes, &alice.account.identity_key())
                .is_err()
        );
        assert_eq!(group.mls.epoch(), epoch);
    }

    #[test]
    fn removal_tells_the_removed_member() {
        let (alice, mut group, bob, mut joined) = pair();
        let commit = group
            .remove(&alice.provider, &bob.account.identity_key())
            .unwrap();
        let bytes = message(&joined.streams()[0], &commit);
        let got = joined
            .receive(&bob.provider, &bytes, &alice.account.identity_key())
            .unwrap();
        assert!(matches!(got, Received::Removed));
        assert_eq!(group.member_count(), 1);
    }

    #[test]
    fn names_count_only_from_the_creator() {
        let (alice, mut group, bob, mut joined) = pair();
        let creator = alice.account.identity_key();
        let names = vec![(vec![5; 33], "dana".to_owned())];
        let from_bob = joined
            .send(&bob.provider, &GroupContent::Names(names.clone()))
            .unwrap();
        let bytes = message(&group.streams()[0], &from_bob);
        let got = group.receive(&alice.provider, &bytes, &creator).unwrap();
        assert!(matches!(got, Received::Nothing));
        let from_alice = group
            .send(&alice.provider, &GroupContent::Names(names.clone()))
            .unwrap();
        let names_bytes = message(&joined.streams()[0], &from_alice);
        let names_got = joined
            .receive(&bob.provider, &names_bytes, &creator)
            .unwrap();
        assert!(matches!(names_got, Received::Names(n) if n == names));
    }

    #[test]
    fn the_creator_cant_name_a_stranger_me() {
        let (_alice, _group, _bob, mut joined) = pair();
        let stranger = member().account.identity_key();
        let id = stranger.serialize().to_vec();
        for name in ["me", "unknown"] {
            joined.learn_names(vec![(id.clone(), name.to_owned())]);
            assert_eq!(joined.name_for(&stranger), None, "{name}");
        }
        joined.learn_names(vec![(id, "dana".to_owned())]);
        assert_eq!(joined.name_for(&stranger), Some("dana"));
    }

    #[test]
    fn group_state_survives_a_snapshot() {
        let (alice, group, _bob, _joined) = pair();
        let mut w = Writer::default();
        alice.provider.encode(&mut w).unwrap();
        group.encode(&mut w).unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let provider = Provider::decode(&mut r).unwrap();
        let mut restored = Group::decode(&mut r, &provider, 6).unwrap();
        r.finish().unwrap();
        assert_eq!(restored.member_count(), 2);
        assert_eq!(seed(&restored.streams()[0]), seed(&group.streams()[0]));
        restored
            .send(&provider, &GroupContent::Text(b"after".to_vec()))
            .unwrap();
    }

    #[test]
    fn own_boxes_are_recognised_and_a_taken_one_moves_on() {
        let (alice, mut group, _bob, _joined) = pair();
        let out = group
            .send(&alice.provider, &GroupContent::Text(b"x".to_vec()))
            .unwrap();
        let (at, packet) = out.writes[0].clone();
        let stream = group.stream_mut(at.stream).unwrap().unwrap();
        let (moved, resealed) = stream.replace(at.index, &packet).unwrap();
        assert_eq!(moved.index, at.index + 1);
        assert!(
            !stream.read_back(at.index, &packet),
            "box 0 is someone else's now"
        );
        assert!(stream.read_back(moved.index, &resealed));
    }

    #[test]
    fn group_content_round_trips_and_rejects_garbage() {
        for content in [
            GroupContent::Text(b"hello".to_vec()),
            GroupContent::Names(vec![(vec![1; 33], "bob".into())]),
        ] {
            let bytes = content.encode().unwrap();
            assert_eq!(GroupContent::decode(&bytes).unwrap(), content);
        }
        assert!(GroupContent::decode(&[]).is_err());
        assert!(GroupContent::decode(&[CONTENT_VERSION, 99]).is_err());
    }

    /// Run with: cargo test -p purple-core --release --offline -- --ignored fifty
    #[test]
    #[ignore = "builds a 50-member group; about a minute in release"]
    fn fifty_members_fit_and_the_fifty_first_is_refused() {
        let alice = member();
        let mut group = Group::create(&alice.provider, &alice.account).unwrap();
        let mut last_welcome = Vec::new();
        while group.member_count() < MAX_MEMBERS {
            let joiner = member();
            let (_, kp) = key_package(&joiner.provider, &joiner.account).unwrap();
            let (_, welcome) = group
                .add(&alice.provider, &kp, &joiner.account.identity_key())
                .unwrap();
            last_welcome = welcome;
        }
        let max = usize::from(MAX_FRAGMENTS) * FRAGMENT_DATA_LEN;
        println!("Welcome at {MAX_MEMBERS}: {} bytes", last_welcome.len());
        assert!(
            last_welcome.len() + 4096 < max,
            "Welcome {} bytes",
            last_welcome.len()
        );
        let one = member();
        let (_, kp) = key_package(&one.provider, &one.account).unwrap();
        assert!(
            group
                .add(&alice.provider, &kp, &one.account.identity_key())
                .is_err()
        );
        let second = group.identities().unwrap()[1];
        let removal = group.remove(&alice.provider, &second).unwrap();
        println!("removal at {MAX_MEMBERS}: {} boxes", removal.writes.len());
        assert!(removal.writes.len() <= usize::from(MAX_FRAGMENTS));
    }

    /// Alice creates a group with Bob and Carol.
    fn trio() -> (Member, Group, Member, Group, Member, Group) {
        let (alice, mut group, bob, mut bobs) = pair();
        let carol = member();
        let (carol_key, kp) = key_package(&carol.provider, &carol.account).unwrap();
        let (commit, welcome) = group
            .add(&alice.provider, &kp, &carol.account.identity_key())
            .unwrap();
        let commit = commit.unwrap();
        let bytes = message(&bobs.streams()[0], &commit);
        bobs.receive(&bob.provider, &bytes, &alice.account.identity_key())
            .unwrap();
        let carols = Group::join(
            &carol.provider,
            carol_key,
            "alice".into(),
            &alice.account.identity_key(),
            &welcome,
            Vec::new(),
        )
        .unwrap();
        (alice, group, bob, bobs, carol, carols)
    }

    #[test]
    fn a_members_update_is_committed_by_the_creator_and_heals_both_leaves() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        let (bob_before, alice_before) = (bobs.leaf_key(), group.leaf_key());

        let proposal = bobs.propose_update(&bob.provider).unwrap();
        assert!(
            bobs.propose_update(&bob.provider).is_err(),
            "one proposal per epoch"
        );
        let bytes = message(&bobs.streams()[0], &proposal);
        for (provider, state) in [
            (&alice.provider, &mut group),
            (&carol.provider, &mut carols),
        ] {
            assert!(matches!(
                state.receive(provider, &bytes, &creator).unwrap(),
                Received::Nothing
            ));
        }

        // Joining set `landed` for the first tick to stamp; none has run here.
        for state in [&mut group, &mut bobs, &mut carols] {
            state.landed = false;
        }
        let carol_before = carols.leaf_key();
        let commit = group.commit_updates(&alice.provider).unwrap().unwrap();
        assert!(group.landed, "the path replaced the creator's leaf");
        assert_ne!(group.leaf_key(), alice_before);
        let commit_bytes = message(&bobs.streams()[0], &commit);
        for (provider, state) in [(&bob.provider, &mut bobs), (&carol.provider, &mut carols)] {
            let got = state.receive(provider, &commit_bytes, &creator).unwrap();
            assert!(matches!(got, Received::Membership { added, removed }
                if added.is_empty() && removed.is_empty()));
        }
        assert_ne!(bobs.leaf_key(), bob_before);
        assert!(bobs.landed);
        assert!(!carols.landed, "Carol's leaf didn't change");
        assert_eq!(carols.leaf_key(), carol_before);

        // Messages still flow in the new epoch.
        let out = bobs
            .send(&bob.provider, &GroupContent::Text(b"after".to_vec()))
            .unwrap();
        let text = message(&carols.streams()[0], &out);
        assert!(matches!(
            carols.receive(&carol.provider, &text, &creator).unwrap(),
            Received::Text { body, .. } if body == b"after"
        ));
    }

    #[test]
    fn only_members_propose_and_only_the_creator_commits_updates() {
        let (alice, mut group, bob, mut bobs) = pair();
        assert!(group.propose_update(&alice.provider).is_err());
        assert!(bobs.commit_updates(&bob.provider).is_err());
        let alone = member();
        let mut solo = Group::create(&alone.provider, &alone.account).unwrap();
        assert!(solo.commit_updates(&alone.provider).unwrap().is_none());
    }

    #[test]
    fn an_add_drops_held_updates_and_the_proposer_proposes_again() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        let before = bobs.leaf_key();
        let proposal = bobs.propose_update(&bob.provider).unwrap();
        let bytes = message(&bobs.streams()[0], &proposal);
        group.receive(&alice.provider, &bytes, &creator).unwrap();
        carols.receive(&carol.provider, &bytes, &creator).unwrap();

        let dave = member();
        let (_, kp) = key_package(&dave.provider, &dave.account).unwrap();
        let (commit, _) = group
            .add(&alice.provider, &kp, &dave.account.identity_key())
            .unwrap();
        assert!(group.held.is_empty());
        let commit_bytes = message(&bobs.streams()[0], &commit.unwrap());
        bobs.receive(&bob.provider, &commit_bytes, &creator)
            .unwrap();
        carols
            .receive(&carol.provider, &commit_bytes, &creator)
            .unwrap();
        assert_eq!(bobs.leaf_key(), before, "the add didn't carry it");
        assert!(bobs.held.is_empty());
        assert!(
            bobs.propose_update(&bob.provider).is_ok(),
            "a new epoch, a new proposal"
        );
    }

    #[test]
    fn a_proposal_that_isnt_an_update_or_swaps_identity_is_ignored() {
        let (alice, mut group, bob, mut bobs, carol, carols) = trio();
        let creator = alice.account.identity_key();
        // A Remove proposal from Bob.
        let carol_leaf = bobs
            .mls
            .members()
            .find(|m| {
                credential::verify(&m.credential, &m.signature_key)
                    .is_ok_and(|id| id == carol.account.identity_key())
            })
            .unwrap()
            .index;
        let (remove, _) = bobs
            .mls
            .propose_remove_member(&bob.provider, &bobs.key.signer(&bob.provider), carol_leaf)
            .unwrap();
        let remove = mls::encode_message(remove).unwrap();
        // An Update from Bob whose leaf claims Carol's identity. He can't sign a binding of
        // his MLS key to her identity key, so he reuses her credential, which binds hers.
        let carols_credential = carols.mls.own_leaf().unwrap().credential().clone();
        let (swap, _) = bobs
            .mls
            .propose_self_update(
                &bob.provider,
                &bobs.key.signer(&bob.provider),
                LeafNodeParameters::builder()
                    .with_credential_with_key(openmls::prelude::CredentialWithKey {
                        credential: carols_credential,
                        signature_key: bobs.key.public().to_vec().into(),
                    })
                    .build(),
            )
            .unwrap();
        let swap = mls::encode_message(swap).unwrap();
        for bytes in [remove, swap] {
            // OpenMLS may refuse the swapped leaf itself; either way nothing is stored.
            let got = group.receive(&alice.provider, &bytes, &creator);
            assert!(got.is_err() || matches!(got, Ok(Received::Nothing)));
        }
        assert!(group.held.is_empty());
    }

    const T0: u64 = 1_000_000;

    #[test]
    fn a_member_proposes_daily_and_the_creator_batches_then_commits() {
        let (alice, mut group, bob, mut bobs) = pair();
        let creator = alice.account.identity_key();
        // Bob's first tick stamps his fresh leaf; nothing is due yet. The creator's first
        // tick comes later, so its own day starts then and doesn't overlap the window.
        assert!(bobs.tick(&bob.provider, T0).unwrap().out.is_none());
        assert!(
            bobs.tick(&bob.provider, T0 + UPDATE_SECS - 1)
                .unwrap()
                .out
                .is_none()
        );

        let proposal = bobs
            .tick(&bob.provider, T0 + UPDATE_SECS)
            .unwrap()
            .out
            .unwrap();
        assert!(
            bobs.tick(&bob.provider, T0 + UPDATE_SECS + 2)
                .unwrap()
                .out
                .is_none(),
            "not twice in one epoch"
        );
        let bytes = message(&bobs.streams()[0], &proposal);
        group.receive(&alice.provider, &bytes, &creator).unwrap();

        // The creator's first tick stamps its leaf and opens a five-minute window.
        let now = T0 + UPDATE_SECS;
        let opened = group.tick(&alice.provider, now).unwrap();
        assert!(opened.out.is_none() && opened.changed);
        assert!(
            group
                .tick(&alice.provider, now + BATCH_SECS - 1)
                .unwrap()
                .out
                .is_none()
        );
        let commit = group
            .tick(&alice.provider, now + BATCH_SECS)
            .unwrap()
            .out
            .unwrap();
        let commit_bytes = message(&bobs.streams()[0], &commit);
        bobs.receive(&bob.provider, &commit_bytes, &creator)
            .unwrap();

        // Bob's update landed: stamped, and not due again for a day.
        let at = T0 + UPDATE_SECS + 400;
        assert!(bobs.tick(&bob.provider, at).unwrap().changed);
        assert!(
            bobs.tick(&bob.provider, at + UPDATE_SECS - 1)
                .unwrap()
                .out
                .is_none()
        );
        assert!(
            bobs.tick(&bob.provider, at + UPDATE_SECS)
                .unwrap()
                .out
                .is_some()
        );
    }

    #[test]
    fn the_creator_self_updates_after_a_quiet_day_unless_alone() {
        let (alice, mut group, _bob, _bobs) = pair();
        group.tick(&alice.provider, T0).unwrap();
        assert!(
            group
                .tick(&alice.provider, T0 + UPDATE_SECS - 1)
                .unwrap()
                .out
                .is_none()
        );
        assert!(
            group
                .tick(&alice.provider, T0 + UPDATE_SECS)
                .unwrap()
                .out
                .is_some()
        );

        let solo = member();
        let mut alone = Group::create(&solo.provider, &solo.account).unwrap();
        alone.tick(&solo.provider, T0).unwrap();
        assert!(
            alone
                .tick(&solo.provider, T0 + 10 * UPDATE_SECS)
                .unwrap()
                .out
                .is_none()
        );
    }

    #[test]
    fn the_batching_window_survives_a_restart() {
        let (alice, mut group, bob, mut bobs) = pair();
        let creator = alice.account.identity_key();
        group.tick(&alice.provider, T0).unwrap();
        bobs.tick(&bob.provider, T0).unwrap();
        let proposal = bobs.propose_update(&bob.provider).unwrap();
        group
            .receive(
                &alice.provider,
                &message(&bobs.streams()[0], &proposal),
                &creator,
            )
            .unwrap();
        group.tick(&alice.provider, T0 + 10).unwrap();

        let mut w = Writer::default();
        alice.provider.encode(&mut w).unwrap();
        group.encode(&mut w).unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let provider = Provider::decode(&mut r).unwrap();
        let mut restored = Group::decode(&mut r, &provider, 6).unwrap();
        r.finish().unwrap();
        assert!(
            restored
                .tick(&provider, T0 + 10 + BATCH_SECS)
                .unwrap()
                .out
                .is_some()
        );
    }

    #[test]
    fn stale_only_for_members_last_seen_over_a_week_ago() {
        let (alice, mut group, bob, mut bobs) = pair();
        assert!(!bobs.stale(T0), "never seen: no warning");
        bobs.tick(&bob.provider, T0).unwrap();
        group.tick(&alice.provider, T0).unwrap();
        assert!(!bobs.stale(T0 + STALE_SECS));
        assert!(bobs.stale(T0 + STALE_SECS + 1));
        assert!(
            !group.stale(T0 + STALE_SECS + 1),
            "the creator can't fall behind"
        );
    }

    /// Save and restore `state` the way a restart does.
    fn restart(provider: &Provider, state: &Group) -> (Provider, Group) {
        let mut w = Writer::default();
        provider.encode(&mut w).unwrap();
        state.encode(&mut w).unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let restored_provider = Provider::decode(&mut r).unwrap();
        let restored = Group::decode(&mut r, &restored_provider, 6).unwrap();
        r.finish().unwrap();
        (restored_provider, restored)
    }

    /// An Update that keeps Bob's identity but that OpenMLS refuses to commit: its
    /// capabilities leave out the group's ciphersuite. Bob's client keeps none of it.
    fn hostile_update(bob: &Member, bobs: &mut Group) -> Vec<u8> {
        let capabilities = openmls::prelude::Capabilities::new(
            None,
            Some(&[openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]),
            None,
            None,
            None,
        );
        let (proposal, _) = bobs
            .mls
            .propose_self_update(
                &bob.provider,
                &bobs.key.signer(&bob.provider),
                LeafNodeParameters::builder()
                    .with_capabilities(capabilities)
                    .build(),
            )
            .unwrap();
        bobs.mls
            .clear_pending_proposals(bob.provider.storage())
            .unwrap();
        mls::encode_message(proposal).unwrap()
    }

    /// Write `state` as version 5 would have: without the update fields, which take
    /// 8 + 1 + 1 + 1 + 1 bytes while every option is empty, plus 4 for the empty held
    /// list. Neither group has ticked or proposed, so they are.
    fn as_version_5(provider: &Provider, state: &Group) -> (Provider, Group) {
        let mut w = Writer::default();
        provider.encode(&mut w).unwrap();
        state.encode(&mut w).unwrap();
        let mut bytes = w.finish().to_vec();
        bytes.truncate(bytes.len().saturating_sub(8 + 1 + 1 + 1 + 1 + 4));
        let mut r = Reader::new(&bytes);
        let restored_provider = Provider::decode(&mut r).unwrap();
        let restored = Group::decode(&mut r, &restored_provider, 5).unwrap();
        r.finish().unwrap();
        (restored_provider, restored)
    }

    #[test]
    fn a_version_5_group_loads_and_only_its_member_proposes_at_once() {
        let (alice, group, bob, bobs) = pair();
        let (bob_provider, mut old_bobs) = as_version_5(&bob.provider, &bobs);
        assert!(!old_bobs.stale(T0 + 100 * STALE_SECS));
        assert!(old_bobs.tick(&bob_provider, T0).unwrap().out.is_some());
        let (alice_provider, mut old_group) = as_version_5(&alice.provider, &group);
        assert!(
            old_group.tick(&alice_provider, T0).unwrap().out.is_none(),
            "the creator's day starts at its first tick"
        );
    }

    #[test]
    fn members_can_still_send_while_an_update_waits() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        let proposal = bobs.propose_update(&bob.provider).unwrap();
        let bytes = message(&bobs.streams()[0], &proposal);
        group.receive(&alice.provider, &bytes, &creator).unwrap();
        carols.receive(&carol.provider, &bytes, &creator).unwrap();
        for (provider, state, who) in [
            (&alice.provider, &mut group, "creator"),
            (&bob.provider, &mut bobs, "proposer"),
            (&carol.provider, &mut carols, "other member"),
        ] {
            let sent = state.send(provider, &GroupContent::Text(b"hi".to_vec()));
            assert!(sent.is_ok(), "{who}: {sent:?}");
        }
    }

    #[test]
    fn a_hostile_update_is_left_out_and_blocks_nothing() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        let hostile = hostile_update(&bob, &mut bobs);
        let honest = carols.propose_update(&carol.provider).unwrap();
        let honest = message(&carols.streams()[0], &honest);
        for bytes in [&hostile, &honest] {
            group.receive(&alice.provider, bytes, &creator).unwrap();
        }
        bobs.receive(&bob.provider, &honest, &creator).unwrap();
        assert_eq!(group.held.len(), 2, "both keep their sender's identity");

        let carol_before = carols.leaf_key();
        let commit = group.commit_updates(&alice.provider).unwrap().unwrap();
        let commit = message(&carols.streams()[0], &commit);
        for (provider, state) in [(&bob.provider, &mut bobs), (&carol.provider, &mut carols)] {
            state.receive(provider, &commit, &creator).unwrap();
        }
        assert_ne!(carols.leaf_key(), carol_before, "the honest update went in");

        let out = group
            .send(
                &alice.provider,
                &GroupContent::Text(b"still one group".to_vec()),
            )
            .unwrap();
        let text = message(&bobs.streams()[0], &out);
        assert!(matches!(
            bobs.receive(&bob.provider, &text, &creator).unwrap(),
            Received::Text { body, .. } if body == b"still one group"
        ));
    }

    #[test]
    fn held_updates_survive_a_restart() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        let before = bobs.leaf_key();
        let proposal = bobs.propose_update(&bob.provider).unwrap();
        let bytes = message(&bobs.streams()[0], &proposal);
        group.receive(&alice.provider, &bytes, &creator).unwrap();
        carols.receive(&carol.provider, &bytes, &creator).unwrap();
        let (alice_provider, mut group) = restart(&alice.provider, &group);
        let (bob_provider, mut bobs) = restart(&bob.provider, &bobs);
        let (carol_provider, mut carols) = restart(&carol.provider, &carols);

        let commit = group.commit_updates(&alice_provider).unwrap().unwrap();
        let commit = message(&bobs.streams()[0], &commit);
        bobs.receive(&bob_provider, &commit, &creator).unwrap();
        carols.receive(&carol_provider, &commit, &creator).unwrap();
        assert_ne!(bobs.leaf_key(), before);
    }

    #[test]
    fn only_a_senders_first_update_is_kept() {
        let (alice, mut group, bob, mut bobs) = pair();
        let creator = alice.account.identity_key();
        let mut first = None;
        for _ in 0..3 {
            let (proposal, _) = bobs
                .mls
                .propose_self_update(
                    &bob.provider,
                    &bobs.key.signer(&bob.provider),
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let bytes = mls::encode_message(proposal).unwrap();
            group.receive(&alice.provider, &bytes, &creator).unwrap();
            first.get_or_insert_with(|| group.held[0].proposal_reference_ref().clone());
        }
        assert_eq!(group.held.len(), 1);
        assert_eq!(Some(group.held[0].proposal_reference_ref().clone()), first);
    }

    #[test]
    fn a_flooding_member_neither_crowds_out_nor_strands_an_honest_update() {
        let (alice, mut group, bob, mut bobs, carol, mut carols) = trio();
        let creator = alice.account.identity_key();
        // Carol fills the stream with updates OpenMLS won't commit, then one it will, all
        // in boxes before Bob's. Bob proposed before reading them.
        let mut flood: Vec<Vec<u8>> = (1..2 * MAX_MEMBERS)
            .map(|_| hostile_update(&carol, &mut carols))
            .collect();
        let (good, _) = carols
            .mls
            .propose_self_update(
                &carol.provider,
                &carols.key.signer(&carol.provider),
                LeafNodeParameters::default(),
            )
            .unwrap();
        carols
            .mls
            .clear_pending_proposals(carol.provider.storage())
            .unwrap();
        flood.push(mls::encode_message(good).unwrap());
        let before = bobs.leaf_key();
        let own = bobs.propose_update(&bob.provider).unwrap();
        for bytes in &flood {
            group.receive(&alice.provider, bytes, &creator).unwrap();
            bobs.receive(&bob.provider, bytes, &creator).unwrap();
        }
        group
            .receive(
                &alice.provider,
                &message(&bobs.streams()[0], &own),
                &creator,
            )
            .unwrap();

        let commit = group.commit_updates(&alice.provider).unwrap().unwrap();
        let commit = message(&bobs.streams()[0], &commit);
        let got = bobs.receive(&bob.provider, &commit, &creator);
        assert!(
            got.is_ok(),
            "Bob holds every proposal the commit names: {got:?}"
        );
        assert!(bobs.leaf_key() != before, "Bob's update went in");
    }
}
