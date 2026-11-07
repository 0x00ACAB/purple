//! The TUI as an Elm-style loop: a [`Model`], an [`update`] that turns messages into a new
//! model plus commands for `purple-core`, and a [`view`] that draws the model.
//!
//! Everything shown that came from outside this process goes through [`sanitize`] first,
//! so a peer can't send terminal escape sequences or bidi overrides.
//!
//! Until `purple-core` reports the vault unlocked, the input line takes the passphrase
//! (masked), and nothing typed is parsed as a command.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use purple_ipc::ui::{MAX_BODY_LEN, UiCmd, UiEvent};
use purple_ipc::{NetStatus, Route};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use zeroize::{Zeroize, Zeroizing};

/// Lines kept in the system log.
const SYSTEM_LOG_LINES: usize = 200;
/// Shortest passphrase for a new vault. purple-core enforces the same limit.
const MIN_PASSPHRASE_CHARS: usize = 8;

const HELP: &[&str] = &[
    "/invite NAME          create an invite for a new contact called NAME",
    "/accept NAME INVITE   accept an invite (paste it) from a contact called NAME",
    "/passphrase           change the vault passphrase (Esc cancels)",
    "/tpm                  seal the vault to this machine's TPM; you get a recovery code",
    "/group new NAME              create a group (shown as #NAME)",
    "/group add NAME CONTACT      ask a contact to join your group",
    "/group remove NAME MEMBER    remove a member, or cancel a request (your groups only)",
    "/group join CREATOR NAME     accept a request to join a group",
    "/group leave NAME            leave a group",
    "/group members NAME          list members: ✓ for your contacts",
    "/group rekey NAME            replace your key in a group now (after a suspected compromise)",
    "/bridges LINE         try a Tor bridge line, once Tor can't connect",
    "/direct               connect to the store without Tor, once Tor can't connect",
    "/quit                 exit (also Esc or Ctrl-C)",
    "Up/Down or Tab switch conversation; anything else you type is sent to the selected one.",
];

/// Input to [`update`].
#[derive(Debug)]
pub(crate) enum Msg {
    /// A key press.
    Key(KeyEvent),
    /// Pasted text (bracketed paste).
    Paste(String),
    /// An event from `purple-core`.
    Core(UiEvent),
    /// `purple-core` closed its socket or sent something unreadable.
    CoreGone(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChatLine {
    from: String,
    body: String,
}

/// Where unlocking the vault stands.
#[derive(Default)]
enum Lock {
    /// Waiting for purple-core to say whether a vault exists.
    #[default]
    Starting,
    /// Asking for the passphrase. For a new vault, `first` holds the first entry until it's
    /// been typed again.
    Locked {
        new: bool,
        first: Option<Zeroizing<String>>,
    },
    /// Passphrase sent; waiting for purple-core.
    Unlocking,
    /// Unlocked: the input line takes messages and commands.
    Open,
}

/// Where a `/passphrase` change or `/tpm` enrollment stands. Each step holds what was
/// typed so far.
#[derive(Default)]
enum Change {
    #[default]
    Idle,
    /// `/tpm`: asking for the passphrase.
    Tpm,
    Old,
    New {
        old: Zeroizing<String>,
    },
    Repeat {
        old: Zeroizing<String>,
        new: Zeroizing<String>,
    },
}

/// Everything the TUI shows.
#[derive(Default)]
pub(crate) struct Model {
    lock: Lock,
    change: Change,
    contacts: Vec<String>,
    selected: usize,
    chats: HashMap<String, Vec<ChatLine>>,
    /// Who created each group this user is in; empty for their own.
    group_creators: HashMap<String, String>,
    system: Vec<String>,
    input: String,
    quit: bool,
    /// purple-net's latest connection status.
    network: Option<NetStatus>,
}

/// Debug without the input line or passphrase.
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("contacts", &self.contacts)
            .finish_non_exhaustive()
    }
}

impl Drop for Model {
    fn drop(&mut self) {
        self.input.zeroize();
    }
}

impl Model {
    pub(crate) fn new() -> Self {
        let mut model = Self::default();
        model.log("purple: starting...");
        model
    }

    /// Add a line to the system log.
    pub(crate) fn note(&mut self, line: String) {
        self.log(line);
    }

    pub(crate) const fn should_quit(&self) -> bool {
        self.quit
    }

    fn selected_contact(&self) -> Option<&str> {
        self.contacts.get(self.selected).map(String::as_str)
    }

    fn log(&mut self, line: impl Into<String>) {
        self.system.push(line.into());
        let excess = self.system.len().saturating_sub(SYSTEM_LOG_LINES);
        self.system.drain(..excess);
    }

    fn add_contact(&mut self, contact: String) {
        if !self.contacts.contains(&contact) {
            self.contacts.push(contact);
        }
    }
}

/// Apply one message to the model. Returns the commands to send to `purple-core`.
pub(crate) fn update(model: &mut Model, msg: Msg) -> Vec<UiCmd> {
    match msg {
        Msg::Key(key) => on_key(model, key),
        Msg::Paste(text) => {
            // Pasted invites may arrive wrapped across lines; drop all whitespace runs that
            // contain a line break, and anything else unprintable.
            let flat: String = text.split(['\n', '\r']).map(str::trim).collect();
            push_input(model, &sanitize(&flat));
            Vec::new()
        }
        Msg::Core(event) => {
            on_core_event(model, event);
            Vec::new()
        }
        Msg::CoreGone(reason) => {
            model.log(format!("purple-core stopped: {}", sanitize(&reason)));
            model.quit = true;
            Vec::new()
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "keys without a binding are ignored, including ones crossterm adds later"
)]
fn on_key(model: &mut Model, key: KeyEvent) -> Vec<UiCmd> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Esc if !matches!(model.change, Change::Idle) => {
            model.change = Change::Idle;
            model.input.zeroize();
            model.log("cancelled");
        }
        KeyCode::Esc => model.quit = true,
        KeyCode::Char('c') if ctrl => model.quit = true,
        KeyCode::Char(c) if !ctrl => push_input(model, &sanitize(&c.to_string())),
        KeyCode::Backspace => {
            model.input.pop();
        }
        KeyCode::Up | KeyCode::BackTab => {
            model.selected = model
                .selected
                .checked_sub(1)
                .unwrap_or_else(|| model.contacts.len().saturating_sub(1));
        }
        KeyCode::Down | KeyCode::Tab => {
            model.selected = match model.selected.checked_add(1) {
                Some(next) if next < model.contacts.len() => next,
                _ => 0,
            };
        }
        KeyCode::Enter if !matches!(model.change, Change::Idle) => return submit_change(model),
        KeyCode::Enter if matches!(model.lock, Lock::Open) => return submit(model),
        KeyCode::Enter => return submit_passphrase(model),
        _ => {}
    }
    Vec::new()
}

fn push_input(model: &mut Model, text: &str) {
    for c in text.chars() {
        if model.input.len().saturating_add(c.len_utf8()) > MAX_BODY_LEN {
            break;
        }
        model.input.push(c);
    }
}

fn submit(model: &mut Model) -> Vec<UiCmd> {
    let typed = std::mem::take(&mut model.input);
    let typed = typed.trim();
    if typed.is_empty() {
        return Vec::new();
    }
    let Some(command) = typed.strip_prefix('/') else {
        return send(model, typed);
    };
    if let Some(line) = command.strip_prefix("bridges ") {
        let line = line.trim();
        if !safe_bridge_line(line) {
            model.log("that isn't a bridge line purple can use");
            return Vec::new();
        }
        return vec![UiCmd::AddBridges {
            lines: line.to_owned(),
        }];
    }
    let mut words = command.split_whitespace();
    match (words.next(), words.next(), words.next(), words.next()) {
        (Some("invite"), Some(name), None, None) => {
            vec![UiCmd::CreateInvite {
                contact: name.to_owned(),
            }]
        }
        (Some("accept"), Some(name), Some(invite), None) => {
            model.log(format!(
                "accepting {name}'s invite; waiting for their bundle..."
            ));
            vec![UiCmd::AcceptInvite {
                contact: name.to_owned(),
                invite: invite.to_owned(),
            }]
        }
        (Some("direct"), None, None, None) => {
            if model.network == Some(NetStatus::Blocked) {
                model.log("network: connecting directly to the store...");
                vec![UiCmd::UseDirect]
            } else {
                model.log("purple is still trying Tor; /direct is offered if every route fails");
                Vec::new()
            }
        }
        (Some("quit"), None, None, None) => {
            model.quit = true;
            Vec::new()
        }
        (Some("passphrase"), None, None, None) => {
            model.change = Change::Old;
            model.log("current passphrase:");
            Vec::new()
        }
        (Some("tpm"), None, None, None) => {
            model.change = Change::Tpm;
            model.log(
                "this seals the vault to this machine's TPM. You'll get a recovery code to write \
                 down. Passphrase:",
            );
            Vec::new()
        }
        (Some("group"), Some(verb), Some(first), second) if words.next().is_none() => {
            group_command(model, verb, first, second)
        }
        (Some("help"), None, None, None) => {
            for help in HELP {
                model.log(*help);
            }
            Vec::new()
        }
        _ => {
            model.log(format!("unknown command: /{command} (try /help)"));
            Vec::new()
        }
    }
}

/// `/group VERB FIRST [SECOND]`.
fn group_command(model: &mut Model, verb: &str, first: &str, second: Option<&str>) -> Vec<UiCmd> {
    let (a, b) = (first.to_owned(), second.map(str::to_owned));
    let cmd = match (verb, b) {
        ("new", None) => UiCmd::GroupNew { group: a },
        ("leave", None) => UiCmd::GroupLeave { group: a },
        ("members", None) => UiCmd::GroupMembers { group: a },
        ("rekey", None) => UiCmd::GroupRekey { group: a },
        ("add", Some(contact)) => UiCmd::GroupAdd { group: a, contact },
        ("remove", Some(member)) => UiCmd::GroupRemove { group: a, member },
        ("join", Some(group)) => UiCmd::GroupJoin { creator: a, group },
        _ => {
            model.log(
                "usage: /group new|leave|members|rekey NAME, /group add|remove NAME CONTACT, \
                       /group join CREATOR NAME",
            );
            return Vec::new();
        }
    };
    vec![cmd]
}

fn submit_passphrase(model: &mut Model) -> Vec<UiCmd> {
    let typed = Zeroizing::new(std::mem::take(&mut model.input));
    let unlock = |passphrase: &Zeroizing<String>| UiCmd::Unlock {
        passphrase: passphrase.to_string(),
    };
    match std::mem::take(&mut model.lock) {
        Lock::Locked { new: false, .. } => {
            model.lock = Lock::Unlocking;
            model.log("unlocking...");
            vec![unlock(&typed)]
        }
        Lock::Locked {
            new: true,
            first: None,
        } => {
            if typed.chars().count() < MIN_PASSPHRASE_CHARS {
                model.log("use at least 8 characters");
                model.lock = Lock::Locked {
                    new: true,
                    first: None,
                };
            } else {
                model.log("type it again to confirm:");
                model.lock = Lock::Locked {
                    new: true,
                    first: Some(typed),
                };
            }
            Vec::new()
        }
        Lock::Locked {
            new: true,
            first: Some(first),
        } => {
            if first == typed {
                model.lock = Lock::Unlocking;
                model.log("creating your vault...");
                vec![unlock(&typed)]
            } else {
                model.log("passphrases didn't match; choose one again:");
                model.lock = Lock::Locked {
                    new: true,
                    first: None,
                };
                Vec::new()
            }
        }
        other @ (Lock::Starting | Lock::Unlocking | Lock::Open) => {
            model.lock = other;
            Vec::new()
        }
    }
}

fn submit_change(model: &mut Model) -> Vec<UiCmd> {
    let typed = Zeroizing::new(std::mem::take(&mut model.input));
    match std::mem::take(&mut model.change) {
        Change::Tpm => {
            model.log("sealing the vault to the TPM...");
            return vec![UiCmd::EnrollTpm {
                passphrase: typed.to_string(),
            }];
        }
        Change::Old => {
            model.log("new passphrase (at least 8 characters):");
            model.change = Change::New { old: typed };
        }
        Change::New { old } => {
            if typed.chars().count() < MIN_PASSPHRASE_CHARS {
                model.log("use at least 8 characters:");
                model.change = Change::New { old };
            } else {
                model.log("type the new passphrase again:");
                model.change = Change::Repeat { old, new: typed };
            }
        }
        Change::Repeat { old, new } => {
            if new == typed {
                model.log("changing passphrase...");
                return vec![UiCmd::ChangePassphrase {
                    old: old.to_string(),
                    new: new.to_string(),
                }];
            }
            model.log("passphrases didn't match; new passphrase:");
            model.change = Change::New { old };
        }
        Change::Idle => {}
    }
    Vec::new()
}

fn send(model: &mut Model, body: &str) -> Vec<UiCmd> {
    let Some(contact) = model.selected_contact().map(str::to_owned) else {
        model.log("no contact selected: /invite or /accept someone first");
        return Vec::new();
    };
    if let Some(group) = contact.strip_prefix('#') {
        let group = group.to_owned();
        model.chats.entry(contact).or_default().push(ChatLine {
            from: "me".to_owned(),
            body: body.to_owned(),
        });
        return vec![UiCmd::GroupSend {
            group,
            body: body.to_owned(),
        }];
    }
    model
        .chats
        .entry(contact.clone())
        .or_default()
        .push(ChatLine {
            from: "me".to_owned(),
            body: body.to_owned(),
        });
    vec![UiCmd::Send {
        contact,
        body: body.to_owned(),
    }]
}

fn on_core_event(model: &mut Model, event: UiEvent) {
    match event {
        UiEvent::NeedPassphrase { new } => {
            model.lock = Lock::Locked { new, first: None };
            model.log(if new {
                "choose a passphrase for your new vault (at least 8 characters):"
            } else {
                "enter your passphrase:"
            });
        }
        UiEvent::Unlocked => {
            model.lock = Lock::Open;
            model.log("unlocked. type /help for commands.");
        }
        UiEvent::PassphraseChanged => model.log("passphrase changed"),
        UiEvent::TpmEnrolled { recovery_code } => {
            model.log("the vault is sealed to the TPM. Write down this recovery code; it is shown only now:");
            model.log(format!("    {}", sanitize(&recovery_code)));
            model.log("if the TPM is ever lost or cleared, type it at the passphrase prompt.");
        }
        UiEvent::RecoveryUnlocked => model.log(
            "opened with the recovery code. Set a new passphrase now with /passphrase, giving \
             the recovery code as the current one.",
        ),
        UiEvent::Sent { to, body } => {
            let to = sanitize(&to);
            model.add_contact(to.clone());
            model.chats.entry(to).or_default().push(ChatLine {
                from: "me".to_owned(),
                body: sanitize(&body),
            });
        }
        UiEvent::InviteCreated { contact, invite } => {
            model.log(format!(
                "invite for {} created. Give them this whole line:",
                sanitize(&contact)
            ));
            model.log(sanitize(&invite));
        }
        UiEvent::Connected { contact } => {
            let contact = sanitize(&contact);
            model.log(format!("connected to {contact}"));
            model.add_contact(contact);
        }
        UiEvent::Message { from, body } => {
            let from = sanitize(&from);
            model.add_contact(from.clone());
            model.chats.entry(from.clone()).or_default().push(ChatLine {
                from,
                body: sanitize(&body),
            });
        }
        UiEvent::Error { message } => model.log(format!("error: {}", sanitize(&message))),
        UiEvent::Notice { text } => model.log(format!("network: {}", sanitize(&text))),
        UiEvent::GroupJoined { .. }
        | UiEvent::GroupRequest { .. }
        | UiEvent::GroupMessage { .. }
        | UiEvent::GroupSent { .. }
        | UiEvent::GroupNotice { .. }
        | UiEvent::GroupLeft { .. }
        | UiEvent::GroupMembers { .. } => on_group_event(model, event),
        UiEvent::Network { status } => on_network(model, status),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "on_core_event passes only group events here"
)]
fn on_group_event(model: &mut Model, event: UiEvent) {
    match event {
        UiEvent::GroupJoined { group, creator } => {
            let (group, creator) = (sanitize(&group), sanitize(&creator));
            model.log(if creator.is_empty() {
                format!("created #{group}")
            } else {
                format!("joined #{group} (created by {creator})")
            });
            model.group_creators.insert(group.clone(), creator);
            model.add_contact(format!("#{group}"));
        }
        UiEvent::GroupRequest { creator, group } => {
            let (creator, group) = (sanitize(&creator), sanitize(&group));
            model.log(format!(
                "{creator} asks you to join #{group}. Accept with: /group join {creator} {group}"
            ));
        }
        UiEvent::GroupMessage {
            group,
            from,
            verified,
            body,
        } => {
            let group = sanitize(&group);
            let label = sender_label(model, &group, &sanitize(&from), verified);
            let key = format!("#{group}");
            model.add_contact(key.clone());
            model.chats.entry(key).or_default().push(ChatLine {
                from: label,
                body: sanitize(&body),
            });
        }
        UiEvent::GroupSent { group, body } => {
            let key = format!("#{}", sanitize(&group));
            model.add_contact(key.clone());
            model.chats.entry(key).or_default().push(ChatLine {
                from: "me".to_owned(),
                body: sanitize(&body),
            });
        }
        UiEvent::GroupNotice { group, text } => {
            model.log(format!("#{}: {}", sanitize(&group), sanitize(&text)));
        }
        UiEvent::GroupLeft { group, reason } => {
            let group = sanitize(&group);
            model.log(format!("left #{group}: {}", sanitize(&reason)));
            let key = format!("#{group}");
            model.contacts.retain(|contact| *contact != key);
            model.selected = model.selected.min(model.contacts.len().saturating_sub(1));
        }
        UiEvent::GroupMembers { group, members } => {
            let group = sanitize(&group);
            let shown: Vec<String> = members
                .iter()
                .map(|(name, verified)| sender_label(model, &group, &sanitize(name), *verified))
                .collect();
            model.log(format!("#{group}: {}", shown.join(", ")));
        }
        _ => {}
    }
}

/// What the user reads about the route, and when to say it.
fn on_network(model: &mut Model, status: NetStatus) {
    let previous = model.network.replace(status);
    match status {
        NetStatus::Connecting { route, percent } => {
            let last = match previous {
                Some(NetStatus::Connecting {
                    route: was,
                    percent: p,
                }) if was == route => Some(p),
                _ => None,
            };
            // A line when the route changes, then one per quarter.
            if last.is_none_or(|last| percent / 25 > last / 25) {
                model.log(format!(
                    "network: connecting {} ({percent}%)",
                    route_name(route)
                ));
            }
        }
        NetStatus::Connected { route } => {
            model.log(format!("network: connected {}", route_name(route)));
        }
        NetStatus::Blocked => {
            for line in BLOCKED_HELP {
                model.log(*line);
            }
        }
    }
}

const fn route_name(route: Route) -> &'static str {
    match route {
        Route::Tor => "over Tor",
        Route::Obfs4 => "over Tor with obfs4 bridges",
        Route::Snowflake => "over Tor with Snowflake",
        Route::WebTunnel => "over Tor with WebTunnel bridges",
        Route::Pasted => "over Tor with your bridges",
        Route::Direct => "directly to the store (not over Tor)",
    }
}

/// Shown when every automatic route failed. The last line must stay whole.
const BLOCKED_HELP: &[&str] = &[
    "network: Tor can't connect from here, with or without the built-in bridges.",
    "  /bridges LINE   try a bridge line from bridges.torproject.org (one per command)",
    "  /direct         connect to the store directly until purple exits:",
    "    The store will see your IP address and when you're online. Your ISP will see that you use this store. If your contact also connects directly, the store can tell that you two talk.",
];

/// The rule purple-net applies to bridge lines (`check_bridge_line`), checked here too so
/// the user hears at once: not empty, at most 1000 bytes, printable ASCII without quotes
/// or backslashes.
fn safe_bridge_line(line: &str) -> bool {
    !line.is_empty()
        && line.len() <= 1000
        && line
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\')
}

/// How a group message's sender is shown: a check mark for your contacts, otherwise whose
/// contact they are.
fn sender_label(model: &Model, group: &str, from: &str, verified: bool) -> String {
    // Only purple-core's own "me" is verified; a name the creator chose never is.
    if verified && from == "me" {
        return "me".to_owned();
    }
    if verified {
        return format!("{from} ✓");
    }
    model
        .group_creators
        .get(group)
        .filter(|creator| !creator.is_empty())
        .map_or_else(
            || format!("{from} (not verified)"),
            |creator| format!("{from} ({creator}'s contact)"),
        )
}

/// Replace every control character (including ESC and newlines) and every bidi control
/// with a space, so text can't move the cursor, change colours, or reorder what's shown.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_bidi_control(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Draw the model: contacts on the left, the selected chat on the right, the system log
/// below, and the input line at the bottom.
pub(crate) fn view(model: &Model, frame: &mut Frame<'_>) {
    let [main, system, input] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(8),
        Constraint::Length(3),
    ])
    .areas(frame.area());
    let [contacts_area, chat_area] =
        Layout::horizontal([Constraint::Length(24), Constraint::Min(20)]).areas(main);

    let items: Vec<ListItem<'_>> = model
        .contacts
        .iter()
        .map(|c| ListItem::new(c.as_str()))
        .collect();
    let mut state =
        ListState::default().with_selected((!model.contacts.is_empty()).then_some(model.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title(" contacts "))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        contacts_area,
        &mut state,
    );

    let title = model
        .selected_contact()
        .map_or_else(|| " no contact ".to_owned(), |c| format!(" {c} "));
    let lines: Vec<Line<'_>> = model
        .selected_contact()
        .and_then(|c| model.chats.get(c))
        .map(|chat| {
            chat.iter()
                .map(|l| {
                    Line::from(vec![
                        Span::styled(
                            format!("{}: ", l.from),
                            Style::new().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(l.body.as_str()),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    frame.render_widget(bottom_aligned(lines, chat_area, title), chat_area);

    let log: Vec<Line<'_>> = model.system.iter().map(|l| Line::raw(l.as_str())).collect();
    frame.render_widget(bottom_aligned(log, system, " purple ".to_owned()), system);

    let masked = || "*".repeat(model.input.chars().count());
    let (input_title, shown) = match (&model.change, &model.lock) {
        (Change::Tpm, _) => (" passphrase ", masked()),
        (Change::Old, _) => (" current passphrase ", masked()),
        (Change::New { .. }, _) => (" new passphrase ", masked()),
        (Change::Repeat { .. }, _) => (" repeat new passphrase ", masked()),
        (Change::Idle, lock) => match lock {
            Lock::Open => (" > ", model.input.clone()),
            Lock::Locked {
                new: true,
                first: None,
            } => (" new passphrase ", masked()),
            Lock::Locked {
                new: true,
                first: Some(_),
            } => (" repeat passphrase ", masked()),
            Lock::Locked { new: false, .. } => (" passphrase ", masked()),
            Lock::Starting | Lock::Unlocking => (" please wait ", String::new()),
        },
    };
    frame.render_widget(
        Paragraph::new(shown).block(Block::bordered().title(input_title)),
        input,
    );
}

/// A wrapped, bordered paragraph scrolled so its last lines are visible.
fn bottom_aligned(lines: Vec<Line<'_>>, area: Rect, title: String) -> Paragraph<'_> {
    let inner_width = area.width.saturating_sub(2);
    let inner_height = area.height.saturating_sub(2);
    let wrap = Wrap { trim: false };
    // Measure with the same word wrapping the render uses, without the border.
    let rows = Paragraph::new(lines.clone())
        .wrap(wrap)
        .line_count(inner_width);
    let scroll = u16::try_from(rows)
        .unwrap_or(u16::MAX)
        .saturating_sub(inner_height);
    Paragraph::new(lines)
        .block(Block::bordered().title(title))
        .wrap(wrap)
        .scroll((scroll, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    /// A model that's past the passphrase prompt.
    fn open_model() -> Model {
        let mut m = Model::new();
        update(&mut m, Msg::Core(UiEvent::Unlocked));
        m
    }

    fn type_line(model: &mut Model, text: &str) -> Vec<UiCmd> {
        for c in text.chars() {
            update(model, key(KeyCode::Char(c)));
        }
        update(model, key(KeyCode::Enter))
    }

    fn core_event(model: &mut Model, event: UiEvent) {
        update(model, Msg::Core(event));
    }

    #[test]
    fn blocked_tor_explains_the_cost_and_offers_both_choices() {
        let mut m = open_model();
        core_event(
            &mut m,
            UiEvent::Network {
                status: NetStatus::Blocked,
            },
        );
        let log = m.system.join("\n");
        assert!(log.contains(
            "The store will see your IP address and when you're online. Your ISP will see that \
             you use this store. If your contact also connects directly, the store can tell \
             that you two talk."
        ));
        assert!(log.contains("/direct") && log.contains("/bridges"));
        assert_eq!(type_line(&mut m, "/direct"), [UiCmd::UseDirect]);
    }

    #[test]
    fn direct_command_without_prompt_says_so() {
        let mut m = open_model();
        core_event(
            &mut m,
            UiEvent::Network {
                status: NetStatus::Connecting {
                    route: Route::Tor,
                    percent: 20,
                },
            },
        );
        assert!(type_line(&mut m, "/direct").is_empty());
        assert!(m.system.last().unwrap().contains("still trying Tor"));
    }

    #[test]
    fn bridges_command_checks_the_line() {
        let mut m = open_model();
        core_event(
            &mut m,
            UiEvent::Network {
                status: NetStatus::Blocked,
            },
        );
        assert_eq!(
            type_line(
                &mut m,
                "/bridges obfs4 192.0.2.1:443 F00 cert=abc iat-mode=0"
            ),
            [UiCmd::AddBridges {
                lines: "obfs4 192.0.2.1:443 F00 cert=abc iat-mode=0".into()
            }]
        );
        assert!(type_line(&mut m, "/bridges x\" Bridge=\"y").is_empty());
    }

    #[test]
    fn progress_is_logged_sparingly() {
        let mut m = open_model();
        let before = m.system.len();
        for percent in 0..=99 {
            core_event(
                &mut m,
                UiEvent::Network {
                    status: NetStatus::Connecting {
                        route: Route::Tor,
                        percent,
                    },
                },
            );
        }
        core_event(
            &mut m,
            UiEvent::Network {
                status: NetStatus::Connected { route: Route::Tor },
            },
        );
        let added = m.system.len() - before;
        assert!((2..=6).contains(&added), "{added} lines");
        assert!(m.system.last().unwrap().contains("connected over Tor"));
    }

    fn unlock_cmd(passphrase: &str) -> Vec<UiCmd> {
        vec![UiCmd::Unlock {
            passphrase: passphrase.into(),
        }]
    }

    #[test]
    fn new_vault_needs_a_long_enough_passphrase_typed_twice() {
        let mut m = Model::new();
        update(&mut m, Msg::Core(UiEvent::NeedPassphrase { new: true }));
        assert!(type_line(&mut m, "short").is_empty());
        assert!(type_line(&mut m, "correct horse").is_empty());
        assert!(type_line(&mut m, "wrong horse!").is_empty());
        assert!(type_line(&mut m, "correct horse").is_empty());
        assert_eq!(
            type_line(&mut m, "correct horse"),
            unlock_cmd("correct horse")
        );
    }

    #[test]
    fn existing_vault_unlocks_and_nothing_is_a_command_until_then() {
        let mut m = Model::new();
        assert!(type_line(&mut m, "/invite bob").is_empty());
        update(&mut m, Msg::Core(UiEvent::NeedPassphrase { new: false }));
        assert_eq!(type_line(&mut m, "/invite bob"), unlock_cmd("/invite bob"));
        update(
            &mut m,
            Msg::Core(UiEvent::Error {
                message: "wrong passphrase".into(),
            }),
        );
        update(&mut m, Msg::Core(UiEvent::NeedPassphrase { new: false }));
        assert_eq!(type_line(&mut m, "right one"), unlock_cmd("right one"));
        update(&mut m, Msg::Core(UiEvent::Unlocked));
        assert_eq!(
            type_line(&mut m, "/invite bob"),
            [UiCmd::CreateInvite {
                contact: "bob".into()
            }]
        );
    }

    #[test]
    fn passphrase_change_asks_old_then_new_twice() {
        let mut m = open_model();
        assert!(type_line(&mut m, "/passphrase").is_empty());
        assert!(type_line(&mut m, "old one!").is_empty());
        assert!(type_line(&mut m, "short").is_empty());
        assert!(type_line(&mut m, "brand new pass").is_empty());
        assert!(type_line(&mut m, "typo new pass").is_empty());
        assert!(type_line(&mut m, "brand new pass").is_empty());
        assert_eq!(
            type_line(&mut m, "brand new pass"),
            [UiCmd::ChangePassphrase {
                old: "old one!".into(),
                new: "brand new pass".into(),
            }]
        );
        // Back to normal: text goes to commands again.
        assert_eq!(
            type_line(&mut m, "/invite bob"),
            [UiCmd::CreateInvite {
                contact: "bob".into()
            }]
        );
    }

    #[test]
    fn esc_cancels_a_passphrase_change_instead_of_quitting() {
        let mut m = open_model();
        type_line(&mut m, "/passphrase");
        for c in "half typed".chars() {
            update(&mut m, key(KeyCode::Char(c)));
        }
        update(&mut m, key(KeyCode::Esc));
        assert!(!m.should_quit());
        assert!(m.input.is_empty());
        assert!(matches!(m.change, Change::Idle));
        update(&mut m, key(KeyCode::Esc));
        assert!(m.should_quit());
    }

    #[test]
    fn replayed_history_shows_both_directions() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::Sent {
                to: "bob".into(),
                body: "earlier".into(),
            }),
        );
        update(
            &mut m,
            Msg::Core(UiEvent::Message {
                from: "bob".into(),
                body: "reply".into(),
            }),
        );
        let froms: Vec<_> = m.chats["bob"].iter().map(|l| l.from.as_str()).collect();
        assert_eq!(froms, ["me", "bob"]);
        assert_eq!(m.contacts, ["bob"]);
    }

    #[test]
    fn long_wrapped_messages_scroll_to_their_last_line() {
        // Word wrapping needs more rows than characters / width; the scroll must use the
        // real wrapped height or the end of long messages is cut off.
        let words = format!("{}THE-END", "long ".repeat(900));
        let area = Rect::new(0, 0, 50, 20);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        ratatui::widgets::Widget::render(
            bottom_aligned(vec![Line::raw(words.as_str())], area, String::new()),
            area,
            &mut buffer,
        );
        let shown: String = (0..area.height)
            .flat_map(|y| (0..area.width).map(move |x| (x, y)))
            .map(|pos| buffer[pos].symbol().to_owned())
            .collect();
        assert!(shown.contains("THE-END"));
    }

    #[test]
    fn sanitize_strips_escapes_controls_and_bidi() {
        assert_eq!(sanitize("a\u{1b}[2Jb"), "a [2Jb");
        assert_eq!(sanitize("x\ny\rz\u{7}"), "x y z ");
        assert_eq!(sanitize("\u{9b}31m"), " 31m");
        assert_eq!(sanitize("ab\u{202E}cd\u{2066}"), "ab cd ");
        assert_eq!(sanitize("héllo 🙂"), "héllo 🙂");
    }

    #[test]
    fn commands_become_core_requests() {
        let mut m = open_model();
        assert_eq!(
            type_line(&mut m, "/invite alice"),
            [UiCmd::CreateInvite {
                contact: "alice".into()
            }]
        );
        assert_eq!(
            type_line(&mut m, "/accept bob purple1abc"),
            [UiCmd::AcceptInvite {
                contact: "bob".into(),
                invite: "purple1abc".into()
            }]
        );
        assert!(type_line(&mut m, "/nope").is_empty());
        assert!(type_line(&mut m, "/quit").is_empty());
        assert!(m.should_quit());
    }

    #[test]
    fn text_goes_to_the_selected_contact_only_once_connected() {
        let mut m = open_model();
        assert!(type_line(&mut m, "hello?").is_empty());

        update(
            &mut m,
            Msg::Core(UiEvent::Connected {
                contact: "alice".into(),
            }),
        );
        update(
            &mut m,
            Msg::Core(UiEvent::Connected {
                contact: "bob".into(),
            }),
        );
        update(&mut m, key(KeyCode::Down));
        assert_eq!(
            type_line(&mut m, "hi bob"),
            [UiCmd::Send {
                contact: "bob".into(),
                body: "hi bob".into()
            }]
        );
        assert_eq!(m.chats["bob"].last().unwrap().from, "me");
    }

    #[test]
    fn incoming_text_is_sanitized() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::Message {
                from: "alice".into(),
                body: "\u{1b}]0;pwned\u{7}".into(),
            }),
        );
        assert_eq!(m.chats["alice"][0].body, " ]0;pwned ");
    }

    #[test]
    fn wrapped_paste_is_joined() {
        let mut m = open_model();
        update(&mut m, Msg::Paste("/accept bob purple1ab\ncd\r\nef".into()));
        assert_eq!(m.input, "/accept bob purple1abcdef");
    }

    #[test]
    fn control_keys_never_reach_the_input() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)),
        );
        update(&mut m, key(KeyCode::Char('\u{1b}')));
        assert_eq!(m.input, " ");
    }

    #[test]
    fn group_events_show_up_under_the_group() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::GroupJoined {
                group: "team".into(),
                creator: "alice".into(),
            }),
        );
        for (from, verified, body) in [("dana", false, "hi"), ("alice", true, "yo")] {
            update(
                &mut m,
                Msg::Core(UiEvent::GroupMessage {
                    group: "team".into(),
                    from: from.into(),
                    verified,
                    body: body.into(),
                }),
            );
        }
        assert!(m.contacts.contains(&"#team".to_owned()));
        let lines = &m.chats["#team"];
        assert_eq!(lines[0].from, "dana (alice's contact)");
        assert_eq!(lines[1].from, "alice ✓");

        update(
            &mut m,
            Msg::Core(UiEvent::GroupLeft {
                group: "team".into(),
                reason: "removed by alice".into(),
            }),
        );
        assert!(!m.contacts.contains(&"#team".to_owned()));
    }

    #[test]
    fn group_commands_become_core_requests() {
        let mut m = open_model();
        let group = || "team".to_owned();
        assert_eq!(
            type_line(&mut m, "/group new team"),
            [UiCmd::GroupNew { group: group() }]
        );
        assert_eq!(
            type_line(&mut m, "/group add team bob"),
            [UiCmd::GroupAdd {
                group: group(),
                contact: "bob".into()
            }]
        );
        assert_eq!(
            type_line(&mut m, "/group remove team bob"),
            [UiCmd::GroupRemove {
                group: group(),
                member: "bob".into()
            }]
        );
        assert_eq!(
            type_line(&mut m, "/group join alice team"),
            [UiCmd::GroupJoin {
                creator: "alice".into(),
                group: group()
            }]
        );
        assert_eq!(
            type_line(&mut m, "/group leave team"),
            [UiCmd::GroupLeave { group: group() }]
        );
        assert_eq!(
            type_line(&mut m, "/group rekey team"),
            [UiCmd::GroupRekey { group: group() }]
        );
        assert_eq!(
            type_line(&mut m, "/group members team"),
            [UiCmd::GroupMembers { group: group() }]
        );
        for bad in [
            "/group",
            "/group add team",
            "/group add team bob extra",
            "/group nope x",
        ] {
            assert!(type_line(&mut m, bad).is_empty(), "{bad}");
        }
    }

    #[test]
    fn text_typed_in_a_group_goes_to_the_group() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::GroupJoined {
                group: "team".into(),
                creator: String::new(),
            }),
        );
        assert_eq!(
            type_line(&mut m, "hello team"),
            [UiCmd::GroupSend {
                group: "team".into(),
                body: "hello team".into()
            }]
        );
        assert_eq!(m.chats["#team"][0].from, "me");
    }

    #[test]
    fn member_lists_are_logged_with_their_marks() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::GroupJoined {
                group: "team".into(),
                creator: "alice".into(),
            }),
        );
        update(
            &mut m,
            Msg::Core(UiEvent::GroupMembers {
                group: "team".into(),
                members: vec![("alice".into(), true), ("dana".into(), false)],
            }),
        );
        assert_eq!(
            m.system.last().unwrap(),
            "#team: alice ✓, dana (alice's contact)"
        );
    }

    #[test]
    fn an_unverified_sender_called_me_is_not_shown_as_you() {
        let mut m = open_model();
        update(
            &mut m,
            Msg::Core(UiEvent::GroupJoined {
                group: "team".into(),
                creator: "alice".into(),
            }),
        );
        update(
            &mut m,
            Msg::Core(UiEvent::GroupMessage {
                group: "team".into(),
                from: "me".into(),
                verified: false,
                body: "hi".into(),
            }),
        );
        assert_eq!(m.chats["#team"][0].from, "me (alice's contact)");
    }

    #[test]
    fn notices_are_shown_as_network_lines() {
        let mut m = open_model();
        core_event(
            &mut m,
            UiEvent::Notice {
                text: "no bridge lines in that".into(),
            },
        );
        assert_eq!(m.system.last().unwrap(), "network: no bridge lines in that");
    }
}
