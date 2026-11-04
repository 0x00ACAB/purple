//! purple-ui: the terminal UI. Talks only to `purple-core`; has no network and no keys.

mod app;

use std::io::{self, stdout};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use crossterm::execute;
use purple_ipc::ui::UiEvent;
use purple_ipc::{UI_CORE_FD, inherited_stream};
use ratatui::DefaultTerminal;

use app::{Model, Msg, update, view};

/// How long to wait for a key before checking for events from `purple-core`.
const TICK: Duration = Duration::from_millis(100);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-ui: {err}");
            ExitCode::FAILURE
        }
    }
}

#[expect(unsafe_code, reason = "adopting the socket the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    // On X11 any client can read keystrokes and screenshot other windows.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err(io::Error::other(
            "WAYLAND_DISPLAY is not set; purple only runs on Wayland",
        ));
    }
    // SAFETY: the launcher hands this fd to purple-ui and nothing else here uses it.
    let mut core = unsafe { inherited_stream(UI_CORE_FD)? };
    let events = spawn_event_reader(core.try_clone()?);

    let mut terminal = ratatui::try_init()?;
    execute!(stdout(), EnableBracketedPaste)?;
    let result = event_loop(&mut terminal, &mut core, &events);
    execute!(stdout(), DisableBracketedPaste).ok();
    ratatui::try_restore()?;
    result
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "resize redraws on the next tick anyway; mouse and focus events are unused"
)]
fn event_loop(
    terminal: &mut DefaultTerminal,
    core: &mut UnixStream,
    events: &Receiver<Msg>,
) -> io::Result<()> {
    let mut model = Model::new();
    while !model.should_quit() {
        terminal.draw(|frame| view(&model, frame))?;
        while let Ok(msg) = events.try_recv() {
            apply(&mut model, msg, core)?;
        }
        if event::poll(TICK)? {
            let msg = match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => Msg::Key(key),
                Event::Paste(text) => Msg::Paste(text),
                _ => continue,
            };
            apply(&mut model, msg, core)?;
        }
    }
    Ok(())
}

fn apply(model: &mut Model, msg: Msg, core: &mut UnixStream) -> io::Result<()> {
    for cmd in update(model, msg) {
        cmd.write_to(core)?;
    }
    Ok(())
}

/// Read events from `purple-core` on their own thread and hand them to the UI loop.
fn spawn_event_reader(mut core: UnixStream) -> Receiver<Msg> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            let msg = match UiEvent::read_from(&mut core) {
                Ok(Some(event)) => Msg::Core(event),
                Ok(None) => Msg::CoreGone("closed the connection".to_owned()),
                Err(err) => Msg::CoreGone(err.to_string()),
            };
            let gone = matches!(msg, Msg::CoreGone(_));
            if tx.send(msg).is_err() || gone {
                return;
            }
        }
    });
    rx
}
