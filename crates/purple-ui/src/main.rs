//! purple-ui: draws the window. Talks only to `purple-core`.

use std::io;
use std::process::ExitCode;

use purple_ipc::{UI_CORE_FD, inherited_stream};

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
    let _core = unsafe { inherited_stream(UI_CORE_FD)? };
    eprintln!("purple-ui: no window yet");
    Ok(())
}
