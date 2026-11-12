//! A watchdog around the loader and owner-only temporary files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use epistle::config::{Config, ConfigError};

pub const WATCHDOG: Duration = Duration::from_secs(20);
pub const VALID: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
/// The most an error message may carry however hostile the file was.
pub const MAX_MESSAGE: usize = 4096;

/// An owner-only file holding `content`.
pub fn file(content: &[u8]) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(content).expect("write");
	file
}

/// `Config::load` on its own thread with a watchdog: a parser that hangs or
/// overflows its stack fails the test instead of the run.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
	let path: PathBuf = path.to_path_buf();
	let (send, recv) = std::sync::mpsc::sync_channel(1);
	let task = std::thread::spawn(move || {
		let _ = send.send(Config::load(&path));
	});
	let result = recv.recv_timeout(WATCHDOG).expect("loader hang or panic");
	task.join().expect("loader thread panicked");
	result
}

/// The loader's refusal of `text`, as the message an operator reads.
pub fn refusal(text: &str) -> (ConfigError, String) {
	let file = file(text.as_bytes());
	let error = load(file.path()).expect_err("the hostile file is refused");
	let message = error.to_string();
	(error, message)
}
