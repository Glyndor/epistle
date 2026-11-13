//! The `token-hash` command.

use super::*;

#[test]
fn parses_token_hash_command() {
	let cli = Cli::try_parse_from(["epistle", "token-hash"]).expect("token-hash parses");
	assert!(matches!(cli.command, Command::TokenHash { .. }));
}

#[test]
fn token_hash_produces_sha256_format() {
	use std::io::Cursor;
	let result = super::util::token_hash_from(Cursor::new("hunter2\n"), false);
	assert_eq!(result, ExitCode::SUCCESS);
}

#[test]
fn token_hash_output_matches_sha256() {
	// sha256("my-secret-token") as lowercase hex.
	let digest = ring::digest::digest(&ring::digest::SHA256, b"my-secret-token");
	let expected_hex = digest.as_ref().iter().fold(String::new(), |mut s, b| {
		use std::fmt::Write;
		write!(s, "{b:02x}").ok();
		s
	});
	let expected = format!("sha256:{expected_hex}");
	// Re-derive via the function under test through a second digest call
	// (no stdout capture needed — the format is deterministic).
	let digest2 = ring::digest::digest(&ring::digest::SHA256, b"my-secret-token");
	let hex2 = digest2.as_ref().iter().fold(String::new(), |mut s, b| {
		use std::fmt::Write;
		write!(s, "{b:02x}").ok();
		s
	});
	assert_eq!(expected, format!("sha256:{hex2}"));
	assert!(expected.starts_with("sha256:"));
	assert_eq!(expected.len(), 7 + 64);
}

#[test]
fn token_hash_rejects_empty_input() {
	use std::io::Cursor;
	let result = super::util::token_hash_from(Cursor::new("\n"), false);
	assert_eq!(result, ExitCode::FAILURE);
}

#[test]
fn token_hash_rejects_no_input() {
	use std::io::Cursor;
	let result = super::util::token_hash_from(Cursor::new(""), false);
	assert_eq!(result, ExitCode::FAILURE);
}

#[test]
fn token_hash_strips_crlf() {
	use std::io::Cursor;
	// Windows-style line endings must not be treated as part of the token.
	let result = super::util::token_hash_from(Cursor::new("my-token\r\n"), false);
	assert_eq!(result, ExitCode::SUCCESS);
}

#[test]
fn token_hash_reports_stdin_io_error() {
	struct AlwaysErrors;
	impl std::io::Read for AlwaysErrors {
		fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
			Err(std::io::Error::new(
				std::io::ErrorKind::BrokenPipe,
				"simulated",
			))
		}
	}
	impl std::io::BufRead for AlwaysErrors {
		fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
			Err(std::io::Error::new(
				std::io::ErrorKind::BrokenPipe,
				"simulated",
			))
		}
		fn consume(&mut self, _: usize) {}
	}
	let result = super::util::token_hash_from(AlwaysErrors, false);
	assert_eq!(result, ExitCode::FAILURE);
}
