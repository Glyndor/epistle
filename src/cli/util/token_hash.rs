//! `epistle token-hash`: the SHA-256 digest of a token read from stdin.

use super::input::read_line;
use super::output::print_json;
use std::process::ExitCode;

pub(in crate::cli) fn token_hash(json: bool) -> ExitCode {
	token_hash_from(std::io::stdin().lock(), json)
}

pub(in crate::cli) fn token_hash_from(reader: impl std::io::BufRead, json: bool) -> ExitCode {
	// let-else for the same reason as the caller in `accounts.rs`: a returning
	// match arm still counts as an arm of the expression that binds `token`.
	let Ok(token) = read_line(reader) else {
		return ExitCode::FAILURE;
	};
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	if json {
		return print_json(&serde_json::json!({ "token_hash": format!("sha256:{hex}") }));
	}
	println!("sha256:{hex}");
	ExitCode::SUCCESS
}
