//! `epistle dkim-keygen` and the key file writer it shares with `init`.

use super::output::print_json;
use std::process::ExitCode;

pub(in crate::cli) fn dkim_keygen(
	out: &std::path::Path,
	rsa: bool,
	bits: u32,
	json: bool,
) -> ExitCode {
	if out.exists() {
		crate::cli::style::error(format_args!(
			"{} already exists, refusing to overwrite",
			out.display()
		));
		return ExitCode::FAILURE;
	}
	if rsa && !matches!(bits, 2048 | 4096) {
		crate::cli::style::error(format_args!("--bits must be 2048 or 4096 (got {bits})"));
		return ExitCode::FAILURE;
	}
	let (pem, record) = if rsa {
		match generate_rsa_key(bits) {
			Ok(generated) => generated,
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	} else {
		match crate::dkim::generate_key() {
			Ok(generated) => generated,
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	};
	if let Err(error) = write_key_pem(out, &pem) {
		crate::cli::style::error(format_args!("cannot write {}: {error}", out.display()));
		return ExitCode::FAILURE;
	}
	if json {
		return print_json(&serde_json::json!({
			"result": "saved", "action": "dkim-keygen", "out": out.display().to_string(),
			"algorithm": if rsa { "rsa" } else { "ed25519" }, "record": record,
		}));
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}

pub(in crate::cli) use crate::dkim::generate_rsa_key;

/// Write the generated PEM to `path` with mode 0600 on Unix (or the
/// closest equivalent on other platforms). Shared between the ed25519 and
/// RSA paths so the file permissions do not drift between them.
fn write_key_pem(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
	// `init` reaches this through the same path; the function stays
	// `pub(super)` so other CLI helpers can call it without exposing it
	// beyond the `cli` module.
	use std::io::Write;
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	options
		.open(path)
		.and_then(|mut file| file.write_all(pem.as_bytes()))
}
