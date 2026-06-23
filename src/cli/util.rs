//! Shared CLI helpers: stdin reading, token hashing, secret generation and the
//! DKIM key-generation command body.

use std::process::ExitCode;

pub(super) fn token_hash() -> ExitCode {
	token_hash_from(std::io::stdin().lock())
}

/// Generate a strong random credential secret: 32 bytes from the system CSPRNG,
/// base32-encoded (unpadded, lowercase) for an easy-to-copy ~52-character
/// string. `None` if the CSPRNG cannot produce bytes (fail closed).
pub(super) fn generate_secret() -> Option<String> {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 32];
	ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
	// RFC 4648 base32 lowercase, no padding.
	const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
	let mut out = String::with_capacity(52);
	let mut buffer: u32 = 0;
	let mut bits = 0u32;
	for &byte in &bytes {
		buffer = (buffer << 8) | byte as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let index = ((buffer >> bits) & 0x1f) as usize;
			out.push(ALPHABET[index] as char);
		}
	}
	if bits > 0 {
		let index = ((buffer << (5 - bits)) & 0x1f) as usize;
		out.push(ALPHABET[index] as char);
	}
	Some(out)
}

/// Read one non-empty line (CR-trimmed) from `reader`, or a FAILURE code.
pub(super) fn read_line(reader: impl std::io::BufRead) -> Result<String, ExitCode> {
	let value = match reader.lines().next() {
		Some(Ok(line)) => line.trim_end_matches('\r').to_owned(),
		Some(Err(error)) => {
			eprintln!("error: reading stdin: {error}");
			return Err(ExitCode::FAILURE);
		}
		None => {
			eprintln!("error: no input — pipe or type the value on stdin");
			return Err(ExitCode::FAILURE);
		}
	};
	if value.is_empty() {
		eprintln!("error: input must not be empty");
		return Err(ExitCode::FAILURE);
	}
	Ok(value)
}

pub(super) fn token_hash_from(reader: impl std::io::BufRead) -> ExitCode {
	let token = match read_line(reader) {
		Ok(token) => token,
		Err(code) => return code,
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
	println!("sha256:{hex}");
	ExitCode::SUCCESS
}

/// Build the at-rest [`MessageCrypto`] from a loaded config, printing the
/// fail-closed error and returning `Err(FAILURE)` if the key cannot be loaded.
pub(super) fn message_crypto(
	config: &crate::config::Config,
) -> Result<crate::storage::MessageCrypto, ExitCode> {
	crate::storage::MessageCrypto::from_config(config.storage.as_ref()).map_err(|error| {
		eprintln!("error: {error}");
		ExitCode::FAILURE
	})
}

/// `epistle storage-keygen`: print a fresh base64 32-byte at-rest encryption key
/// to stdout for the operator to place in an env var or key file (off the data
/// disk). Mirrors `dkim-keygen`; never writes into `data_dir`.
pub(super) fn storage_keygen() -> ExitCode {
	match crate::storage::generate_key_base64() {
		Some(key) => {
			println!("{key}");
			ExitCode::SUCCESS
		}
		None => {
			eprintln!("error: system CSPRNG unavailable");
			ExitCode::FAILURE
		}
	}
}

pub(super) fn dkim_keygen(out: &std::path::Path) -> ExitCode {
	if out.exists() {
		eprintln!(
			"error: {} already exists, refusing to overwrite",
			out.display()
		);
		return ExitCode::FAILURE;
	}
	let (pem, record) = match crate::dkim::generate_key() {
		Ok(generated) => generated,
		Err(error) => {
			eprintln!("error: {error}");
			return ExitCode::FAILURE;
		}
	};
	// The private key must never be group/world readable.
	let result = {
		use std::io::Write;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		options
			.open(out)
			.and_then(|mut file| file.write_all(pem.as_bytes()))
	};
	if let Err(error) = result {
		eprintln!("error: cannot write {}: {error}", out.display());
		return ExitCode::FAILURE;
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}
