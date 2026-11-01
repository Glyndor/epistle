//! The key files of one hosted domain, made when the domain is added.
//!
//! Every hosted domain signs with a key of its own: a leaked key then signs
//! only as the domain it belongs to. The files sit under
//! `<data_dir>/keys/dkim/<domain>/`, `ed25519.pem` and, when the server
//! dual-signs, `rsa.pem`, and are named by a `[[dkim.domain]]` entry.
//!
//! The selectors are `own<day>` and `ownrsa<day>`. They are not the ones the
//! `[dkim]` key publishes (`s1` or whatever it is configured with, and the
//! `ed<day>` and `rsa<day>` the rotation makes), so publishing a domain's own
//! record never replaces the record the key it still signs with is published
//! under. `<day>` is the day the key was made, taken from the file when the
//! key already exists, so running the same step again names the same record.

use std::path::{Path, PathBuf};

use super::{Signer, generate_key, generate_rsa_key};

/// The keys of one domain, as a `[[dkim.domain]]` entry names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainKeys {
	/// Ed25519 selector.
	pub selector: String,
	/// Ed25519 key file (PKCS#8 PEM).
	pub key_file: PathBuf,
	/// RSA selector and key file, when the server dual-signs.
	pub rsa: Option<(String, PathBuf)>,
}

/// The directory that holds `domain`'s key files. `domain` is a DNS name the
/// configuration already accepted; the directory is refused for a name that
/// could leave `keys/dkim`.
pub fn key_dir(data_dir: &Path, domain: &str) -> Result<PathBuf, String> {
	let name = domain.trim().to_ascii_lowercase();
	let safe = !name.is_empty()
		&& !name.starts_with('.')
		&& name
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
	if !safe || name.contains("..") {
		return Err(format!(
			"{domain:?} is not a domain name a key directory can carry"
		));
	}
	Ok(data_dir.join("keys").join("dkim").join(name))
}

/// The day number a key file was made on, from its modification time.
fn made_on(file: &Path) -> Option<u64> {
	let modified = std::fs::metadata(file).ok()?.modified().ok()?;
	let seconds = modified
		.duration_since(std::time::UNIX_EPOCH)
		.ok()?
		.as_secs();
	Some(seconds / 86_400)
}

/// The day number of `now`, epoch seconds.
fn day(now: u64) -> u64 {
	now / 86_400
}

/// Create `dir` readable by its owner only.
fn private_dir(dir: &Path) -> std::io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	builder.create(dir)
}

/// The keys [`ensure`] would name for `domain` today, without touching the
/// file system: what a dry run shows.
pub fn planned(
	data_dir: &Path,
	domain: &str,
	dual_signing: bool,
	now: u64,
) -> Result<DomainKeys, String> {
	let dir = key_dir(data_dir, domain)?;
	Ok(DomainKeys {
		selector: format!("own{}", day(now)),
		key_file: dir.join("ed25519.pem"),
		rsa: dual_signing.then(|| (format!("ownrsa{}", day(now)), dir.join("rsa.pem"))),
	})
}

/// Make `domain`'s key files, or take the ones already there. A key file
/// that exists must load: one that does not is an error, never replaced, so
/// a damaged key is not silently swapped for one nobody has published.
/// `created` lists the files this call wrote, for the caller to remove when a
/// later step fails.
pub fn ensure(
	data_dir: &Path,
	domain: &str,
	dual_signing: bool,
	now: u64,
) -> Result<(DomainKeys, Vec<PathBuf>), String> {
	let dir = key_dir(data_dir, domain)?;
	private_dir(&dir).map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
	let mut created = Vec::new();
	let ed_file = dir.join("ed25519.pem");
	if ed_file.exists() {
		Signer::load("check", &ed_file)
			.map_err(|error| format!("{} does not load: {error}", ed_file.display()))?;
	} else {
		let (pem, _) = generate_key().map_err(|error| error.to_string())?;
		crate::storage::write_secret(&ed_file, pem.as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", ed_file.display()))?;
		created.push(ed_file.clone());
	}
	// Read back from the file, so the first run and every later one agree.
	let selector = format!("own{}", made_on(&ed_file).unwrap_or(day(now)));
	let rsa = if dual_signing {
		let rsa_file = dir.join("rsa.pem");
		if rsa_file.exists() {
			super::rsa_record_value(&rsa_file)
				.map_err(|error| format!("{} does not load: {error}", rsa_file.display()))?;
		} else {
			let (pem, _) = generate_rsa_key(2048).map_err(|error| error.to_string())?;
			if let Err(error) = crate::storage::write_secret(&rsa_file, pem.as_bytes()) {
				remove(&created);
				return Err(format!("cannot write {}: {error}", rsa_file.display()));
			}
			created.push(rsa_file.clone());
		}
		let rsa_day = made_on(&rsa_file).unwrap_or(day(now));
		Some((format!("ownrsa{rsa_day}"), rsa_file))
	} else {
		None
	};
	Ok((
		DomainKeys {
			selector,
			key_file: ed_file,
			rsa,
		},
		created,
	))
}

/// Remove key files a failed step leaves behind. Best effort: a file that is
/// already gone is what was wanted.
pub fn remove(files: &[PathBuf]) {
	for file in files {
		if let Err(error) = std::fs::remove_file(file)
			&& error.kind() != std::io::ErrorKind::NotFound
		{
			tracing::warn!(%error, file = %file.display(), "cannot remove a DKIM key file that was not used");
		}
	}
}

#[cfg(test)]
mod tests;
