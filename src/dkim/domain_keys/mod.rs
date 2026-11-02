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

/// The first selector `<prefix><day>` that is not in `reserved`
/// (`<prefix><day>x2`, `x3`, ... after it). A selector a key is still
/// published under must not be the name of a new key's record: publishing it
/// would replace the TXT of the key that is signing.
fn free_selector(prefix: &str, day: u64, reserved: &[String]) -> String {
	let taken = |name: &str| reserved.iter().any(|r| r.eq_ignore_ascii_case(name));
	let mut candidate = format!("{prefix}{day}");
	let mut n = 2;
	while taken(&candidate) {
		candidate = format!("{prefix}{day}x{n}");
		n += 1;
	}
	candidate
}

/// Every selector the `[dkim]` key is published under or is being moved
/// to: the configured pair, the one in service, and the ones a rotation has
/// pending or is retiring. A new key never takes one of these names.
pub fn reserved_selectors(config: &crate::config::Config) -> Result<Vec<String>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let mut found = vec![dkim.selector.clone()];
	found.extend(dkim.rsa_selector.clone());
	let active =
		super::rotate::active_ed25519(dkim, &config.data_dir).map_err(|error| error.to_string())?;
	found.push(active.selector);
	if let Some(rsa) =
		super::rotate::active_rsa(dkim, &config.data_dir).map_err(|error| error.to_string())?
	{
		found.push(rsa.selector);
	}
	if let Some(state) =
		super::rotate::read_state(&config.data_dir).map_err(|error| error.to_string())?
	{
		for named in [state.previous.as_ref().map(|p| (&p.selector, &p.rsa))]
			.into_iter()
			.flatten()
		{
			found.push(named.0.clone());
			found.extend(named.1.iter().map(|rsa| rsa.selector.clone()));
		}
		if let Some(pending) = &state.pending {
			found.push(pending.selector.clone());
			found.extend(pending.rsa.iter().map(|rsa| rsa.selector.clone()));
		}
	}
	Ok(found)
}

/// Write `pem` to `path` only if nothing is there: the key is installed with a
/// hard link, which refuses to replace a file, so two runs that both found the
/// path empty cannot swap one another's key. `Ok(false)` when a key was already
/// there; it is then the one to use.
fn install_new(path: &Path, pem: &str) -> Result<bool, String> {
	let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("key");
	let staged = path.with_file_name(format!(".{name}.{}.new", uuid::Uuid::now_v7()));
	crate::storage::write_secret(&staged, pem.as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	let linked = std::fs::hard_link(&staged, path);
	let _ = std::fs::remove_file(&staged);
	match linked {
		Ok(()) => Ok(true),
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
		Err(error) => Err(format!("cannot write {}: {error}", path.display())),
	}
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
	reserved: &[String],
) -> Result<DomainKeys, String> {
	let dir = key_dir(data_dir, domain)?;
	Ok(DomainKeys {
		selector: free_selector("own", day(now), reserved),
		key_file: dir.join("ed25519.pem"),
		rsa: dual_signing.then(|| {
			(
				free_selector("ownrsa", day(now), reserved),
				dir.join("rsa.pem"),
			)
		}),
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
	reserved: &[String],
) -> Result<(DomainKeys, Vec<PathBuf>), String> {
	let dir = key_dir(data_dir, domain)?;
	private_dir(&dir).map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
	let mut created = Vec::new();
	let ed_file = dir.join("ed25519.pem");
	if !ed_file.exists() {
		let (pem, _) = generate_key().map_err(|error| error.to_string())?;
		if install_new(&ed_file, &pem)? {
			created.push(ed_file.clone());
		}
	}
	// A key that is there, made by this run or by another, must load.
	Signer::load("check", &ed_file)
		.map_err(|error| format!("{} does not load: {error}", ed_file.display()))?;
	// Read back from the file, so the first run and every later one agree.
	let selector = free_selector("own", made_on(&ed_file).unwrap_or(day(now)), reserved);
	let rsa = if dual_signing {
		let rsa_file = dir.join("rsa.pem");
		if !rsa_file.exists() {
			let (pem, _) = generate_rsa_key(2048).map_err(|error| error.to_string())?;
			match install_new(&rsa_file, &pem) {
				Ok(true) => created.push(rsa_file.clone()),
				Ok(false) => {}
				Err(error) => {
					remove(&created);
					return Err(error);
				}
			}
		}
		super::rsa_record_value(&rsa_file)
			.map_err(|error| format!("{} does not load: {error}", rsa_file.display()))?;
		let rsa_day = made_on(&rsa_file).unwrap_or(day(now));
		Some((free_selector("ownrsa", rsa_day, reserved), rsa_file))
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
