//! Directory preparation: marker file, file modes, and the artifacts
//! written into a freshly-laid-out local directory.

use std::path::Path;

use rcgen::CertificateParams;

/// Create `dir` if it does not exist; if it exists and is empty, leave it
/// alone; if it exists with content but no marker, refuse. Returns the
/// [`Outcome`] `prepare` should follow.
pub(super) fn ensure_dir(dir: &Path) -> Result<Outcome, super::LocalError> {
	let outcome = match std::fs::metadata(dir) {
		Ok(metadata) => {
			if !metadata.is_dir() {
				return Err(super::LocalError::Io(std::io::Error::new(
					std::io::ErrorKind::AlreadyExists,
					format!("{} is not a directory", dir.display()),
				)));
			}
			let marker = dir.join(super::MARKER_FILE);
			let config = dir.join("mail.toml");
			if !marker.exists() {
				let has_content = std::fs::read_dir(dir)
					.map_err(super::LocalError::Io)?
					.next()
					.is_some();
				if has_content {
					return Err(super::LocalError::NotEmpty(dir.to_path_buf()));
				}
				Outcome::Generate
			} else if config.exists() {
				Outcome::Reuse
			} else {
				// Marker but no `mail.toml`: a partial state the operator
				// is allowed to be in (e.g. they moved the cert in but
				// not yet the rest). The marker is ours, the dir is ours,
				// so we regenerate.
				Outcome::Generate
			}
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			create_with_mode(dir, 0o700)?;
			Outcome::Generate
		}
		Err(error) => return Err(super::LocalError::Io(error)),
	};
	Ok(outcome)
}

/// What `ensure_dir` decided about the directory at the given path. The
/// three-way split is what `prepare` consumes; collapsing it to `bool`
/// would lose the "marker present but `mail.toml` missing" case, which
/// `prepare` recovers from by re-generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
	/// Generate every artifact: missing dir, empty dir, marker present
	/// but the rest of the layout not yet written.
	Generate,
	/// Reuse everything: marker present AND `mail.toml` already there.
	Reuse,
}

/// Create `path` as a directory with `mode` (no-op when it already exists).
pub(super) fn create_with_mode(path: &Path, mode: u32) -> Result<(), super::LocalError> {
	match std::fs::create_dir(path) {
		Ok(()) => {
			set_mode(path, mode)?;
			Ok(())
		}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
			set_mode(path, mode)?;
			Ok(())
		}
		Err(error) => Err(super::LocalError::Io(error)),
	}
}

/// Set the mode on `path` to `mode` (no-op on non-Unix). The `set_permissions`
/// call here is the same one `Config::load` uses to enforce `0600`, so a
/// file that drifts to `0644` is corrected on every run.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), super::LocalError> {
	use std::os::unix::fs::PermissionsExt;
	let permissions = std::fs::Permissions::from_mode(mode);
	std::fs::set_permissions(path, permissions).map_err(super::LocalError::Io)
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), super::LocalError> {
	Ok(())
}

/// Write the marker file, owner-readable only.
pub(super) fn write_marker(path: &Path) -> Result<(), super::LocalError> {
	write_with_mode(path, b"", 0o600)
}

/// Write `contents` to `path` with `mode`. Created exclusively so a
/// pre-existing file under a name we never reuse cannot be silently
/// overwritten.
pub(super) fn write_with_mode(
	path: &Path,
	contents: &[u8],
	mode: u32,
) -> Result<(), super::LocalError> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create_new(true).mode(mode);
		let mut file = options.open(path).map_err(super::LocalError::Io)?;
		std::io::Write::write_all(&mut file, contents).map_err(super::LocalError::Io)?;
	}
	#[cfg(not(unix))]
	{
		let mut file = std::fs::File::create(path).map_err(super::LocalError::Io)?;
		std::io::Write::write_all(&mut file, contents).map_err(super::LocalError::Io)?;
	}
	Ok(())
}

/// Tighten the mode on `path` if it is currently wider than `mode`.
pub(super) fn enforce_mode(path: &Path, mode: u32) -> Result<(), super::LocalError> {
	set_mode(path, mode)
}

/// Generate a self-signed certificate for the harness hostname and write
/// the PEM pair to `cert_path` and `key_path`. Uses the same `rcgen` call
/// `tls/mod.rs` uses in its test support so the generated material loads
/// through the production code path.
pub(super) fn generate_certificate(
	cert_path: &Path,
	key_path: &Path,
) -> Result<(), super::LocalError> {
	let mut params = CertificateParams::new(vec![super::HOSTNAME.to_string()])
		.map_err(|error| super::LocalError::Certificate(error.to_string()))?;
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String(super::HOSTNAME.to_string()),
	);
	let key_pair = rcgen::KeyPair::generate()
		.map_err(|error| super::LocalError::Certificate(error.to_string()))?;
	let cert = params
		.self_signed(&key_pair)
		.map_err(|error| super::LocalError::Certificate(error.to_string()))?;
	write_with_mode(cert_path, cert.pem().as_bytes(), 0o600)?;
	write_with_mode(key_path, key_pair.serialize_pem().as_bytes(), 0o600)?;
	Ok(())
}

/// Generate a DKIM Ed25519 key through the same code `dkim-keygen` calls.
pub(super) fn write_dkim_key(path: &Path) -> Result<(), super::LocalError> {
	let (pem, _record) = crate::dkim::generate_key()
		.map_err(|error| super::LocalError::DkimKey(error.to_string()))?;
	write_with_mode(path, pem.as_bytes(), 0o600)
}

/// Mint a fresh API bearer token, hash it with argon2id (the same
/// `hash_password` `account-add` uses) and return the PHC string for
/// `[api] token_hash`. The plaintext token is dropped on the floor: only
/// the harness operator gets the password, and the API is loopback-local
/// anyway.
pub(super) fn generate_api_token_hash() -> Result<String, super::LocalError> {
	let secret =
		super::super::util::generate_secret().ok_or(super::LocalError::CsprngUnavailable)?;
	crate::smtp::auth::hash_password(&secret).map_err(super::LocalError::Account)
}

/// Mint a fresh account password from the same generator that produces
/// app-passwords and API keys: 32 random bytes base32-encoded. The result
/// is well over the policy's 12-character minimum and uses only the
/// alphabet `a-z2-7`, all printable ASCII.
pub(super) fn generate_account_password() -> Result<String, super::LocalError> {
	super::super::util::generate_secret().ok_or(super::LocalError::CsprngUnavailable)
}

/// Persist the dynamic account to `<data_dir>/accounts.toml` using the same
/// on-disk format `AccountStore::open` reads, so the second run finds it
/// without a separate path.
pub(super) fn write_account(
	path: &Path,
	account: &crate::directory_store::DynamicAccount,
) -> Result<(), super::LocalError> {
	#[derive(serde::Serialize)]
	struct File<'a> {
		accounts: Vec<&'a crate::directory_store::DynamicAccount>,
	}
	let body = toml::to_string(&File {
		accounts: vec![account],
	})
	.map_err(|error| super::LocalError::Account(error.to_string()))?;
	write_with_mode(path, body.as_bytes(), 0o600)
}
