//! Directory preparation: marker file, file modes, and the artifacts
//! written into a freshly-laid-out local directory.

use std::path::Path;

use rcgen::CertificateParams;

/// Confirm `dir` exists and is either empty or already marked as ours.
/// Creates the directory with mode `0700` if it does not exist; if it
/// does and holds entries that are not our marker, refuses with
/// [`super::LocalError::NotEmpty`].
pub(super) fn ensure_dir(dir: &Path) -> Result<(), super::LocalError> {
	let metadata = match std::fs::metadata(dir) {
		Ok(metadata) => metadata,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			create_with_mode(dir, 0o700)?;
			return Ok(());
		}
		Err(error) => return Err(super::LocalError::Io(error)),
	};
	if !metadata.is_dir() {
		return Err(super::LocalError::Io(std::io::Error::new(
			std::io::ErrorKind::AlreadyExists,
			format!("{} is not a directory", dir.display()),
		)));
	}
	if !dir.join(super::MARKER_FILE).exists() {
		let has_content = std::fs::read_dir(dir)
			.map_err(super::LocalError::Io)?
			.next()
			.is_some();
		if has_content {
			return Err(super::LocalError::NotEmpty(dir.to_path_buf()));
		}
	}
	Ok(())
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

/// Write the marker file, owner-readable only. Idempotent: a marker that
/// is already on disk is left alone. `prepare` calls this on every run
/// (it is the trust anchor), and the second run must not fail just
/// because the first one already left the file behind.
pub(super) fn write_marker(path: &Path) -> Result<(), super::LocalError> {
	if path.exists() {
		return Ok(());
	}
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

/// Write `contents` to `path` with `mode`, replacing any existing file.
/// The caller has already decided overwriting is safe (typically because
/// the file is the credential pair `mail.toml` + `accounts.toml` and at
/// least one half is missing, so the only consistent state is to mint a
/// fresh password and rewrite both files together). The mode is set on
/// the new file; a file that existed before is replaced, not appended
/// to.
///
/// Two guarantees the credential files need that the obvious
/// `open(O_TRUNC) → write_all → chmod` shape does not give:
///
/// - The file must never be world-readable, even for an instant. The
///   naive shape opens with the default mode (0644 under a normal
///   umask), writes, and only then narrows to 0600; an interrupted run
///   leaves the wider mode on disk. We open the temporary with
///   `OpenOptionsExt::mode(mode)` so the new file is 0600 from the
///   first byte.
/// - An interrupted run must not leave a truncated `mail.toml` on
///   disk that the runtime then tries to load. We write to a sibling
///   temporary file and `rename(2)` over the target; the rename is
///   atomic on POSIX, so the operator either sees the old file or the
///   new file, never a half-written one. The temporary is unlinked by
///   the rename itself; no cleanup is needed.
///
/// The trailing `set_mode` is kept so a target that pre-existed with a
/// wider mode (e.g. an older `epistle local` that wrote 0644, or a
/// hand-edited 0644 file) is narrowed on the next replace. With the
/// fix above the target inherits the temporary's 0600 on rename, so
/// the call is a defensive no-op on every fresh write and only fires
/// on a directory that already drifted.
pub(super) fn write_with_replace(
	path: &Path,
	contents: &[u8],
	mode: u32,
) -> Result<(), super::LocalError> {
	let parent = path.parent().ok_or_else(|| {
		super::LocalError::Io(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			format!("{} has no parent directory", path.display()),
		))
	})?;
	let temp_path = sibling_temp_path(parent, path)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		let mut options = std::fs::OpenOptions::new();
		// `create_new(true)` so a stale temporary left over from a
		// previous crash (the rename never happened, the process died
		// in between) cannot be silently reused and clobber the new
		// contents. `sibling_temp_path` already picked a name, so the
		// race-free behaviour is what `create_new` gives us.
		options.write(true).create_new(true).mode(mode);
		let mut file = options.open(&temp_path).map_err(super::LocalError::Io)?;
		std::io::Write::write_all(&mut file, contents).map_err(super::LocalError::Io)?;
	}
	#[cfg(not(unix))]
	{
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&temp_path)
			.map_err(super::LocalError::Io)?;
		std::io::Write::write_all(&mut file, contents).map_err(super::LocalError::Io)?;
	}
	std::fs::rename(&temp_path, path).map_err(super::LocalError::Io)?;
	set_mode(path, mode)?;
	Ok(())
}

/// Pick a sibling temporary file path inside `parent` for an atomic
/// replace of `target`. The name is `.<target>.<pid>-<n>.tmp`, which
/// keeps it distinct from the real file so a stale temp from an earlier
/// crash does not collide and the runtime can spot it (the leading dot
/// hides it from directory listings by convention). The counter is
/// process-local; `pid` keeps two concurrent processes on the same
/// directory from clashing.
fn sibling_temp_path(parent: &Path, target: &Path) -> std::io::Result<std::path::PathBuf> {
	use std::sync::atomic::{AtomicU64, Ordering};
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	let file_name = target.file_name().ok_or_else(|| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			format!("{} has no file name", target.display()),
		)
	})?;
	let pid = std::process::id();
	let n = COUNTER.fetch_add(1, Ordering::Relaxed);
	Ok(parent.join(format!(".{}-{pid}-{n}.tmp", file_name.to_string_lossy())))
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

/// Persist the dynamic account to `<data_dir>/accounts.toml`, replacing
/// any existing file. The credential-pair recovery in `prepare` calls
/// this when `accounts.toml` is missing alongside a valid `mail.toml`,
/// so the file must be replaceable rather than exclusive.
pub(super) fn write_account_replace(
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
	write_with_replace(path, body.as_bytes(), 0o600)
}
