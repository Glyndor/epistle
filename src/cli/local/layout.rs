//! Directory preparation: marker file, file modes, and the artifacts
//! written into a freshly-laid-out local directory.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

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
/// `open(O_TRUNC) write_all chmod` shape does not give:
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
/// `create_new(true)` plus the bounded retry below guard against the
/// race where a previous crash left a sibling temp on disk under the
/// exact name this run drew. The counter advances on every attempt,
/// so the retry hits the next slot; after ten collisions the original
/// error is forwarded so the operator sees the real reason the rename
/// never happened.
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
	const MAX_RETRIES: usize = 10;
	let mut original_exists: Option<std::io::Error> = None;
	for _ in 0..=MAX_RETRIES {
		match open_replace_temp(parent, path, mode) {
			Ok((mut file, temp_path)) => {
				if let Err(error) = std::io::Write::write_all(&mut file, contents) {
					// The temp is open with `create_new`; remove it so
					// the next run does not have to retry past a slot
					// we already touched on a partial write.
					let _ = std::fs::remove_file(&temp_path);
					return Err(super::LocalError::Io(error));
				}
				drop(file);
				std::fs::rename(&temp_path, path).map_err(super::LocalError::Io)?;
				set_mode(path, mode)?;
				return Ok(());
			}
			Err(super::LocalError::Io(error))
				if error.kind() == std::io::ErrorKind::AlreadyExists =>
			{
				if original_exists.is_none() {
					original_exists = Some(error);
				}
				continue;
			}
			Err(other) => return Err(other),
		}
	}
	Err(super::LocalError::Io(
		original_exists.expect("retry loop forwarded no AlreadyExists error"),
	))
}

/// Process-local counter that names every sibling-temp file. Lifted
/// out of `sibling_temp_path` so the stale-temp test can peek what
/// name the first attempt will draw without consuming a slot itself.
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_counter() -> u64 {
	COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn compute_sibling_temp_path(parent: &Path, target: &Path, n: u64) -> std::path::PathBuf {
	let file_name = target.file_name().expect("target has no file name");
	let pid = std::process::id();
	parent.join(format!(".{}-{pid}-{n}.tmp", file_name.to_string_lossy()))
}

/// Pick a sibling temporary file path inside `parent` for an atomic
/// replace of `target`. The name is `.<target>-<pid>-<n>.tmp`, which
/// keeps it distinct from the real file so a stale temp from an earlier
/// crash does not collide and the runtime can spot it (the leading dot
/// hides it from directory listings by convention). The counter is
/// process-local; `pid` keeps two concurrent processes on the same
/// directory from clashing.
fn sibling_temp_path(parent: &Path, target: &Path) -> std::path::PathBuf {
	compute_sibling_temp_path(parent, target, next_counter())
}

/// Return the path the next call to `sibling_temp_path` would pick,
/// without consuming a slot. Used by the stale-temp test to seed a
/// collision on the first attempt.
#[cfg(test)]
pub(super) fn peek_sibling_temp_path(parent: &Path, target: &Path) -> std::path::PathBuf {
	let n = COUNTER.load(Ordering::Relaxed);
	compute_sibling_temp_path(parent, target, n)
}

/// Open the sibling temporary for an atomic replace of `target` under
/// `parent`, returning the open file together with its path so a test
/// can stat the file before the rename. The temp is created with
/// `mode` from the very first byte (`OpenOptionsExt::mode` on Unix),
/// not narrowed afterwards; `create_new(true)` makes the open fail
/// with `AlreadyExists` if a previous run left a stale temp behind,
/// which the retry loop in `write_with_replace` handles.
pub(super) fn open_replace_temp(
	parent: &Path,
	target: &Path,
	mode: u32,
) -> Result<(std::fs::File, std::path::PathBuf), super::LocalError> {
	let temp_path = sibling_temp_path(parent, target);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create_new(true).mode(mode);
		let file = options.open(&temp_path).map_err(super::LocalError::Io)?;
		Ok((file, temp_path))
	}
	#[cfg(not(unix))]
	{
		let file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&temp_path)
			.map_err(super::LocalError::Io)?;
		Ok((file, temp_path))
	}
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
