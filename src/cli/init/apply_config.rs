//! Build the desired `Config` value from the answers and merge it with
//! whatever the operator already has on disk. The types live in a
//! sibling so `apply.rs` keeps under the per-file line limit.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::init::answers::{Answers, Services};
use crate::cli::init::apply::ApplyError;
use crate::config::Config;

/// Build the desired `Config` value from the answers. Each listener
/// line carries its kind and an explicit `addr`; the operator-visible
/// default of `127.0.0.1` is no longer the answer for any listener
/// `init` writes, because loopback-only mail listeners receive no
/// mail and serve nobody.
#[derive(Debug, Serialize)]
pub(super) struct DesiredConfig {
	pub(super) hostname: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) public_ipv4: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) public_ipv6: Option<String>,
	pub(super) data_dir: String,
	pub(super) domains: Vec<String>,
	pub(super) listeners: Vec<DesiredListener>,
	pub(super) dkim: DesiredDkim,
	pub(super) tls: DesiredTls,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) dns: Option<DesiredDns>,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredListener {
	pub(super) kind: String,
	/// Bind address the listener uses. Always written so the schema
	/// default (`127.0.0.1`) cannot silently take over: an init
	/// config that names only `kind` would bind loopback and miss
	/// every packet the network delivers.
	pub(super) addr: IpAddr,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredDkim {
	pub(super) selector: String,
	pub(super) key_file: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) rsa_selector: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) rsa_key_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredTls {
	pub(super) cert_file: String,
	pub(super) key_file: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredDns {
	pub(super) provider: String,
	pub(super) zone: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token_file: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token_env: Option<String>,
}

/// The outcome of trying to merge the desired config with whatever is
/// on disk. `Identical` means the file is already byte-for-byte what we
/// want and stays untouched; `Wrote` means the file did not exist or
/// was rewritten; `Updated` means an existing file was overwritten with
/// a different value.
pub(super) enum ConfigWrite {
	Identical,
	Wrote,
	Updated,
}

/// Construct the desired config tree from the answers and the paths to
/// the keys `apply` generated.
///
/// `mail_addr` is the bind address used by every mail-facing listener
/// (smtp, submission, imap, pop3s, manage-sieve, web-dav). The
/// management API listener is closed to the network by design and
/// binds loopback (`127.0.0.1`) regardless. `mail_addr` is decided
/// once in `plan` so the operator sees the same address on the
/// confirmation prompt that `apply` writes into the config.
pub(super) fn build_config(
	answers: &Answers,
	mail_addr: IpAddr,
	dkim_ed25519: Option<&Path>,
	dkim_rsa: Option<&Path>,
	cert_file: &Path,
	key_file: &Path,
) -> Result<DesiredConfig, ApplyError> {
	let mut listeners = Vec::new();
	let services: Services = answers.services;
	// SMTP (port 25, inbound mail) is always written. It is the
	// listener the rest of the internet talks to, and a fresh install
	// that does not bind it receives no mail. The kind is unconditional
	// even when every other optional service is off, so the operator
	// never has to add it back by hand.
	listeners.push(DesiredListener {
		kind: "smtp".to_string(),
		addr: mail_addr,
	});
	if services.imap {
		listeners.push(DesiredListener {
			kind: "imap".to_string(),
			addr: mail_addr,
		});
	}
	if services.submission {
		listeners.push(DesiredListener {
			kind: "submission".to_string(),
			addr: mail_addr,
		});
	}
	if services.pop3 {
		listeners.push(DesiredListener {
			kind: "pop3s".to_string(),
			addr: mail_addr,
		});
	}
	if services.managesieve {
		listeners.push(DesiredListener {
			kind: "manage-sieve".to_string(),
			addr: mail_addr,
		});
	}
	if services.webdav {
		listeners.push(DesiredListener {
			kind: "web-dav".to_string(),
			addr: mail_addr,
		});
	}
	if services.api {
		listeners.push(DesiredListener {
			kind: "api".to_string(),
			addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
		});
	}

	let dkim = match (dkim_ed25519, dkim_rsa) {
		(Some(ed), Some(rsa)) => DesiredDkim {
			selector: "s1".to_string(),
			key_file: ed.display().to_string(),
			rsa_selector: Some("s2".to_string()),
			rsa_key_file: Some(rsa.display().to_string()),
		},
		// When the RSA key is absent (no `openssl` on `PATH`, or key
		// generation failed), omit both RSA fields entirely so the
		// server configuration does not name an RSA selector pointing
		// at Ed25519 material. The single-signature warning from
		// `#[allow(dead_code)]` / issue #911 already explains what is
		// missing to the operator.
		(Some(ed), None) => DesiredDkim {
			selector: "s1".to_string(),
			key_file: ed.display().to_string(),
			rsa_selector: None,
			rsa_key_file: None,
		},
		// The (None, _) arm would have refused to write a config without
		// an ed25519 key, but `apply` always supplies Some and `plan`
		// only calls `build_config` with `Some(dkim_ed25519)`. The arm
		// is unreachable from any caller, so the refusal message is
		// documented in the test that exercises the function directly.
		(None, _) => unreachable!("apply always supplies a dkim ed25519 path"),
	};

	let dns = answers.dns.as_ref().map(|d| DesiredDns {
		provider: d.provider.clone(),
		zone: d.zone.clone(),
		token: d.token.clone(),
		token_file: d.token_file.as_ref().map(|p| p.display().to_string()),
		token_env: d.token_env.clone(),
	});

	Ok(DesiredConfig {
		hostname: answers.hostname.clone(),
		public_ipv4: answers.public_ipv4.map(|a| a.to_string()),
		public_ipv6: answers.public_ipv6.map(|a| a.to_string()),
		data_dir: answers.data_dir.display().to_string(),
		domains: answers.domains.clone(),
		listeners,
		dkim,
		tls: DesiredTls {
			cert_file: cert_file.display().to_string(),
			key_file: key_file.display().to_string(),
		},
		dns,
	})
}

/// Top-level keys `init` writes into the desired config. The merge
/// removes these from the existing config when the desired config does
/// not include them, so omitting `services.api = true`, `public_ipv4`,
/// the `[dns]` section, or every listener actually clears the entry
/// from the file instead of leaving it preserved as an "operator
/// setting" the operator never asked for.
const INIT_MANAGED_KEYS: &[&str] = &[
	"hostname",
	"public_ipv4",
	"public_ipv6",
	"data_dir",
	"domains",
	"listeners",
	"dkim",
	"tls",
	"dns",
];

/// Merge the desired config with the file on disk. Three outcomes:
/// - no file on disk: write the desired one (Wrote);
/// - file on disk with the same `toml::Value` shape and content: skip
///   (Identical), but only when the on-disk file also passes
///   `Config::load`. An operator-edited file that the rest of the
///   CLI (`config-check`, `serve`) would reject must not be
///   reported as identical: `init` would leave a non-starting
///   configuration behind a green run;
/// - file on disk with the same shape but different values: rewrite
///   (Updated), with unknown top-level keys preserved.
///
/// When `keep_existing_listeners` is `true`, the existing `listeners`
/// array on disk is preserved verbatim and the desired `listeners`
/// array is dropped: the operator already put a `metrics` listener,
/// or pinned `imap` to a sidecar port, and `init` does not silently
/// overwrite their work. The desired config still carries every
/// other managed key.
///
/// Comments are not preserved: the merge goes through `toml::Value` and
/// the resulting document is re-serialised. The plan step mentions this
/// so the operator knows what to expect.
pub(super) fn merge_with_existing(
	path: &Path,
	desired: &str,
	keep_existing_listeners: bool,
) -> Result<ConfigWrite, ApplyError> {
	let desired_value: toml::Value =
		toml::from_str(desired).map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	match fs::read_to_string(path) {
		Ok(existing) => {
			let existing_value: toml::Value = parsed(&existing).map_err(|e| {
				ApplyError::ConfigRead(path.to_path_buf(), std::io::Error::other(e.to_string()))
			})?;
			let merged = reconcile(existing_value, desired_value, keep_existing_listeners);
			if merged == parsed(&existing)? {
				if let Err(error) = Config::load(path) {
					return Err(ApplyError::ConfigInvalid(format!(
						"existing config at {} would be left untouched but is invalid: {}",
						path.display(),
						error
					)));
				}
				Ok(ConfigWrite::Identical)
			} else {
				let serialized = toml::to_string(&merged)
					.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
				write_validated_config(path, &serialized)?;
				Ok(ConfigWrite::Updated)
			}
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			write_validated_config(path, desired)?;
			Ok(ConfigWrite::Wrote)
		}
		Err(error) => Err(ApplyError::ConfigRead(path.to_path_buf(), error)),
	}
}

/// Reconcile a desired TOML value with an existing one. Every key
/// listed in `INIT_MANAGED_KEYS` is removed from the root table of
/// the existing value (so the desired config can drop a previously
/// managed entry that the operator no longer wants) and replaced
/// from the desired value when present there. Keys not in that list
/// are preserved as the operator added them. The removal applies
/// at the root only: a nested operator table that happens to carry
/// a key whose name matches a managed key is preserved verbatim,
/// because `init` does not own the contents of nested tables.
///
/// When `keep_existing_listeners` is `true`, the `listeners` key is
/// skipped on both sides: the existing array survives untouched and
/// the desired one is dropped. The flag is set only when the
/// existing config already carries a non-empty `listeners` array on
/// disk.
///
/// Tables are reconciled recursively for keys the operator and
/// `init` both write; arrays are replaced wholesale because listeners
/// and the dns section are managed as a whole by `init`.
pub(crate) fn reconcile(
	existing: toml::Value,
	desired: toml::Value,
	keep_existing_listeners: bool,
) -> toml::Value {
	use toml::Value;
	match (existing, desired) {
		(Value::Table(mut existing_table), Value::Table(desired_table)) => {
			for key in INIT_MANAGED_KEYS {
				if *key == "listeners" && keep_existing_listeners {
					continue;
				}
				existing_table.remove(*key);
			}
			for (key, value) in desired_table {
				if key == "listeners" && keep_existing_listeners {
					continue;
				}
				let new = match existing_table.remove(&key) {
					Some(existing_inner) => reconcile_inner(existing_inner, value),
					None => value,
				};
				existing_table.insert(key, new);
			}
			Value::Table(existing_table)
		}
		(_, desired) => desired,
	}
}

/// Recurse into a nested table without applying the managed-key
/// removal. The root table is the only place `init` owns keys by
/// name, so a nested operator table keeps every key it had.
fn reconcile_inner(existing: toml::Value, desired: toml::Value) -> toml::Value {
	use toml::Value;
	match (existing, desired) {
		(Value::Table(mut existing_table), Value::Table(desired_table)) => {
			for (key, value) in desired_table {
				let new = match existing_table.remove(&key) {
					Some(existing_inner) => reconcile_inner(existing_inner, value),
					None => value,
				};
				existing_table.insert(key, new);
			}
			Value::Table(existing_table)
		}
		(_, desired) => desired,
	}
}

fn parsed(text: &str) -> Result<toml::Value, ApplyError> {
	toml::from_str(text).map_err(|error| ApplyError::ConfigEncode(error.to_string()))
}

/// Read the config at `path` and return every listener the operator
/// already has on disk, when the file exists and the `listeners`
/// array is non-empty. `Ok(None)` covers four cases the caller
/// treats the same: no file on disk, an I/O failure reading it
/// (e.g. the parent is a regular file rather than a directory; the
/// apply phase surfaces those with its own error), the file exists
/// but has no `listeners` key, and the `listeners` array is present
/// but empty. In all four cases `init` writes its own array.
///
/// `Ok(Some(_))` carries one `Listener` per existing entry, with the
/// listener's kind, the explicit bind address the operator wrote (or
/// the schema default when omitted), and the explicit port (or the
/// schema default for the kind). The plan uses these to render what
/// `serve` will actually expose; the apply phase uses the same
/// signal to decide whether the merge preserves the `listeners`
/// array verbatim or replaces it with its own.
///
/// A file the rest of the CLI would reject (the `Config::load` path
/// the plan mirrors) surfaces as a hard error here so the apply
/// phase cannot "succeed" against a config `serve` would refuse to
/// start with.
pub(crate) fn existing_operators_listeners(
	path: &Path,
) -> Result<Option<Vec<crate::config::Listener>>, ApplyError> {
	let text = match fs::read_to_string(path) {
		Ok(text) => text,
		// An unreadable file is a precondition the apply phase will
		// surface with its own error variant; the plan here only
		// decides what listeners to render, and "no existing
		// listeners" is the safe choice when the disk cannot be read.
		// The apply phase re-reads the file and reports the failure
		// with its own error message.
		Err(_) => return Ok(None),
	};
	let value: toml::Value = match toml::from_str(&text) {
		Ok(value) => value,
		Err(_) => return Ok(None),
	};
	let Some(arr) = value.get("listeners").and_then(|v| v.as_array()) else {
		return Ok(None);
	};
	if arr.is_empty() {
		return Ok(None);
	}
	let mut out = Vec::with_capacity(arr.len());
	for entry in arr {
		let listener: crate::config::Listener = entry.clone().try_into().map_err(|error| {
			ApplyError::ConfigInvalid(format!(
				"existing listener in {} does not parse: {error}",
				path.display()
			))
		})?;
		out.push(listener);
	}
	if let Err(error) = Config::load(path) {
		return Err(ApplyError::ConfigInvalid(format!(
			"existing config at {} has listeners but does not load: {error}",
			path.display()
		)));
	}
	Ok(Some(out))
}

/// Write `bytes` to `path` after staging them on a sibling file with
/// a random suffix, validating the candidate through `Config::load`,
/// and atomically renaming onto `path`. The staging filename cannot
/// collide with `config_path` (it always carries a random hex suffix)
/// and the staging file is created with `O_EXCL` at mode `0600` from
/// the very first byte, so it never has a wider-mode lifetime. The
/// destination is never touched when the candidate does not validate.
/// A `config_path` that resolves through a symlink is refused with an
/// actionable message; symlinks can be silently replaced in ways the
/// operator does not see, so the run stops before any effect rather
/// than guessing what the operator wanted.
pub(super) fn write_validated_config(path: &Path, bytes: &str) -> Result<(), ApplyError> {
	#[cfg(unix)]
	{
		match fs::symlink_metadata(path) {
			Ok(meta) if meta.file_type().is_symlink() => {
				return Err(ApplyError::ConfigSymlink(path.to_path_buf()));
			}
			Ok(_) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(ApplyError::ConfigRead(path.to_path_buf(), error)),
		}
	}
	let parent = path.parent().ok_or_else(|| {
		ApplyError::ConfigInvalid(format!(
			"config_path {} has no parent directory",
			path.display()
		))
	})?;
	let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
		ApplyError::ConfigInvalid(format!(
			"config_path {} has no usable file name",
			path.display()
		))
	})?;
	let (created, staging) = create_unique_staging(parent, file_name, bytes)?;
	match Config::load(&staging) {
		Ok(_) => {}
		Err(error) => {
			if created {
				let _ = fs::remove_file(&staging);
			}
			return Err(ApplyError::ConfigInvalid(error.to_string()));
		}
	}
	if let Err(error) = fs::rename(&staging, path) {
		if created {
			let _ = fs::remove_file(&staging);
		}
		return Err(ApplyError::ConfigWrite(path.to_path_buf(), error));
	}
	Ok(())
}

/// Create a unique staging file under `parent` derived from
/// `file_name` plus a random hex suffix. The file is opened with
/// `O_EXCL` at mode `0600` from the start: a pre-existing file at
/// the chosen name fails creation, so the operator can never lose a
/// sibling at a deterministic staging basename. Returns whether
/// this call created the file (so the caller knows it is safe to
/// clean up on a later error).
fn create_unique_staging(
	parent: &Path,
	file_name: &str,
	bytes: &str,
) -> Result<(bool, PathBuf), ApplyError> {
	create_unique_staging_with(
		parent,
		file_name,
		bytes,
		&mut random_hex_suffix,
		write_and_sync,
	)
}

/// Same as `create_unique_staging` but the suffix source and the
/// byte-write step are injected so the test can drive a controlled
/// collision sequence and a forced write failure. Production code
/// uses `create_unique_staging` and gets the real CSPRNG and the
/// `write_all` + `sync_all` step.
pub(super) fn create_unique_staging_with(
	parent: &Path,
	file_name: &str,
	bytes: &str,
	next_suffix: &mut dyn FnMut() -> String,
	write: fn(&mut fs::File, &[u8]) -> std::io::Result<()>,
) -> Result<(bool, PathBuf), ApplyError> {
	let mut opts = fs::OpenOptions::new();
	opts.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	// The random suffix must be drawn inside the loop: the previous
	// shape held the suffix constant across all sixteen attempts and
	// the `AlreadyExists` arm could never fire on a different
	// candidate, so the retry loop was inert and a pre-existing
	// sibling at the first candidate name stopped the call.
	for _attempt in 0..16u32 {
		let suffix = next_suffix();
		let staging = parent.join(format!("{file_name}.config.tmp.{suffix}"));
		match opts.open(&staging) {
			Ok(mut file) => {
				// A guard that unlinks the staging file on every
				// error path: a write_all or sync_all failure must
				// not leave the partial file behind, because the
				// file can hold an inline DNS token and the next
				// run would block on its `O_EXCL` blocker. The
				// guard is disarmed just before the success return
				// so the caller's rename can move the staging
				// file onto the destination.
				let guard = StagingGuard {
					path: staging.clone(),
					armed: true,
				};
				if let Err(error) = write(&mut file, bytes.as_bytes()) {
					return Err(ApplyError::ConfigWrite(staging, error));
				}
				guard.disarm();
				return Ok((true, staging));
			}
			Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
			Err(error) => return Err(ApplyError::ConfigWrite(staging, error)),
		}
	}
	Err(ApplyError::ConfigWrite(
		parent.join(format!("{file_name}.config.tmp")),
		std::io::Error::other("could not allocate a unique staging filename after 16 attempts"),
	))
}

fn write_and_sync(file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()> {
	use std::io::Write;
	file.write_all(bytes)?;
	file.sync_all()
}

/// RAII handle that removes the staging file on drop unless
/// `disarm` is called. The `O_EXCL` create and the early write_all
/// errors return paths the caller wants surfaced; if any of those
/// arms fires before the rename, the partial file is unlinked
/// instead of left behind as a `0600` token in the operator's
/// directory.
struct StagingGuard {
	path: PathBuf,
	armed: bool,
}

impl StagingGuard {
	fn disarm(mut self) {
		self.armed = false;
	}
}

impl Drop for StagingGuard {
	fn drop(&mut self) {
		if self.armed {
			let _ = fs::remove_file(&self.path);
		}
	}
}

/// Twelve hex digits drawn from the system CSPRNG. The CSPRNG cannot
/// fail on a well-formed host, but `init` only ever needs a unique
/// suffix; if it ever did, the fallback returns the constant
/// `424242424242` on every call, so the retry loop never finds a
/// free candidate and surfaces an `ApplyError::ConfigWrite` after
/// sixteen attempts.
fn random_hex_suffix() -> String {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 6];
	if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
		bytes = [0x42; 6];
	}
	let mut out = String::with_capacity(12);
	for byte in bytes {
		out.push_str(&format!("{byte:02x}"));
	}
	out
}
