//! The `compose.yaml` that `podup` brings up. JSON, not YAML: the
//! repository has no YAML crate and YAML 1.2 is a superset of JSON.
//! The order of fields in the rendered file is the order the
//! operator sees; the `serde_json` writer walks the `serde::Serialize`
//! implementation below in declaration order, so the field order
//! in this file is also the order in the rendered JSON.
//!
//! Conventions measured on podup 5.10.11 to 5.10.12:
//! - `mode` for a secret spec must be a JSON number whose value is
//!   the octal mode (`0o400` is `256`). The string `"0400"` would
//!   be read as the decimal number `400`; the string `"0256"` and
//!   the number `256` both resolve to the same octal mode.
//! - `$(...)` inside a healthcheck `CMD-SHELL` is NOT interpolated by
//!   podup. `$$` is not required; the shell runs the literal
//!   `$(...)`.
//! - The `mail` service binds `network_mode: "pasta"` so the SMTP
//!   listeners keep the real client address; rootless podman would
//!   otherwise funnel every connection through `rootlessport` and
//!   the server would see one internal IP for every client.
//! - The `db` service binds `network_mode: "none"`. It talks to
//!   `mail` over a Unix-domain socket on a named volume.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::answers::Answers;
use super::apply::{ApplyError, Report, ReportStep, listeners_to_write};
use crate::config::Listener;

/// The digest-pinned `postgres:18` image. The CI workflow
/// `.github/workflows/db.yml` carries the same digest; if either
/// side moves, the other has to follow.
pub(super) const POSTGRES_18_IMAGE: &str = "docker.io/library/postgres:18@sha256:06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941";

/// The mode of the database secret. podup reads a JSON number as
/// the octal mode, so the byte written here must be the decimal
/// value whose octal representation is the desired mode. `0o400`
/// reads as decimal `400` (not `256`); the rendered file carries
/// the number `400` and podup applies `0o400` (owner read-only).
/// Verified with `podup -f compose.yaml config` on 2026-10-04:
/// `mode: 400` -> rendered `mode: 256`. The decimal `256` would
/// be read as `0o256`, which has the owner-execute bit set and
/// triggers a `mode 0o256 sets an execute bit on a secret`
/// refusal at `podup up` time.
const DATABASE_SECRET_MODE: u32 = 400;

/// The default image for the `mail` service when the operator did
/// not set `image` in the answers file. The tag is the
/// `<MAJOR.MINOR>` prefix of `CARGO_PKG_VERSION`, never `latest`
/// and never the full `X.Y.Z` patch: a release of `0.9.0` pins
/// the image to `ghcr.io/glyndor/epistle:0.9` so a 0.9.1 patch
/// keeps reusing the same base image until the operator
/// re-tags. Patch releases that need a new image should ship
/// a new tag (a manual `0.9.X` build), not rely on this
/// default.
pub(super) fn default_image() -> String {
	let version = env!("CARGO_PKG_VERSION");
	let mut parts = version.split('.');
	let major = parts.next().unwrap_or("0");
	let minor = parts.next().unwrap_or("0");
	format!("ghcr.io/glyndor/epistle:{}.{}", major, minor)
}

/// Resolve the image for the `mail` service. The answers file
/// Resolve the image for the `mail` service. The answers file
/// wins when the operator set `image`; otherwise the
/// build-time default from [`default_image`] applies.
pub(super) fn resolve_image(image: Option<&str>) -> String {
	image.map(str::to_string).unwrap_or_else(default_image)
}

/// The directory `init` keeps the database password in, under
/// `<data_dir>/secrets`. The compose file references it by the
/// absolute path on the host, which is also the path inside the
/// `mail` container (the data directory is bind-mounted at the
/// same path on both sides).
pub(super) fn compose_secrets_dir(data_dir: &Path) -> PathBuf {
	data_dir.join("secrets")
}

/// The path the database password lives at.
pub(super) fn db_password_path(data_dir: &Path) -> PathBuf {
	compose_secrets_dir(data_dir).join("epistle_db_password")
}

/// The path the compose file lives at.
pub(super) fn compose_file_path(data_dir: &Path) -> PathBuf {
	data_dir.join("compose").join("compose.yaml")
}

/// A README the operator reads after the run. Three short lines:
/// how to start the stack with podup, that `init` regenerates this
/// file, and that stable changes belong in the answers file.
const COMPOSE_README: &str = "Bring up the stack with `podup -f compose.yaml up -d`. \
init regenerates this file from the answers; stable changes belong in the answers file.\n";

/// Mint a fresh 32-character alphanumeric password from the system
/// CSPRNG. The alphabet excludes look-alikes (no `0`/`O`/`1`/`l`)
/// so a value copied off the operator's screen is read back
/// correctly. Returns `None` when the CSPRNG cannot produce bytes;
/// the apply phase surfaces that as `ApplyError::Rng` and the run
/// exits 1 with the report of what already landed.
pub(super) fn generate_db_password() -> Option<String> {
	use ring::rand::SecureRandom;
	const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
	let mut bytes = [0u8; 32];
	ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
	let mut out = String::with_capacity(32);
	for byte in bytes {
		// The bias from a 256-byte modular reduction against a
		// 32-character alphabet is small enough to ignore: every
		// character has at least 6 candidates (256 / 32 = 8) and
		// the worst case is 8 vs 9, well within a CSPRNG's noise
		// floor.
		out.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
	}
	Some(out)
}

/// Lay down `<data_dir>/secrets/epistle_db_password` and the
/// `<data_dir>/secrets` directory. Called only when
/// `services.database` is `true`.
///
/// The file is reused byte-for-byte when it already exists and
/// is a regular file with non-empty content AND it can actually
/// be read. Rotating it would lock epistle out of the existing
/// database: PostgreSQL keeps the old credential in its volume
/// and a new password would never be honoured.
///
/// Only a path that does not exist at all (the result of
/// `symlink_metadata` is `NotFound`) is regenerated. Every
/// other entry at the path is a present-but-unusable shape the
/// operator put there on purpose (or by accident) and the apply
/// phase refuses rather than silently rewriting it:
/// - a regular file with empty content (a leftover zero-length
///   file from an earlier half-written run);
/// - a symlink (broken or not) at the path (a symlink target
///   could be a file the operator points at from a backup, and
///   replacing the symlink with a fresh file would lose the
///   link without warning);
/// - a directory, fifo, device, or socket in place of the file
///   (`fs::read` returns `Is a directory`, a fifo would block
///   on the read, a device node would expose the wrong API);
/// - a non-empty file that cannot be read (`mode 0o000`, an
///   unreadable mount, an EIO error, ...).
///
/// Each refusal surfaces as
/// [`ApplyError::ExistingSecretUnreadable`] and names the path
/// the operator must repair by hand. The Postgres entrypoint
/// still has the old credential in its volume; minting a fresh
/// password would lock the database out from under the operator.
///
/// Returns the password path; the bytes themselves are not
/// surfaced to the apply phase.
pub(super) fn ensure_db_password(
	data_dir: &Path,
	report: &mut Report,
) -> Result<PathBuf, ApplyError> {
	let dir = compose_secrets_dir(data_dir);
	fs::create_dir_all(&dir).map_err(|error| ApplyError::KeyWrite(dir.clone(), error))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
			.map_err(|error| ApplyError::KeyWrite(dir.clone(), error))?;
	}
	let path = db_password_path(data_dir);
	match fs::symlink_metadata(&path) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			// The path is absent (the common case on a fresh
			// install, and the documented recovery path: the
			// operator deleted the file by hand to force a
			// fresh password). Mint one and write it.
			write_fresh_password(&path, report)
		}
		Err(error) => {
			// A `symlink_metadata` failure other than
			// `NotFound` is a precondition the apply phase
			// surfaces with its own diagnostic: an
			// unreadable parent, a permissions refusal on
			// the secrets directory, ...
			Err(ApplyError::ExistingSecretUnreadable(path, error))
		}
		Ok(metadata) => {
			// The path resolves to something. Only a regular
			// file with non-empty content is reusable; every
			// other shape is refused so the operator sees the
			// refusal rather than a silent rewrite.
			let file_type = metadata.file_type();
			if file_type.is_symlink() {
				return Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other(
						"path is a symlink; remove it (or replace it with the file it pointed at) and rerun init",
					),
				));
			}
			if !file_type.is_file() {
				return Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other("path is not a regular file; remove it and rerun init"),
				));
			}
			match fs::read(&path) {
				Ok(existing) if !existing.is_empty() => {
					// The file is a regular file with
					// non-empty content: PostgreSQL has
					// the matching password in its volume
					// and rotating it would lock
					// epistle out.
					report.steps.push(ReportStep::Reused(path.clone()));
					Ok(path)
				}
				Ok(_) => Err(ApplyError::ExistingSecretUnreadable(
					path,
					std::io::Error::other(
						"file is empty; remove it and rerun init to mint a fresh password",
					),
				)),
				Err(error) => Err(ApplyError::ExistingSecretUnreadable(path, error)),
			}
		}
	}
}

/// Mint a fresh database password and write it under
/// `write_secret` so a crash mid-write cannot leave a
/// half-written secret in place. Returns the password path on
/// success; the bytes themselves are not surfaced.
fn write_fresh_password(path: &Path, report: &mut Report) -> Result<PathBuf, ApplyError> {
	let password =
		generate_db_password().ok_or_else(|| ApplyError::Rng("database password".to_string()))?;
	crate::storage::write_secret(path, password.as_bytes())
		.map_err(|error| ApplyError::KeyWrite(path.to_path_buf(), error))?;
	report.steps.push(ReportStep::Wrote(path.to_path_buf()));
	Ok(path.to_path_buf())
}

/// Test whether the database-password file the apply phase
/// would reuse is a regular file with non-empty content. The
/// plan uses this to mark the `DbPassword` step `reused: true`
/// only when the apply phase will actually reuse. A symlink
/// at the path, a directory, an empty file, or any other
/// present-but-unusable shape returns `false` here so the plan
/// says `generate` and the apply phase then refuses the entry
/// with [`ApplyError::ExistingSecretUnreadable`] before any
/// effect.
pub(super) fn db_password_reused(data_dir: &Path) -> bool {
	let path = db_password_path(data_dir);
	let Ok(metadata) = fs::symlink_metadata(&path) else {
		return false;
	};
	if !metadata.file_type().is_file() {
		return false;
	}
	matches!(fs::read(&path), Ok(bytes) if !bytes.is_empty())
}

/// Compose-file step in the apply phase. The caller already
/// passed the answers file through `ensure_db_password`; this
/// derives the published ports from the listeners init will
/// write into the config (after the keep-existing-listeners
/// merge) and writes the compose file plus the README.
pub(super) fn write_compose_step(answers: &Answers, report: &mut Report) -> Result<(), ApplyError> {
	ensure_compose_file(answers, answers.services.database, report)?;
	Ok(())
}

/// Lay down `<data_dir>/compose/compose.yaml` and a short README
/// next to it. The compose file is regenerated when its bytes do
/// not match; identical means untouched. The `database` flag
/// switches the `db` service and the secrets/volumes blocks in
/// or out. The published-port list is derived from the listeners
/// init writes into the config (see [`published_ports_for_listeners`])
/// so a published port always matches a listener that is actually
/// bound.
pub(super) fn ensure_compose_file(
	answers: &Answers,
	database: bool,
	report: &mut Report,
) -> Result<PathBuf, ApplyError> {
	let dir = answers.data_dir.join("compose");
	fs::create_dir_all(&dir).map_err(|error| ApplyError::ConfigDir(dir.clone(), error))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
			.map_err(|error| ApplyError::ConfigDir(dir.clone(), error))?;
	}
	let path = compose_file_path(&answers.data_dir);
	let listeners = listeners_to_write(answers)?;
	let published_ports = published_ports_for_listeners(&listeners);
	let composed = ComposeFile::build(answers, published_ports, database);
	// `serde_json::to_string_pretty` is the stable pretty-printer
	// the tests pin on: the rendered file carries a trailing
	// newline, two-space indentation, and the field order of the
	// struct definition above.
	let mut bytes = serde_json::to_string_pretty(&composed)
		.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	bytes.push('\n');
	match fs::read(&path) {
		Ok(existing) if existing == bytes.as_bytes() => {
			report.steps.push(ReportStep::ConfigIdentical(path.clone()));
		}
		_ => {
			crate::storage::write_secret(&path, bytes.as_bytes())
				.map_err(|error| ApplyError::ConfigWrite(path.clone(), error))?;
			report.steps.push(ReportStep::Wrote(path.clone()));
		}
	}
	write_readme(&dir, report)?;
	Ok(path)
}

/// Render the desired compose file without writing it. Used by the
/// plan phase to decide whether the file is already up to date
/// (the operator sees `identical, not touched` instead of
/// `update`). The exact same bytes the apply phase would write
/// are the bytes the plan compares against; a future change to
/// the apply path that diverges from this one would re-write a
/// file the plan said was identical, which the rerun test would
/// catch. The published-port list is derived from the same
/// listener set the apply phase will write.
pub(super) fn render_for(answers: &Answers, database: bool) -> Result<String, ApplyError> {
	let listeners = listeners_to_write(answers)?;
	let published_ports = published_ports_for_listeners(&listeners);
	let composed = ComposeFile::build(answers, published_ports, database);
	let mut bytes = serde_json::to_string_pretty(&composed)
		.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	bytes.push('\n');
	Ok(bytes)
}

fn write_readme(dir: &Path, report: &mut Report) -> Result<(), ApplyError> {
	let path = dir.join("README");
	// The README is operator-facing, not a secret; the default
	// `0o644` is the umask-derived mode a regular `touch` would
	// produce. Pin it explicitly on every run, including when
	// the bytes are unchanged: an earlier run under a tight
	// umask (for example, 0o077) would have left the file at
	// 0o600, and a follow-up `cat README` from a different
	// account would quietly deny access. The mode is operator
	// documentation, not a secret, so the same default applies
	// every time.
	match fs::read(&path) {
		Ok(existing) if existing == COMPOSE_README.as_bytes() => {
			// Bytes unchanged: the file is reused, but the
			// mode is still re-pinned so an earlier
			// 0o077-umask run that landed the file at
			// 0o600 does not survive.
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
					.map_err(|error| ApplyError::KeyWrite(path.clone(), error))?;
			}
			report.steps.push(ReportStep::Reused(path));
			Ok(())
		}
		_ => {
			let mut file = fs::OpenOptions::new()
				.write(true)
				.create(true)
				.truncate(true)
				.open(&path)
				.map_err(|error| ApplyError::KeyWrite(path.clone(), error))?;
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				let perms = std::fs::Permissions::from_mode(0o644);
				file.set_permissions(perms)
					.map_err(|error| ApplyError::KeyWrite(path.clone(), error))?;
			}
			file.write_all(COMPOSE_README.as_bytes())
				.map_err(|error| ApplyError::KeyWrite(path.clone(), error))?;
			report.steps.push(ReportStep::Wrote(path));
			Ok(())
		}
	}
}

/// Map the listeners `init` writes into the config to the
/// `ports:` array of the `mail` service. Every non-loopback
/// listener is published as `<port>:<port>` so the host port is
/// the same number the listener binds inside the container.
/// Loopback listeners (a `127.0.0.1` API, for example) are
/// reachable inside the container through the pasta mapping but
/// not from the host network, so they do not get a `ports:`
/// entry. The list is returned in the same order the listeners
/// appear in the config; the operator reads it in that order in
/// the rendered file.
///
/// `IpAddr::is_loopback` recognises `127.0.0.0/8` and `::1` only.
/// An IPv4-mapped IPv6 form (`::ffff:127.0.0.1`) would otherwise
/// slip past the loopback check and produce a `19123:19123`
/// publish for a listener that only ever sees loopback packets.
/// `to_canonical` collapses the IPv4-mapped form to its IPv4
/// representation first, so the loopback check sees the address
/// the operator actually bound.
pub(super) fn published_ports_for_listeners(listeners: &[Listener]) -> Vec<String> {
	let mut ports = Vec::with_capacity(listeners.len());
	for listener in listeners {
		if listener.addr.to_canonical().is_loopback() {
			continue;
		}
		let port = listener
			.port
			.unwrap_or_else(|| listener.kind.default_port());
		ports.push(format!("{port}:{port}"));
	}
	ports
}

// ---- internal JSON shape -----------------------------------------------

#[derive(Debug, Serialize)]
pub(super) struct ComposeService {
	image: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	command: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	network_mode: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	user: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	userns_mode: Option<String>,
	volumes: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	ports: Option<Vec<String>>,
	environment: BTreeMap<String, String>,
	restart: String,
	security_opt: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	read_only: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	tmpfs: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	sysctls: Option<BTreeMap<String, String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	secrets: Option<Vec<SecretMount>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	depends_on: Option<BTreeMap<String, DependsOn>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	healthcheck: Option<Healthcheck>,
}

impl ComposeService {
	/// Build the `mail` service. `image` is either the operator's
	/// override or the build-time default. `config_path` is
	/// bind-mounted read-only; the parent of `config_path` (the
	/// operator's `mail.toml` directory) is the mount source so the
	/// container sees the same file the host wrote.
	fn new_mail(
		image: &str,
		config_path: &Path,
		data_dir: &Path,
		database: bool,
		published_ports: Vec<String>,
	) -> Self {
		let config_dir = config_path.parent().unwrap_or_else(|| Path::new("/"));
		let mut volumes = Vec::new();
		volumes.push(format!(
			"{}:{}:ro,Z",
			config_dir.display(),
			config_dir.display()
		));
		volumes.push(format!("{}:{}:Z", data_dir.display(), data_dir.display()));
		if database {
			volumes.push("epistle-pgsock:/run/postgresql".to_string());
		}
		let mut environment = BTreeMap::new();
		environment.insert("TZ".to_string(), "UTC".to_string());
		Self {
			image: image.to_string(),
			command: Some(vec![
				"serve".to_string(),
				"--config".to_string(),
				config_path.display().to_string(),
			]),
			network_mode: Some("pasta".to_string()),
			user: Some("65532:65532".to_string()),
			userns_mode: Some("keep-id:uid=65532,gid=65532".to_string()),
			volumes,
			ports: Some(published_ports),
			environment,
			restart: "unless-stopped".to_string(),
			security_opt: vec!["no-new-privileges".to_string()],
			read_only: None,
			tmpfs: None,
			// Lower the unprivileged port start inside the
			// container's network namespace so the mail user
			// (uid 65532) can bind SMTP (25) and the rest of
			// the listeners that ship below 1024. The setting
			// is namespaced to the container's netns and does
			// not touch the host.
			sysctls: Some({
				let mut map = BTreeMap::new();
				map.insert(
					"net.ipv4.ip_unprivileged_port_start".to_string(),
					"0".to_string(),
				);
				map
			}),
			secrets: None,
			depends_on: database.then(|| {
				let mut map = BTreeMap::new();
				map.insert(
					"db".to_string(),
					DependsOn {
						condition: "service_healthy".to_string(),
					},
				);
				map
			}),
			healthcheck: None,
		}
	}

	/// Build the `db` service. The image is the pinned digest; the
	/// `command` overrides the default `postgres` invocation to
	/// refuse TCP; the `secrets` mount uses the long syntax with
	/// `uid`/`gid`/`mode` so the entrypoint (uid 999) can read the
	/// file. The healthcheck connects over the Unix-domain socket
	/// on the `epistle-pgsock` volume and selects `1` to prove the
	/// authentication round-trip works.
	fn new_db() -> Self {
		let mut environment = BTreeMap::new();
		environment.insert("POSTGRES_USER".to_string(), "epistle".to_string());
		environment.insert("POSTGRES_DB".to_string(), "epistle".to_string());
		environment.insert(
			"POSTGRES_PASSWORD_FILE".to_string(),
			"/run/secrets/epistle_db_password".to_string(),
		);
		environment.insert(
			"POSTGRES_INITDB_ARGS".to_string(),
			"--auth-local=scram-sha-256 --auth-host=reject".to_string(),
		);
		environment.insert("TZ".to_string(), "UTC".to_string());
		let healthcheck_test = "PGPASSWORD=\"$(cat /run/secrets/epistle_db_password)\" \
			psql -h /var/run/postgresql -U epistle -d epistle -Atc 'select 1' >/dev/null"
			.to_string();
		Self {
			image: POSTGRES_18_IMAGE.to_string(),
			command: Some(vec![
				"postgres".to_string(),
				"-c".to_string(),
				"listen_addresses=".to_string(),
			]),
			network_mode: Some("none".to_string()),
			user: None,
			userns_mode: None,
			volumes: vec![
				"epistle-pgdata:/var/lib/postgresql".to_string(),
				"epistle-pgsock:/var/run/postgresql".to_string(),
			],
			ports: None,
			environment,
			restart: "unless-stopped".to_string(),
			security_opt: vec!["no-new-privileges".to_string()],
			read_only: Some(true),
			tmpfs: Some(vec!["/tmp".to_string()]),
			sysctls: None,
			secrets: Some(vec![SecretMount {
				source: "epistle_db_password".to_string(),
				target: "epistle_db_password".to_string(),
				uid: "999".to_string(),
				gid: "999".to_string(),
				mode: DATABASE_SECRET_MODE,
			}]),
			depends_on: None,
			healthcheck: Some(Healthcheck {
				test: vec!["CMD-SHELL".to_string(), healthcheck_test],
				interval: "5s".to_string(),
				timeout: "5s".to_string(),
				retries: 30,
			}),
		}
	}
}

#[derive(Debug, Serialize)]
struct SecretMount {
	source: String,
	target: String,
	uid: String,
	gid: String,
	/// Mode as a JSON number. 0o400 == 256 decimal; the rendered
	/// file carries the same byte, and podup reads it as the octal
	/// mode. The string form is rejected by podup's mode parser as
	/// decimal, so the number is the only safe shape.
	mode: u32,
}

#[derive(Debug, Serialize)]
struct DependsOn {
	condition: String,
}

#[derive(Debug, Serialize)]
struct Healthcheck {
	test: Vec<String>,
	interval: String,
	timeout: String,
	retries: u32,
}

#[derive(Debug, Serialize)]
struct TopLevelSecret {
	file: String,
}

#[derive(Debug, Serialize)]
struct TopLevelVolume {}

/// The full compose file. `serde_json` writes the field order from
/// the struct definition, so the rendered file matches the order
/// the operator reads here.
#[derive(Debug, Serialize)]
pub(super) struct ComposeFile {
	name: String,
	services: BTreeMap<String, ComposeService>,
	secrets: BTreeMap<String, TopLevelSecret>,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	volumes: BTreeMap<String, TopLevelVolume>,
}

impl ComposeFile {
	fn build(answers: &Answers, published_ports: Vec<String>, database: bool) -> Self {
		let image = resolve_image(answers.image.as_deref());
		let mut services = BTreeMap::new();
		services.insert(
			"mail".to_string(),
			ComposeService::new_mail(
				&image,
				&answers.config_path,
				&answers.data_dir,
				database,
				published_ports,
			),
		);
		let mut secrets = BTreeMap::new();
		let mut volumes = BTreeMap::new();
		if database {
			services.insert("db".to_string(), ComposeService::new_db());
			secrets.insert(
				"epistle_db_password".to_string(),
				TopLevelSecret {
					file: db_password_path(&answers.data_dir).display().to_string(),
				},
			);
			volumes.insert("epistle-pgdata".to_string(), TopLevelVolume {});
			volumes.insert("epistle-pgsock".to_string(), TopLevelVolume {});
		}
		Self {
			name: "epistle".to_string(),
			services,
			secrets,
			volumes,
		}
	}
}

#[cfg(test)]
#[path = "compose_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compose_password_tests.rs"]
mod tests_password;

#[cfg(test)]
#[path = "compose_file_tests.rs"]
mod tests_file;

#[cfg(test)]
pub(super) fn minimal_answers() -> crate::cli::init::Answers {
	use crate::cli::init::answers::Mode;
	crate::cli::init::Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: std::path::PathBuf::from("/var/lib/epistle"),
		config_path: std::path::PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: crate::cli::init::answers::Services {
			imap: true,
			submission: true,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database: false,
		},
		image: None,
	}
}

#[cfg(test)]
pub(super) fn stack_answers() -> crate::cli::init::Answers {
	let mut answers = minimal_answers();
	answers.services.database = true;
	answers
}

#[cfg(test)]
pub(super) fn local_image_answers() -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.image = Some("localhost/epistle:dev".to_string());
	answers
}
