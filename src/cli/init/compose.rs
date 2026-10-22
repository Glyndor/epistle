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
use super::compose_publish;

#[path = "host_binary.rs"]
mod host_binary;

#[cfg(not(test))]
pub(super) use host_binary::validate_host_binary_for;
#[cfg(test)]
pub(super) use host_binary::{ElfLinkKind, classify_elf_link, validate_host_binary_for};

/// The fixed role created by the database image entrypoint.
pub(crate) const DATABASE_USER: &str = "epistle";
/// The fixed database created by the database image entrypoint.
pub(crate) const DATABASE_NAME: &str = "epistle";
/// The database password secret mounted inside the db service.
pub(crate) const DATABASE_PASSWORD_FILE: &str = "/run/secrets/epistle_db_password";

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

/// Where a key lives on the host, given data_dir.
type KeyPath = fn(&Path) -> PathBuf;

/// The keys `mail` reads as compose secrets, by secret name and host path.
const KEY_SECRETS: [(&str, KeyPath); 2] = [
	(
		"epistle_oauth_signing_key",
		super::host_secrets::oauth_signing_key,
	),
	("epistle_storage_key", super::host_secrets::storage_key),
];

/// The host path the .deb installs `epistle` at. The default compose
/// shape bind-mounts this file into the distroless base read-only and
/// runs it as the container's entrypoint. A source build linked
/// against glibc uses a different path and is rejected by the host
/// binary validator below.
pub(crate) const HOST_EPISTLE_PATH: &str = "/usr/bin/epistle";

/// Resolve the mail image the compose file will render. The
/// default is the digest-pinned distroless base; an explicit
/// `image` in the answers replaces it with the operator's
/// reference (validated by the answers validator).
pub(super) fn resolve_image(image: Option<&str>) -> String {
	image
		.map(str::to_string)
		.unwrap_or_else(|| super::images::mail_base().to_string())
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

/// The path the compose file lives at. `pub` so the sibling `backup`
/// module can ask "is the container stack present?" without reaching
/// into `init`'s private surface; the rest of the helpers stay
/// module-private.
pub fn compose_file_path(data_dir: &Path) -> PathBuf {
	data_dir.join("compose").join("compose.yaml")
}

/// Explain how to start the stack and keep customizations across init reruns.
const COMPOSE_README: &str = "Bring up the stack with `sudo epistle stack up` (runs podup). \
init regenerates compose.yaml; keep image choices in the answers and customizations in compose.override.yaml.\n";

#[path = "compose_secrets.rs"]
mod secrets;
pub(super) use secrets::{db_password_reused, ensure_db_admin_password, ensure_db_password};
#[cfg(test)]
pub(super) use secrets::{ensure_db_password_with_probe, generate_db_password};

/// Compose-file step in the apply phase. The caller already
/// passed the answers file through `ensure_db_password`; this
/// derives the published ports from the listeners init will
/// write into the config (after the keep-existing-listeners
/// merge) and writes the compose file plus the README. Validates
/// the host `/usr/bin/epistle` first when the answers leave
/// `image` unset (default host-binary mode): the compose file
/// references the path and binds it read-only into the
/// distroless base, so a missing or dynamically linked binary
/// would produce a `podup up` that fails to start the mail
/// service. The refusal here is the operator-facing message
/// that names the .deb install path the operator needs to
/// run.
pub(super) fn write_compose_step(answers: &Answers, report: &mut Report) -> Result<(), ApplyError> {
	write_compose_step_with_host_binary(answers, report, std::path::Path::new(HOST_EPISTLE_PATH))
}

/// Same as [`write_compose_step`] but with the host-binary
/// path injected. Tests point this at a synthetic file under
/// a tempdir; the production caller uses
/// [`HOST_EPISTLE_PATH`].
pub(super) fn write_compose_step_with_host_binary(
	answers: &Answers,
	report: &mut Report,
	host_binary_path: &Path,
) -> Result<(), ApplyError> {
	if answers.image.is_none()
		&& let Some(message) = validate_host_binary_for(host_binary_path)
	{
		return Err(ApplyError::HostBinaryInvalid(message));
	}
	ensure_compose_file(answers, answers.services.database, report)?;
	Ok(())
}

/// Lay down `<data_dir>/compose/compose.yaml` and a short README
/// next to it. The compose file is regenerated when its bytes do
/// not match; identical means untouched. The `database` flag
/// switches the `db` service and the secrets/volumes blocks in
/// or out. The published-port list is derived from the listeners
/// init writes into the config (see [`compose_publish::published`])
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
	let narrow = compose_publish::hosts_in_file(&path);
	let published_ports = compose_publish::published(&listeners, &narrow, None);
	let composed = ComposeFile::build(answers, published_ports, database);
	// `serde_json::to_string_pretty` is the stable pretty-printer
	// the tests pin on: the rendered file carries a trailing
	// newline, two-space indentation, and the field order of the
	// struct definition above.
	let bytes = render_document(&composed)?;
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
	let clamd_config = dir.join("clamd.conf");
	let content = "LocalSocket /run/clamav/clamd.sock\nLocalSocketMode 666\nFixStaleSocket yes\nDatabaseDirectory /var/lib/clamav\nUser clamav\nForeground yes\n";
	// Socket mode permits mail uid 65532 across distinct rootless user namespaces.
	if fs::read_to_string(&clamd_config).ok().as_deref() != Some(content) {
		crate::storage::write_secret(&clamd_config, content.as_bytes())
			.map_err(|error| ApplyError::ConfigWrite(clamd_config.clone(), error))?;
		report.steps.push(ReportStep::Wrote(clamd_config));
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
	let narrow = compose_publish::hosts_in_file(&compose_file_path(&answers.data_dir));
	let published_ports = compose_publish::published(&listeners, &narrow, None);
	let composed = ComposeFile::build(answers, published_ports, database);
	render_document(&composed)
}

/// Render the desired compose file after validating the host
/// binary. Same as [`render_for`] but performs the static-ELF
/// check against `host_binary_path` first when the answers
/// leave `image` unset. Used by the apply-phase tests so a
/// fixture without `image` set exercises the same code path
/// the production apply phase runs without having to install
/// the .deb on the test machine.
#[cfg(test)]
pub(super) fn render_for_with_host_binary(
	answers: &Answers,
	database: bool,
	host_binary_path: &Path,
) -> Result<String, ApplyError> {
	if answers.image.is_none()
		&& let Some(message) = validate_host_binary_for(host_binary_path)
	{
		return Err(ApplyError::HostBinaryInvalid(message));
	}
	render_for(answers, database)
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

#[path = "compose_services.rs"]
mod services;
use services::ComposeService;
pub(crate) use services::MAIL_STOP_GRACE_SECS;
pub(super) use services::{host_hard_nofile, warn_low_nofile};

#[derive(Debug, Serialize)]
struct TopLevelSecret {
	file: String,
}

#[derive(Debug, Serialize)]
struct TopLevelVolume {}

#[derive(Debug, Serialize)]
struct TopLevelConfig {
	content: &'static str,
}

/// The full compose file. `serde_json` writes the field order from
/// the struct definition, so the rendered file matches the order
/// the operator reads here.
#[derive(Debug, Serialize)]
pub(super) struct ComposeFile {
	name: String,
	#[serde(rename = "x-epistle-managed-image")]
	managed_image: bool,
	/// `false` when the stack runs no clamav on purpose, which `stack
	/// update` reads back; absent otherwise, so a file from before clamav
	/// was part of the stack still gets it.
	#[serde(
		rename = "x-epistle-antivirus",
		skip_serializing_if = "Option::is_none"
	)]
	antivirus: Option<bool>,
	/// The limits the answers set, which `stack update` reads back.
	#[serde(
		rename = "x-epistle-resources",
		skip_serializing_if = "BTreeMap::is_empty"
	)]
	resources: BTreeMap<String, super::resources::ServiceResources>,
	services: BTreeMap<String, ComposeService>,
	secrets: BTreeMap<String, TopLevelSecret>,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	configs: BTreeMap<String, TopLevelConfig>,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	volumes: BTreeMap<String, TopLevelVolume>,
}

impl ComposeFile {
	pub(super) fn build(answers: &Answers, published_ports: Vec<String>, database: bool) -> Self {
		let nofile = services::mail_nofile(services::host_hard_nofile());
		Self::build_with_nofile(answers, published_ports, database, nofile)
	}

	/// [`Self::build`] asking for `nofile` open files in the `mail` service.
	pub(super) fn build_with_nofile(
		answers: &Answers,
		published_ports: Vec<String>,
		database: bool,
		nofile: Option<u64>,
	) -> Self {
		let image = resolve_image(answers.image.as_deref());
		let mut services = BTreeMap::new();
		services.insert(
			"mail".to_string(),
			ComposeService::new_mail(&image, answers, database, published_ports, nofile),
		);
		// Off only when the answers or the host's memory said so.
		let antivirus = answers.services.antivirus != Some(false);
		if antivirus {
			services.insert(
				"clamav".to_string(),
				ComposeService::new_clamav(answers, false),
			);
			services.insert(
				"freshclam".to_string(),
				ComposeService::new_clamav(answers, true),
			);
		}
		let mut secrets = BTreeMap::new();
		for (name, path) in KEY_SECRETS {
			secrets.insert(
				name.to_string(),
				TopLevelSecret {
					file: path(&answers.data_dir).display().to_string(),
				},
			);
		}
		let mut configs = BTreeMap::new();
		let mut volumes = BTreeMap::new();
		if antivirus {
			volumes.insert("clamd-socket".to_string(), TopLevelVolume {});
			volumes.insert("clamav-db".to_string(), TopLevelVolume {});
		}
		if database {
			services.insert("db".to_string(), ComposeService::new_db());
			secrets.insert(
				"epistle_db_password".to_string(),
				TopLevelSecret {
					file: db_password_path(&answers.data_dir).display().to_string(),
				},
			);
			secrets.insert(
				super::db_roles::ADMIN_SECRET.to_string(),
				TopLevelSecret {
					file: super::host_secrets::db_admin_password(&answers.data_dir)
						.display()
						.to_string(),
				},
			);
			configs.insert(
				services::DB_ROLES_CONFIG.to_string(),
				TopLevelConfig {
					content: super::db_roles::INIT_SCRIPT,
				},
			);
			volumes.insert("epistle-pgdata".to_string(), TopLevelVolume {});
			volumes.insert("epistle-pgsock".to_string(), TopLevelVolume {});
		}
		let services = services
			.into_iter()
			.map(|(name, service)| {
				let service = service.limited(&name, &answers.resources);
				(name, service)
			})
			.collect();
		Self {
			name: "epistle".to_string(),
			managed_image: answers.image.is_none(),
			antivirus: (!antivirus).then_some(false),
			resources: answers.resources.clone(),
			services,
			secrets,
			configs,
			volumes,
		}
	}
}

#[cfg(test)]
#[path = "compose_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compose_tests_mail.rs"]
mod tests_mail;

#[cfg(test)]
#[path = "compose_tests_mail_ports.rs"]
mod tests_mail_ports;

#[cfg(test)]
#[path = "compose_tests_mail_probes.rs"]
mod tests_mail_probes;

#[cfg(test)]
#[path = "compose_tests_db.rs"]
mod tests_db;

#[cfg(test)]
#[path = "compose_tests_image_validator.rs"]
mod tests_image_validator;

#[cfg(test)]
#[path = "compose_tests_readme_modes.rs"]
mod tests_readme_modes;

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
		acme: None,
		first_account: None,
		dns: None,
		services: crate::cli::init::answers::Services {
			antivirus: None,
			imap: true,
			submission: true,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database: false,
		},
		image: None,
		resources: Default::default(),
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

/// Render the compose file the apply phase would write for `answers`
/// and `database`, parsing the produced JSON into a `serde_json::Value`
/// so the tests can read the same fields podup reads. Lifted out of
/// the topic-split `compose_tests_*` siblings: every test in those
/// files reaches for it, and lifting it next to `render_for` keeps
/// the helper next to the code path it exercises.
#[cfg(test)]
pub(super) fn render(answers: &crate::cli::init::Answers, database: bool) -> serde_json::Value {
	let bytes = render_for(answers, database).expect("render");
	serde_json::from_str(&bytes).expect("parse")
}

#[cfg(test)]
#[path = "compose_tests_clamav.rs"]
mod tests_clamav;

#[cfg(test)]
#[path = "compose_tests_antivirus.rs"]
mod tests_antivirus;

#[cfg(test)]
#[path = "compose_tests_db_startup.rs"]
mod tests_db_startup;

#[cfg(test)]
#[path = "compose_password_tests_volume.rs"]
mod tests_password_volume;

#[cfg(test)]
#[path = "compose_tests_bind_paths.rs"]
mod tests_bind_paths;

#[cfg(test)]
#[path = "compose_tests_dns_credentials.rs"]
mod tests_dns_credentials;

#[cfg(test)]
#[path = "compose_tests_override.rs"]
mod tests_override;

#[cfg(test)]
#[path = "compose_tests_updates.rs"]
mod tests_updates;

#[cfg(test)]
#[path = "compose_tests_host_binary.rs"]
mod tests_host_binary;

#[cfg(test)]
#[path = "host_binary_tests.rs"]
mod host_binary_tests;

#[cfg(test)]
#[path = "apply_host_binary_tests.rs"]
mod apply_host_binary_tests;

/// Render either a generated compose document or an edited document.
pub(super) fn render_document(document: &impl Serialize) -> Result<String, ApplyError> {
	let mut bytes = serde_json::to_string_pretty(document)
		.map_err(|error| ApplyError::ConfigEncode(error.to_string()))?;
	bytes.push('\n');
	Ok(bytes)
}

#[cfg(test)]
#[path = "compose_tests_service.rs"]
mod tests_service;

#[cfg(test)]
#[path = "compose_tests_capabilities.rs"]
mod tests_capabilities;

#[cfg(test)]
#[path = "compose_tests_read_only.rs"]
mod tests_read_only;

#[cfg(test)]
#[path = "compose_tests_resources.rs"]
mod tests_resources;

#[cfg(test)]
#[path = "compose_tests_keys.rs"]
mod tests_keys;

#[cfg(test)]
#[path = "compose_tests_db_roles.rs"]
mod tests_db_roles;
