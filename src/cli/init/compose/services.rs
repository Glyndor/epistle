//! Service definitions for the generated container stack.
use super::super::db_roles;
use super::{Answers, DATABASE_SECRET_MODE, HOST_EPISTLE_PATH};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

// ---- internal JSON shape -----------------------------------------------

#[derive(Debug, Serialize)]
pub(super) struct ComposeService {
	image: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	entrypoint: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	command: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	network_mode: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	user: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	userns_mode: Option<String>,
	volumes: Vec<VolumeMount>,
	#[serde(skip_serializing_if = "Option::is_none")]
	ports: Option<Vec<String>>,
	environment: BTreeMap<String, String>,
	restart: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	stop_grace_period: Option<String>,
	security_opt: Vec<String>,
	cap_drop: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	cap_add: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	read_only: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	tmpfs: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	sysctls: Option<BTreeMap<String, String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	mem_limit: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pids_limit: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	ulimits: Option<BTreeMap<String, u64>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	secrets: Option<Vec<SecretMount>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	configs: Option<Vec<ConfigMount>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	depends_on: Option<BTreeMap<String, DependsOn>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	healthcheck: Option<Healthcheck>,
}

impl ComposeService {
	/// Apply the memory and process limits of `name` from
	/// [`super::super::resources::limits`].
	pub(super) fn limited(
		mut self,
		name: &str,
		overrides: &BTreeMap<String, super::super::resources::ServiceResources>,
	) -> Self {
		if let Some((memory, pids)) = super::super::resources::limits(overrides, name) {
			self.mem_limit = Some(memory);
			self.pids_limit = Some(pids);
		}
		self
	}

	/// Build the `mail` service. The default mode (answers
	/// leave `image` unset) mounts the host's `/usr/bin/epistle`
	/// bind-mounted read-only into the digest-pinned
	/// `gcr.io/distroless/static-debian13:nonroot` base and
	/// overrides the entrypoint to `/usr/bin/epistle`; the custom
	/// mode keeps the old shape (the operator's image as
	/// provided, no binary mount, image's own entrypoint/CMD).
	/// `image` is the resolved image reference (either the
	/// distroless base or the operator's override). `config_path`
	/// is bind-mounted read-only; the parent of `config_path` (the
	/// operator's `mail.toml` directory) is the mount source so the
	/// container sees the same file the host wrote.
	pub(super) fn new_mail(
		image: &str,
		answers: &Answers,
		database: bool,
		published_ports: Vec<String>,
		nofile: Option<u64>,
	) -> Self {
		let config_path = &answers.config_path;
		let data_dir = &answers.data_dir;
		let config_dir = config_path.parent().unwrap_or_else(|| Path::new("/"));
		let mut volumes = Vec::new();
		volumes.push(VolumeMount::bind(config_dir, config_dir, true));
		volumes.push(VolumeMount::bind(data_dir, data_dir, false));
		if database {
			volumes.push(VolumeMount::Named(
				"epistle-pgsock:/run/postgresql".to_string(),
			));
		}
		let antivirus = answers.services.antivirus != Some(false);
		if antivirus {
			volumes.push(VolumeMount::Named("clamd-socket:/run/clamav".to_string()));
		}
		let mut environment = BTreeMap::new();
		environment.insert("TZ".to_string(), "UTC".to_string());
		// With the certificates container the DNS credential is mounted
		// there and nowhere else, and the pair it writes is read-only here.
		if answers.services.certs {
			volumes.extend(certs::read_only_in_mail(data_dir));
			// The hand-off both containers share: this one asks the other
			// to write the DKIM records, because the credential is there.
			volumes.push(VolumeMount::bind(
				&certs::handoff_dir(data_dir),
				&certs::handoff_dir(data_dir),
				false,
			));
		} else {
			add_dns_credentials(answers, &mut volumes, &mut environment);
		}
		// The host-binary default: bind-mount the system-supplied
		// `/usr/bin/epistle` read-only into the digest-pinned
		// distroless base, then override the entrypoint to run
		// that path. The bind mount is the long syntax (so
		// `read_only` is honoured) and carries NO `Z` (SELinux
		// relabel) option: the path is a system file owned by
		// root after the .deb install and relabelling it would
		// silently change its on-disk label. Custom image mode
		// does not mount the binary; the image carries its own
		// entrypoint and a release image can also carry the
		// `serve --config` default.
		if answers.image.is_none() {
			volumes.push(VolumeMount::bind_system_binary(
				Path::new(HOST_EPISTLE_PATH),
				Path::new(HOST_EPISTLE_PATH),
			));
		}
		Self {
			image: image.to_string(),
			entrypoint: if answers.image.is_none() {
				Some(vec![HOST_EPISTLE_PATH.to_string()])
			} else {
				None
			},
			command: Some(serve_command(
				config_path,
				answers.services.certs.then_some("mail"),
			)),
			network_mode: Some("pasta".to_string()),
			user: Some("65532:65532".to_string()),
			userns_mode: Some("keep-id:uid=65532,gid=65532".to_string()),
			volumes,
			ports: Some(published_ports),
			environment,
			restart: "unless-stopped".to_string(),
			// `serve` drains for a few seconds less than this on SIGTERM,
			// so open SMTP transactions finish before podup sends SIGKILL.
			stop_grace_period: Some(format!("{MAIL_STOP_GRACE_SECS}s")),
			security_opt: vec!["no-new-privileges".to_string()],
			// uid 65532 holds no capability, and the ports below 1024 come
			// from the sysctl below, not from NET_BIND_SERVICE.
			cap_drop: drop_all(),
			cap_add: None,
			// `podman diff` after mail in, a submission and an IMAP read
			// showed no write outside the mounts, so no tmpfs either.
			read_only: Some(true),
			tmpfs: None,
			// Lower the unprivileged port start inside the
			// container's network namespace so the mail user
			// (uid 65532) can bind SMTP (25) and the rest of
			// the listeners that ship below 1024. The setting
			// is namespaced to the container's netns and does
			// not touch the host.
			mem_limit: None,
			pids_limit: None,
			ulimits: nofile.map(|limit| BTreeMap::from([("nofile".to_string(), limit)])),
			sysctls: Some({
				let mut map = BTreeMap::new();
				map.insert(
					"net.ipv4.ip_unprivileged_port_start".to_string(),
					"0".to_string(),
				);
				map
			}),
			// The keys kept outside data_dir, read-only, at their host path:
			// the host commands read the same config and need the same path.
			configs: None,
			secrets: Some(
				super::KEY_SECRETS
					.iter()
					.map(|(source, path)| SecretMount {
						source: (*source).to_string(),
						target: path(data_dir).display().to_string(),
						uid: "65532".to_string(),
						gid: "65532".to_string(),
						mode: DATABASE_SECRET_MODE,
					})
					.collect(),
			),
			depends_on: Some({
				let mut map = BTreeMap::new();
				if antivirus {
					map.insert(
						"clamav".to_string(),
						DependsOn {
							condition: "service_healthy".to_string(),
						},
					);
				}
				if database {
					map.insert(
						"db".to_string(),
						DependsOn {
							condition: "service_healthy".to_string(),
						},
					);
				}
				map
			})
			.filter(|map| !map.is_empty()),
			// Healthcheck the running mail listeners from inside the
			// container. The distroless base image ships neither a
			// shell nor curl, so the only viable probe is the
			// `epistle probe` subcommand itself; any container engine
			// `CMD`/`CMD-SHELL` form that depends on a shell or a
			// binary the image does not carry will fail closed.
			// Custom-image mode reuses the same command path
			// (`/usr/bin/epistle probe ...`) and therefore requires
			// the operator's image to ship `/usr/bin/epistle`; the
			// default mode satisfies that by bind-mounting the host
			// `/usr/bin/epistle` read-only at the same path inside
			// the container, so the entrypoint and the healthcheck
			// resolve the binary to the same bytes either way.
			//
			// `timeout: 10s` sits comfortably above the probe's own
			// two-second per-listener budget: a slow first byte from
			// a freshly started listener surfaces as `connect:
			// timeout` (a real listener problem) rather than getting
			// folded into the healthcheck timeout (which the engine
			// counts as a probe failure with no diagnostic).
			healthcheck: Some(Healthcheck {
				test: vec![
					"CMD".to_string(),
					HOST_EPISTLE_PATH.to_string(),
					"probe".to_string(),
					"--config".to_string(),
					config_path.display().to_string(),
				],
				interval: "30s".to_string(),
				timeout: "10s".to_string(),
				retries: 3,
				start_period: Some("30s".to_string()),
			}),
		}
	}

	/// Build the `db` service. The image is the pinned digest; the
	/// `command` overrides the default `postgres` invocation to
	/// refuse TCP; the `secrets` mount uses the long syntax with
	/// `uid`/`gid`/`mode` so the entrypoint (uid 999) can read the
	/// file. The healthcheck connects over the Unix-domain socket
	/// on the `epistle-pgsock` volume and selects `1` to prove the
	/// authentication round-trip works.
	pub(super) fn new_db() -> Self {
		let mut environment = BTreeMap::new();
		// The image's POSTGRES_USER becomes the bootstrap superuser, which
		// can never lose SUPERUSER; see `db_roles`.
		environment.insert(
			"POSTGRES_USER".to_string(),
			db_roles::ADMIN_USER.to_string(),
		);
		environment.insert("POSTGRES_DB".to_string(), super::DATABASE_NAME.to_string());
		environment.insert(
			"POSTGRES_PASSWORD_FILE".to_string(),
			db_roles::ADMIN_PASSWORD_FILE.to_string(),
		);
		environment.insert(
			"POSTGRES_INITDB_ARGS".to_string(),
			"--auth-local=scram-sha-256 --auth-host=reject".to_string(),
		);
		environment.insert("TZ".to_string(), "UTC".to_string());
		let healthcheck_test = "[ \"$(cat /proc/1/comm)\" = postgres ] && PGPASSWORD=\"$(cat /run/secrets/epistle_db_password)\" \
			psql -h /var/run/postgresql -U epistle -d epistle -Atc 'select 1' >/dev/null"
			.to_string();
		Self {
			image: super::super::images::postgres().to_string(),
			entrypoint: None,
			command: Some(vec![
				"postgres".to_string(),
				"-c".to_string(),
				"listen_addresses=".to_string(),
			]),
			network_mode: Some("none".to_string()),
			// The image's postgres user. Started as root, the entrypoint
			// chowns both volumes and steps down with gosu, which under
			// `cap_drop: [ALL]` failed on the first chmod (measured on
			// postgres:18). As 999 it skips both, and the volumes an
			// earlier root start initialised are already owned by 999.
			user: Some("999:999".to_string()),
			userns_mode: None,
			volumes: vec![
				VolumeMount::Named("epistle-pgdata:/var/lib/postgresql".to_string()),
				VolumeMount::Named("epistle-pgsock:/var/run/postgresql".to_string()),
			],
			ports: None,
			environment,
			restart: "unless-stopped".to_string(),
			stop_grace_period: None,
			security_opt: vec!["no-new-privileges".to_string()],
			cap_drop: drop_all(),
			cap_add: None,
			read_only: Some(true),
			tmpfs: Some(vec!["/tmp".to_string()]),
			mem_limit: None,
			pids_limit: None,
			ulimits: None,
			sysctls: None,
			// epistle's password for the healthcheck, the dumps and the role
			// script; the admin password only here, never in mail.
			secrets: Some(
				["epistle_db_password", db_roles::ADMIN_SECRET]
					.map(|name| SecretMount {
						source: name.to_string(),
						target: name.to_string(),
						uid: "999".to_string(),
						gid: "999".to_string(),
						mode: DATABASE_SECRET_MODE,
					})
					.to_vec(),
			),
			configs: Some(vec![ConfigMount {
				source: DB_ROLES_CONFIG.to_string(),
				target: db_roles::INIT_SCRIPT_PATH.to_string(),
				mode: 444,
			}]),
			depends_on: None,
			healthcheck: Some(Healthcheck {
				start_period: None,
				test: vec!["CMD-SHELL".to_string(), healthcheck_test],
				interval: "5s".to_string(),
				timeout: "5s".to_string(),
				retries: 30,
			}),
		}
	}
}

/// `serve --config <path>`, with `--role <role>` when the process runs one
/// half of a split stack.
fn serve_command(config_path: &Path, role: Option<&str>) -> Vec<String> {
	let mut command = vec![
		"serve".to_string(),
		"--config".to_string(),
		config_path.display().to_string(),
	];
	if let Some(role) = role {
		command.extend(["--role".to_string(), role.to_string()]);
	}
	command
}

/// Hand the DNS credential of every `[dns]` entry to a service: the token
/// variable passed through as `${NAME}`, the token file bound read-only at
/// its own path.
fn add_dns_credentials(
	answers: &Answers,
	volumes: &mut Vec<VolumeMount>,
	environment: &mut BTreeMap<String, String>,
) {
	let mut token_files = Vec::new();
	for (token_env, token_file) in super::dns_credentials::of(answers) {
		if let Some(name) = &token_env {
			environment.insert(name.clone(), format!("${{{name}}}"));
		}
		if let Some(path) = token_file {
			// Two zones may read one file; it is mounted once.
			if !token_files.contains(&path) {
				volumes.push(VolumeMount::bind(&path, &path, true));
				token_files.push(path);
			}
		}
	}
}

mod certs;
mod clamav;
mod nofile;
pub(super) use certs::ACME_ACCOUNT_SECRET;
pub(crate) use nofile::{MAIL_STOP_GRACE_SECS, host_hard_nofile, mail_nofile, warn_low_nofile};

/// Every capability: each service starts from none and `cap_add` names
/// what it was measured to need.
fn drop_all() -> Vec<String> {
	vec!["ALL".to_string()]
}

#[derive(Debug, Clone, Serialize)]
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

/// The compose config that carries [`db_roles::INIT_SCRIPT`].
pub(super) const DB_ROLES_CONFIG: &str = "epistle_db_roles";

/// A compose config mounted as a file. `mode` follows the same octal
/// reading as [`SecretMount::mode`]: `444` is `0o444`, read-only for all,
/// which the entrypoint sources rather than executes.
#[derive(Debug, Serialize)]
struct ConfigMount {
	source: String,
	target: String,
	mode: u32,
}

#[derive(Debug, Serialize)]
struct DependsOn {
	condition: String,
}

#[derive(Debug, Serialize)]
struct Healthcheck {
	#[serde(skip_serializing_if = "Option::is_none")]
	start_period: Option<String>,
	test: Vec<String>,
	interval: String,
	timeout: String,
	retries: u32,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum VolumeMount {
	Named(String),
	Bind(BindMount),
	/// System binary bind mount: same shape as [`Bind`] but
	/// carries NO `bind.propagation` or `bind.selinux` option
	/// at all. Used for the host `/usr/bin/epistle`, which is a
	/// root-owned system file that must NOT carry the SELinux
	/// `Z` relabel hint the other bind mounts use: relabelling
	/// a system file would silently change its on-disk label
	/// and break out-of-band tooling that reads the file
	/// through the original label.
	BindSystemBinary(SystemBindMount),
}

#[derive(Debug, Serialize)]
struct BindMount {
	#[serde(rename = "type")]
	kind: &'static str,
	source: String,
	target: String,
	read_only: bool,
	bind: BindOptions,
}

/// The `Z` private SELinux relabel hint the apply phase
/// attaches to operator bind mounts. The shell knob in
/// podup 5.10.11+ recognises it as "relabel the source with
/// the container's private label, then unlabel it on
/// teardown"; podup writes its absence as no relabel.
#[derive(Debug, Serialize)]
struct BindOptions {
	selinux: &'static str,
}

/// Bind shape for system binaries: long syntax (`type`/`source`/
/// `target`/`read_only`) and no relabel hint. podup treats
/// the missing `bind` block as "no relabel".
#[derive(Debug, Serialize)]
struct SystemBindMount {
	#[serde(rename = "type")]
	kind: &'static str,
	source: String,
	target: String,
	read_only: bool,
}

impl VolumeMount {
	fn bind(source: &Path, target: &Path, read_only: bool) -> Self {
		Self::Bind(BindMount {
			kind: "bind",
			source: source.display().to_string(),
			target: target.display().to_string(),
			read_only,
			bind: BindOptions { selinux: "Z" },
		})
	}

	/// Bind shape for a system binary: read-only, no SELinux
	/// relabel hint. Used for `/usr/bin/epistle` in the default
	/// compose shape. `read_only: true` is set explicitly so a
	/// podup-side default that ever flipped to writable would
	/// not silently widen this mount.
	fn bind_system_binary(source: &Path, target: &Path) -> Self {
		Self::BindSystemBinary(SystemBindMount {
			kind: "bind",
			source: source.display().to_string(),
			target: target.display().to_string(),
			read_only: true,
		})
	}
}
