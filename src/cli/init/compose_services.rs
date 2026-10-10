//! Service definitions for the generated container stack.
use super::{Answers, DATABASE_SECRET_MODE, POSTGRES_18_IMAGE};
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
	pub(super) fn new_mail(
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
		volumes.push("clamd-socket:/run/clamav".to_string());
		let mut environment = BTreeMap::new();
		environment.insert("TZ".to_string(), "UTC".to_string());
		Self {
			image: image.to_string(),
			entrypoint: None,
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
			depends_on: Some({
				let mut map = BTreeMap::new();
				map.insert(
					"clamav".to_string(),
					DependsOn {
						condition: "service_healthy".to_string(),
					},
				);
				if database {
					map.insert(
						"db".to_string(),
						DependsOn {
							condition: "service_healthy".to_string(),
						},
					);
				}
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
	pub(super) fn new_db() -> Self {
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
		let healthcheck_test = "[ \"$(cat /proc/1/comm)\" = postgres ] && PGPASSWORD=\"$(cat /run/secrets/epistle_db_password)\" \
			psql -h /var/run/postgresql -U epistle -d epistle -Atc 'select 1' >/dev/null"
			.to_string();
		Self {
			image: POSTGRES_18_IMAGE.to_string(),
			entrypoint: None,
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
				start_period: None,
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
	#[serde(skip_serializing_if = "Option::is_none")]
	start_period: Option<String>,
	test: Vec<String>,
	interval: String,
	timeout: String,
	retries: u32,
}

impl ComposeService {
	pub(super) fn new_clamav(answers: &Answers, freshclam: bool) -> Self {
		let mut service = Self {
			image: "docker.io/clamav/clamav:1.4".to_string(),
			entrypoint: None,
			command: None,
			network_mode: Some(if freshclam { "pasta" } else { "none" }.to_string()),
			user: None,
			userns_mode: None,
			volumes: vec!["clamav-db:/var/lib/clamav".to_string()],
			ports: None,
			environment: BTreeMap::new(),
			restart: "unless-stopped".to_string(),
			security_opt: vec!["no-new-privileges".to_string()],
			read_only: None,
			tmpfs: None,
			sysctls: None,
			secrets: None,
			depends_on: None,
			healthcheck: None,
		};
		service.environment.insert(
			if freshclam {
				"CLAMAV_NO_CLAMD"
			} else {
				"CLAMAV_NO_FRESHCLAMD"
			}
			.to_string(),
			"true".to_string(),
		);
		if !freshclam {
			service.volumes.push("clamd-socket:/run/clamav".to_string());
			service.volumes.push(format!(
				"{}:/etc/clamav/epistle-clamd.conf:ro,Z",
				answers.data_dir.join("compose/clamd.conf").display()
			));
			// Bypass the image's config rewriting and enforce a traversable socket directory.
			service.entrypoint = Some(vec!["/bin/sh".to_string(), "-c".to_string(), "chown clamav:clamav /run/clamav && chmod 755 /run/clamav && exec clamd --config-file=/etc/clamav/epistle-clamd.conf".to_string()]);
			service.healthcheck = Some(Healthcheck {
				test: vec![
					"CMD".to_string(),
					"clamdscan".to_string(),
					"--config-file=/etc/clamav/epistle-clamd.conf".to_string(),
					"--ping=1".to_string(),
				],
				interval: "10s".to_string(),
				timeout: "5s".to_string(),
				retries: 30,
				// The initial freshclam download is about 300 MB; clamd waits for signatures.
				start_period: Some("10m".to_string()),
			});
		}
		service
	}
}
