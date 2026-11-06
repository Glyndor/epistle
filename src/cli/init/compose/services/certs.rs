//! The `certs` service of a split stack (`docs/operations/container-split.md`).
//!
//! It holds the DNS credential and the ACME account key and runs `serve
//! --role certs`: ACME renewal with `dns-01` and the TLSA refresh, no
//! listener and no published port. It shares one directory with `mail`,
//! `<data_dir>/acme`, which it writes and `mail` mounts read-only, and it
//! mounts nothing else of data_dir but the TLSA retry state it owns.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
	Answers, ComposeService, DATABASE_SECRET_MODE, HOST_EPISTLE_PATH, SecretMount, VolumeMount,
	add_dns_credentials, drop_all, serve_command,
};

/// The compose secret that carries the ACME account key into `certs`.
pub(in crate::cli::init) const ACME_ACCOUNT_SECRET: &str = "epistle_acme_account_key";

/// The `network_mode` of the `certs` service: a pasta instance of its own,
/// with the two routes to the host closed.
///
/// `certs` needs the internet and nothing else: DNS, the ACME CA and the API of
/// the DNS provider. It must not reach the management API, the listeners
/// `mail` publishes, or the other containers of the stack. Measured on Podman
/// 5.7.0 rootless on 2026-11-06:
///
/// - pasta remaps the host's gateway address to the host unless `--no-map-gw`
///   says otherwise. Podman already passes that option by default, but the
///   property is written here so it does not rest on an engine default.
/// - podman also passes `--map-guest-addr 169.254.1.2`, the alias that makes
///   `host.containers.internal` work: it maps to the host's own address, and
///   through it the container reached a port another container had published
///   and a listener the host had on `0.0.0.0`. With `none` that address maps
///   to nothing, and the internet keeps working (the DNS forwarder podman
///   adds is a different option).
///
/// A user-defined network would not say this: measured, a container on a
/// bridge network reaches the host the same way, and the only network without
/// a route out (`internal: true`) has no internet either. podup gives
/// `network_mode` precedence over `networks:`, so a service cannot carry
/// both.
pub(in crate::cli::init) const CERTS_NETWORK_MODE: &str = "pasta:--no-map-gw,--map-guest-addr,none";

/// The directory both services share: the pair and the renewal request
/// files under `<data_dir>/acme`.
pub(in crate::cli::init) fn pair_dir(data_dir: &Path) -> PathBuf {
	crate::acme::renew::pair_dir(data_dir)
}

/// The directory the TLSA retry state lives in, which only `certs` writes
/// once it publishes.
pub(in crate::cli::init) fn tlsa_state_dir(data_dir: &Path) -> PathBuf {
	let state = crate::dns::tlsa::state_path(data_dir);
	state.parent().map_or(state.clone(), Path::to_path_buf)
}

/// What `mail` sees read-only, mounted over its read-write data_dir: every
/// directory under data_dir that `certs` reads or that decides what `certs`
/// does. `certs` acts on nothing the process that takes SMTP can write.
///
/// - the pair and the renewal request files (`<data_dir>/acme`), so `mail`
///   can neither replace the certificate nor ask for an order;
/// - the TLSA retry state, which `certs` publishes and withdraws from;
/// - the generated compose file, which says which container holds the DNS
///   credential and the account key and which `stack update` renders again.
pub(super) fn read_only_in_mail(data_dir: &Path) -> Vec<VolumeMount> {
	[
		pair_dir(data_dir),
		tlsa_state_dir(data_dir),
		compose_dir(data_dir),
	]
	.iter()
	.map(|dir| VolumeMount::bind(dir, dir, true))
	.collect()
}

/// The directory of the generated compose file.
pub(in crate::cli::init) fn compose_dir(data_dir: &Path) -> PathBuf {
	let compose = crate::cli::init::compose_file_path(data_dir);
	compose.parent().map_or(compose.clone(), Path::to_path_buf)
}

impl ComposeService {
	/// Build the `certs` service. Same image, entrypoint, user and user
	/// namespace as `mail`, so the files it writes are owned the way `mail`
	/// reads them; [`CERTS_NETWORK_MODE`] for the CA and the provider API and
	/// no route to the host, with no port published; the root file system
	/// read-only and every capability dropped.
	pub(in crate::cli::init::compose) fn new_certs(image: &str, answers: &Answers) -> Self {
		let config_path = &answers.config_path;
		let data_dir = &answers.data_dir;
		let config_dir = config_path.parent().unwrap_or_else(|| Path::new("/"));
		let mut volumes = vec![
			VolumeMount::bind(config_dir, config_dir, true),
			VolumeMount::bind(&pair_dir(data_dir), &pair_dir(data_dir), false),
			VolumeMount::bind(&tlsa_state_dir(data_dir), &tlsa_state_dir(data_dir), false),
		];
		let mut environment = BTreeMap::new();
		environment.insert("TZ".to_string(), "UTC".to_string());
		add_dns_credentials(answers, &mut volumes, &mut environment);
		if answers.image.is_none() {
			volumes.push(VolumeMount::bind_system_binary(
				Path::new(HOST_EPISTLE_PATH),
				Path::new(HOST_EPISTLE_PATH),
			));
		}
		let account_key = crate::cli::init::host_secrets::acme_account_key(data_dir);
		Self {
			image: image.to_string(),
			entrypoint: answers
				.image
				.is_none()
				.then(|| vec![HOST_EPISTLE_PATH.to_string()]),
			command: Some(serve_command(config_path, Some("certs"))),
			network_mode: Some(CERTS_NETWORK_MODE.to_string()),
			user: Some("65532:65532".to_string()),
			userns_mode: Some("keep-id:uid=65532,gid=65532".to_string()),
			volumes,
			ports: None,
			environment,
			restart: "unless-stopped".to_string(),
			stop_grace_period: None,
			security_opt: vec!["no-new-privileges".to_string()],
			cap_drop: drop_all(),
			cap_add: None,
			read_only: Some(true),
			tmpfs: None,
			sysctls: None,
			mem_limit: None,
			pids_limit: None,
			ulimits: None,
			// Read-only at its host path: the role reads it there, and a key
			// it cannot write is a key it cannot replace.
			secrets: Some(vec![SecretMount {
				source: ACME_ACCOUNT_SECRET.to_string(),
				target: account_key.display().to_string(),
				uid: "65532".to_string(),
				gid: "65532".to_string(),
				mode: DATABASE_SECRET_MODE,
			}]),
			configs: None,
			// `mail` never waits for it: with `certs` down the certificate in
			// service stays until it expires.
			depends_on: None,
			healthcheck: None,
		}
	}
}
