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

/// `mail`'s view of the pair: the same directory, read-only, mounted over
/// the read-write data_dir so the process that takes SMTP cannot replace
/// the certificate or leave a renewal request.
pub(super) fn pair_read_only(data_dir: &Path) -> VolumeMount {
	let dir = pair_dir(data_dir);
	VolumeMount::bind(&dir, &dir, true)
}

impl ComposeService {
	/// Build the `certs` service. Same image, entrypoint, user and user
	/// namespace as `mail`, so the files it writes are owned the way `mail`
	/// reads them; `pasta` for the CA and the provider API, with no port
	/// published; the root file system read-only and every capability
	/// dropped.
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
			network_mode: Some("pasta".to_string()),
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
