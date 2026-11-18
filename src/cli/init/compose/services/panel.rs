//! The `panel` service: the web panel the `epistle-panel` package brings.
//!
//! The package ships no application code. It installs one file holding the
//! image reference of the panel release it belongs to, and this module renders
//! the service that runs it. The image is the panel's own: a Next.js standalone
//! server on `gcr.io/distroless/nodejs24-debian13`, running as uid 65532 with
//! no shell and no curl, listening on port 7587 (`EXPOSE 7587` in its
//! `Containerfile`).
//!
//! # The network
//!
//! The panel needs the management API, and the API is closed to the network by
//! design: the listener `init` writes binds `127.0.0.1` **inside** the mail
//! container (`API_BIND_ADDR` in `src/cli/init/apply/apply_config/mod.rs`), so
//! the pasta mapping does not reach it and it gets no `ports:` entry.
//!
//! Measured on Podman 5.7.0 rootless on 2026-11-14, a container in a pasta
//! instance of its own reaches:
//!
//! - nothing of the host on `127.0.0.1`;
//! - nothing of the host on the host's own address;
//! - only the host services bound on the wildcard, through the alias
//!   `169.254.1.2` that podman maps by default;
//! - nothing at all with `pasta:--no-map-gw,--map-guest-addr,none`, the
//!   network the `certs` service uses.
//!
//! pasta also refuses to remap the host's loopback (`Invalid address to remap
//! to host: 127.0.0.1`), so a container of its own cannot reach an API that
//! only listens on the container's loopback. What is left is the namespace the
//! API listens in: the panel runs in the mail container's namespace with
//! `network_mode: "service:mail"`, which podman resolves to
//! `container:<mail>` and podup to the same, with the start-order dependency
//! it derives from it.
//!
//! The panel therefore reaches the management API on the container's loopback
//! and nothing else of the host's own services. It shares the mail listeners
//! of the same server, which the host publishes anyway, and the internet,
//! which the mail container's pasta already proxies.
//!
//! # The published port
//!
//! A container that shares another container's namespace cannot publish a port
//! of its own: podman drops the mapping (`Port mappings have been discarded
//! because "container" network namespace mode does not support them`,
//! measured). The owner of the namespace publishes it, so the mail service's
//! `ports:` array carries `127.0.0.1:7587:7587` while the panel runs, and the
//! address the operator gave it survives every re-render the way the other
//! publications do.
//!
//! The port is on the host's loopback because the panel serves plain HTTP:
//! TLS is the operator's reverse proxy, the same reason the API and WebDAV
//! are published on loopback.

use std::collections::BTreeMap;

use super::{ComposeService, DATABASE_SECRET_MODE, Healthcheck, SecretMount, drop_all};
use crate::config::{Listener, ListenerKind};

/// The port the panel's own server listens on, inside its container. Its
/// `Containerfile` sets `ENV PORT=7587` and `EXPOSE 7587`.
pub(in crate::cli::init) const PANEL_PORT: u16 = 7587;

/// The node binary of the panel's image. The runtime is distroless: no shell,
/// no curl, no wget, so the only probe that works is the runtime's own
/// `fetch`. Measured on the base image the panel builds from: the entrypoint
/// is `/nodejs/bin/node` and `/bin/sh` does not exist.
const NODE: &str = "/nodejs/bin/node";

/// The directory the three secrets are mounted at, inside the panel. The
/// panel's `_FILE` variables point at these paths, so nothing sensitive is in
/// the environment (a value there shows in `podman inspect`).
const SECRET_DIR: &str = "/run/secrets";

/// The compose secrets the panel reads, with the host path of each. The files
/// live in the host secrets directory beside `data_dir`, which `mail` (which
/// mounts `data_dir` read-write) and `epistle backup` (which archives it)
/// never hold.
pub(in crate::cli::init) const SECRETS: [(&str, super::super::KeyPath); 3] = [
	(
		"panel_api_token",
		super::super::panel_secrets::api_token_path,
	),
	(
		"panel_session_secret",
		super::super::panel_secrets::session_secret_path,
	),
	("panel_admin_id", super::super::panel_secrets::admin_id_path),
];

/// The port the management API answers on inside the mail container: the
/// listener's own port when the stack has one, and the schema default when
/// it does not. The listener carries no port of its own unless the operator
/// gave it one, and then the schema default is what `serve` binds.
pub(in crate::cli::init) fn api_port(listeners: &[Listener]) -> u16 {
	listeners
		.iter()
		.find(|listener| listener.kind == ListenerKind::Api)
		.map(|listener| {
			listener
				.port
				.unwrap_or_else(|| listener.kind.default_port())
		})
		.unwrap_or_else(|| ListenerKind::Api.default_port())
}

impl ComposeService {
	/// Build the `panel` service. The image is the reference the pin file
	/// named; `api_port` is the port the management API answers on inside the
	/// mail container, which is the namespace the panel shares.
	///
	/// The hardening is the mail service's: the root file system read-only,
	/// every capability dropped, `no-new-privileges`, the same uid and the
	/// same `keep-id` mapping, and a tmpfs `/tmp` for the runtime's scratch
	/// space (the root file system is read-only, and Node writes there).
	///
	/// The three secrets arrive as files: the API key, the session secret and
	/// the admin id. The panel reads each through its `_FILE` variable, and a
	/// missing file is an error the panel reports, never a fallback to a value
	/// in the environment.
	pub(in crate::cli::init::compose) fn new_panel(image: &str, api_port: u16) -> Self {
		let mut environment = BTreeMap::new();
		environment.insert(
			"EPISTLE_API_URL".to_string(),
			format!("http://127.0.0.1:{api_port}"),
		);
		environment.insert(
			"EPISTLE_API_TOKEN_FILE".to_string(),
			format!("{SECRET_DIR}/panel_api_token"),
		);
		environment.insert(
			"EPISTLE_PANEL_SESSION_SECRET_FILE".to_string(),
			format!("{SECRET_DIR}/panel_session_secret"),
		);
		environment.insert(
			"EPISTLE_PANEL_ADMIN_ID_FILE".to_string(),
			format!("{SECRET_DIR}/panel_admin_id"),
		);
		environment.insert("TZ".to_string(), "UTC".to_string());
		Self {
			image: image.to_string(),
			entrypoint: None,
			command: None,
			network_mode: Some("service:mail".to_string()),
			// The image's own user, and the same mapping the other services
			// use, so the uid the secrets are mounted under is the uid the
			// panel runs as.
			user: Some("65532:65532".to_string()),
			userns_mode: Some("keep-id:uid=65532,gid=65532".to_string()),
			volumes: Vec::new(),
			// The port belongs to the mail container, which owns the
			// namespace the panel runs in.
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
			secrets: Some(
				SECRETS
					.iter()
					.map(|(name, _)| SecretMount {
						source: (*name).to_string(),
						target: format!("{SECRET_DIR}/{name}"),
						uid: "65532".to_string(),
						gid: "65532".to_string(),
						mode: DATABASE_SECRET_MODE,
					})
					.collect(),
			),
			configs: None,
			// The mail container is already a dependency: it owns the
			// namespace the panel joins.
			depends_on: None,
			// The panel ships no healthcheck of its own: its runtime has no
			// shell, no curl and no wget, and a check would need a second
			// binary in the image. The probe is the runtime's own `fetch`
			// against the sign-in page, which the panel's `Containerfile`
			// names as the public page that answers 200 without a session.
			healthcheck: Some(Healthcheck {
				test: vec![
					"CMD".to_string(),
					NODE.to_string(),
					"-e".to_string(),
					format!(
						"fetch('http://127.0.0.1:{PANEL_PORT}/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
					),
				],
				interval: "30s".to_string(),
				timeout: "10s".to_string(),
				retries: 3,
				start_period: Some("30s".to_string()),
			}),
		}
	}
}
