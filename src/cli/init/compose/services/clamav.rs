//! The `clamav` service: the signature updater, or the scanning daemon.

use std::collections::BTreeMap;
use std::path::Path;

use super::{ComposeService, Healthcheck, VolumeMount, drop_all};
use crate::cli::init::compose::Answers;

/// Signature checks per day when the answers say nothing: the number the
/// ClamAV documentation gives as its default, so a signature is hours old, not a day.
const DEFAULT_FRESHCLAM_CHECKS: u8 = 12;
/// The most checks per day `freshclam --checks` takes, which is what the
/// signature servers allow one client.
pub(in crate::cli::init) const MAX_FRESHCLAM_CHECKS: u8 = 50;

/// The shell line the updater runs. The image's `freshclam.conf` has
/// `NotifyClamd`, which dials `clamd` on its own socket, and `clamd` runs in
/// another container with no socket in common, so every update logged
/// `Clamd was NOT notified`. The line drops that one option from a copy and
/// runs `freshclam` on the copy; `clamd` reloads the databases by itself at
/// its `SelfCheck` interval (600 seconds in the generated `clamd.conf`).
fn freshclam_script(checks: u8) -> String {
	format!(
		"grep -v '^NotifyClamd' /etc/clamav/freshclam.conf > /var/log/clamav/freshclam.conf \
		 && exec freshclam --config-file=/var/log/clamav/freshclam.conf \
		 --daemon --foreground --stdout --checks={checks}"
	)
}

impl ComposeService {
	pub(in crate::cli::init::compose) fn new_clamav(answers: &Answers, freshclam: bool) -> Self {
		let mut service = Self {
			image: crate::cli::init::images::clamav().to_string(),
			entrypoint: None,
			command: None,
			network_mode: Some(if freshclam { "pasta" } else { "none" }.to_string()),
			user: None,
			userns_mode: None,
			volumes: vec![VolumeMount::Named("clamav-db:/var/lib/clamav".to_string())],
			ports: None,
			environment: BTreeMap::new(),
			restart: "unless-stopped".to_string(),
			stop_grace_period: None,
			security_opt: vec!["no-new-privileges".to_string()],
			cap_drop: drop_all(),
			cap_add: None,
			read_only: Some(true),
			tmpfs: None,
			mem_limit: None,
			pids_limit: None,
			ulimits: None,
			sysctls: None,
			secrets: None,
			configs: None,
			depends_on: None,
			healthcheck: None,
		};
		if freshclam {
			// The image's /init chowns the database volume and creates
			// /run/clamav as root before it starts freshclam with
			// `--user=clamav`. Running the daemon as clamav (uid 100, gid
			// 101 in the image) from the start needs no capability: the
			// database volume is clamav's, from the image or from earlier
			// starts. tini stays PID 1, as under /init, so SIGTERM reaches
			// freshclam and its children are reaped.
			service.user = Some("100:101".to_string());
			// UpdateLogFile in the image's freshclam.conf. The tmpfs root is
			// root's unless its mode opens it, and freshclam runs as clamav.
			// The log stops growing at LogFileMaxSize (1 MiB by default).
			service.tmpfs = Some(vec!["/var/log/clamav:size=16m,mode=1777".to_string()]);
			let checks = answers
				.services
				.freshclam_checks
				.unwrap_or(DEFAULT_FRESHCLAM_CHECKS);
			service.entrypoint = Some(
				["/sbin/tini", "--", "/bin/sh", "-c"]
					.map(str::to_string)
					.into_iter()
					.chain([freshclam_script(checks)])
					.collect(),
			);
		} else {
			service
				.environment
				.insert("CLAMAV_NO_FRESHCLAMD".to_string(), "true".to_string());
			// Measured under `cap_drop: [ALL]`, one failure per line: chown
			// of /run/clamav (CHOWN), chmod of the now clamav-owned
			// directory (FOWNER), and clamd's own step down to `User
			// clamav`, which failed in initgroups() (SETGID, SETUID).
			// clamd's TemporaryDirectory: every INSTREAM body and every
			// archive member it extracts lands here while it is scanned.
			service.tmpfs = Some(vec!["/tmp:size=512m,mode=1777".to_string()]);
			service.cap_add = Some(
				["CHOWN", "FOWNER", "SETGID", "SETUID"]
					.map(str::to_string)
					.to_vec(),
			);
			service
				.volumes
				.push(VolumeMount::Named("clamd-socket:/run/clamav".to_string()));
			service.volumes.push(VolumeMount::bind(
				&answers.data_dir.join("compose/clamd.conf"),
				Path::new("/etc/clamav/epistle-clamd.conf"),
				true,
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
