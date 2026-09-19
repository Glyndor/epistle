//! Pins for the `hold_outbound` flag and the `start_queue_worker` decision.
//!
//! `hold_outbound` is the internal switch `epistle local` sets to keep the
//! test harness from opening outbound SMTP connections. The field is
//! `#[serde(skip)]`, so `Config::load` cannot produce `true` from a TOML
//! file: any `hold_outbound = ...` line is rejected as an unknown key by
//! `deny_unknown_fields`. `start_queue_worker` is the pure decision
//! `serve` consults before spawning the queue worker; both pins live
//! here at the config layer so the `cli::local` test can focus on the
//! integration without re-asserting the underlying rule.

use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::config::Config;

/// Pin: an ordinary config (no `hold_outbound`) reports
/// `start_queue_worker() == true`. The default is the production
/// behaviour: the queue worker drains the outbound spool.
#[test]
fn start_queue_worker_is_true_for_an_ordinary_config() {
	let body = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
	let config: Config = toml::from_str(body).expect("ordinary config parses");
	assert!(
		config.start_queue_worker(),
		"ordinary config must start the queue worker"
	);
	assert!(
		!config.hold_outbound,
		"ordinary config must have hold_outbound == false"
	);
}

/// Pin: a `mail.toml` carrying `hold_outbound = true` is rejected by
/// `Config::load` as an unknown field. The flag is internal to
/// `Config`; the only way to set it is programmatically, and the
/// harness is the only caller that does.
#[test]
fn hold_outbound_in_toml_is_rejected_as_unknown_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&path).expect("create");
	file.write_all(
		b"hostname = \"mail.local.test\"\ndata_dir = \"/tmp/never-read\"\nhold_outbound = true\n",
	)
	.expect("write");
	drop(file);
	#[cfg(unix)]
	{
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0600");
	}
	let result = Config::load(&path);
	assert!(
		matches!(result, Err(crate::config::ConfigError::Parse { .. })),
		"hold_outbound in TOML must be rejected as an unknown field, got {result:?}"
	);
}
