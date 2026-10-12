//! Authentication toggles (`[auth]`).
//!
//! Single knob today: `scram = true` (default) enables SCRAM-SHA-256 and
//! SCRAM-SHA-256-PLUS advertisement and verifier derivation. Setting it to
//! `false` hides the mechanism from SMTP EHLO AUTH, IMAP `CAPABILITY
//! AUTH=`, and ManageSieve `SASL`; rejects `AUTHENTICATE`/`AUTH` against
//! it like any other unknown mechanism; and stops every account-create
//! and password-change path from deriving or storing a verifier. The
//! next password change of an account that already has a verifier drops
//! it (the password-mutator passes `None` for `scram` when the config
//! flag is off).

use serde::Deserialize;

/// The `[auth]` configuration section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
	/// Whether SCRAM-SHA-256 / SCRAM-SHA-256-PLUS is offered and a SCRAM
	/// verifier is derived for newly-set passwords. Defaults to `true`.
	/// Disabling hides the mechanisms on the wire (no SMTP AUTH, no IMAP
	/// `AUTH=`, no ManageSieve `SASL`), refuses an explicit
	/// `AUTHENTICATE`/`AUTH` with them, and prevents account-create and
	/// password-change paths from writing a verifier. The first password
	/// change after the flag flips drops an existing verifier.
	#[serde(default = "default_scram")]
	pub scram: bool,
}

fn default_scram() -> bool {
	true
}

/// Written out instead of derived: `Config` falls back to this when the
/// `[auth]` section is absent, and a derived `Default` would set `scram`
/// to `false`, turning SCRAM off for every config that never mentions it.
impl Default for Auth {
	fn default() -> Self {
		Auth {
			scram: default_scram(),
		}
	}
}

#[cfg(test)]
mod tests {
	/// Load a minimal `mail.toml` with `extra` appended.
	fn load(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
		use std::os::unix::fs::PermissionsExt;
		let dir = tempfile::tempdir().expect("tempdir");
		let path = dir.path().join("mail.toml");
		std::fs::write(
			&path,
			format!(
				"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n{extra}",
				dir.path()
			),
		)
		.expect("write config");
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
		crate::config::Config::load(&path)
	}

	#[test]
	fn a_config_without_an_auth_section_keeps_scram_on() {
		assert!(
			load("").expect("load").auth.scram,
			"an absent [auth] section must keep SCRAM enabled"
		);
	}

	#[test]
	fn an_empty_auth_section_keeps_scram_on() {
		assert!(load("[auth]\n").expect("load").auth.scram);
	}

	#[test]
	fn scram_false_turns_it_off() {
		assert!(!load("[auth]\nscram = false\n").expect("load").auth.scram);
	}

	#[test]
	fn an_unknown_auth_key_fails_the_load() {
		let error = load("[auth]\nscram = true\nsrcam = false\n").expect_err("unknown key");
		assert!(
			error.to_string().contains("srcam"),
			"the error must name the unknown key, got: {error}"
		);
	}
}
