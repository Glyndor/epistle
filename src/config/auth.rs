//! Authentication toggles (`[auth]`).
//!
//! Two knobs:
//!
//! - `scram = true` (default) enables SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
//!   advertisement and verifier derivation. Setting it to `false` hides the
//!   mechanism from SMTP EHLO AUTH, IMAP `CAPABILITY AUTH=`, and ManageSieve
//!   `SASL`; rejects `AUTHENTICATE`/`AUTH` against it like any other unknown
//!   mechanism; and stops every account-create and password-change path from
//!   deriving or storing a verifier. The next password change of an account
//!   that already has a verifier drops it (the password-mutator passes `None`
//!   for `scram` when the config flag is off).
//!
//! - `unicode_passwords = false` (default) keeps the historical ASCII-only
//!   password policy; setting it to `true` lets the policy accept any
//!   non-control Unicode scalar and normalises with NFKC on both set and
//!   verify (RFC 8265 OpaqueString), so a password set with one keyboard
//!   verifies from another. Older IMAP/POP clients that mangle non-ASCII
//!   in AUTH PLAIN/LOGIN still get a working session — the SASL mechanisms
//!   are the wire path, the password policy is independent of them — but
//!   their on-the-wire behaviour may not match a non-ASCII password they
//!   set, so enabling the flag is an operator decision; see the
//!   authentication section of `docs/security.md` for the caveat.

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
	/// Accept Unicode passwords and normalise them with NFKC on both set
	/// and verify, so a password set with one keyboard verifies from
	/// another. Default `false` keeps the historical ASCII-only policy
	/// (the policy is tighter than the length floor; older IMAP/POP
	/// clients that mangle non-ASCII in AUTH PLAIN/LOGIN still match the
	/// wire bytes when the password is ASCII). Operators that need
	/// non-ASCII passwords (international passphrases, a credential
	/// manager that prefers Unicode) opt in here, knowing their clients
	/// must normalise consistently — the SCRAM auth path RFC 5802 /
	/// RFC 7677 clients use already do SASLprep (NFKC) on the supplied
	/// credential, so SCRAM-SHA-256 with a non-ASCII password works
	/// without further config.
	#[serde(default = "default_unicode_passwords")]
	pub unicode_passwords: bool,
}

fn default_scram() -> bool {
	true
}

fn default_unicode_passwords() -> bool {
	false
}

/// Written out instead of derived: `Config` falls back to this when the
/// `[auth]` section is absent, and a derived `Default` would set `scram`
/// to `false`, turning SCRAM off for every config that never mentions it.
impl Default for Auth {
	fn default() -> Self {
		Auth {
			scram: default_scram(),
			unicode_passwords: default_unicode_passwords(),
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
	fn a_config_without_an_auth_section_keeps_unicode_passwords_off() {
		// The historical default must be preserved when the [auth] section
		// is absent: existing configs do not get a new flag turned on.
		assert!(
			!load("").expect("load").auth.unicode_passwords,
			"an absent [auth] section must keep the ASCII-only policy"
		);
	}

	#[test]
	fn unicode_passwords_true_opt_in_is_accepted() {
		assert!(
			load("[auth]\nunicode_passwords = true\n")
				.expect("load")
				.auth
				.unicode_passwords
		);
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
