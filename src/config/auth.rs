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
#[derive(Debug, Clone, Default, Deserialize)]
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
