//! Credentials of the people and programs that sign in.

use super::{Entry, Handling, TRACKING_ISSUE};

pub(super) const ENTRIES: &[Entry] = &[
	Entry {
		id: "api-key",
		name: "Management API keys and the static API token",
		stored_in: "`api_keys.toml` (sha256 digests) and `[api] token_hash`",
		config_fields: &["Api.token_hash"],
		rotate: Handling::Epistle(
			"`epistle api-key rotate LABEL`, one key at a time; the static token is replaced by hand (`epistle token-hash`)",
		),
		revoke: Handling::Epistle("`epistle api-key revoke LABEL`, one key at a time"),
		operator_after: &["hand each client its new key; it is shown once"],
	},
	Entry {
		id: "app-password",
		name: "App passwords",
		stored_in: "`app_passwords.toml` (argon2id)",
		config_fields: &[],
		rotate: Handling::Epistle("`epistle app-password rotate N LABEL`, one at a time"),
		revoke: Handling::Epistle("`epistle app-password revoke N LABEL`, one at a time"),
		operator_after: &["update every client that used the old secret"],
	},
	Entry {
		id: "account-password",
		name: "Account passwords",
		stored_in: "`accounts.toml` (argon2id and SCRAM verifier) and `[[accounts]] password_hash`",
		config_fields: &["Account.password_hash"],
		rotate: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "`epistle account password N` for one account at a time; a static `[[accounts]] password_hash` is replaced in the file",
		},
		revoke: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "`epistle account disable N` blocks one account at a time",
		},
		operator_after: &["tell every user to choose a new password"],
	},
	Entry {
		id: "account-totp-secret",
		name: "Second-factor (TOTP) secrets of the accounts",
		stored_in: "`accounts.toml`, sealed with the storage key when storage encryption is on",
		config_fields: &[],
		rotate: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "delete the secret of one account (`epistle account 2fa disable N`) and have its user enrol again",
		},
		revoke: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "`epistle account 2fa disable N` for one account at a time",
		},
		operator_after: &["tell every user to enrol their authenticator again"],
	},
	Entry {
		id: "totp-seed-in-clear",
		name: "TOTP seeds stored in the clear while storage encryption is off",
		stored_in: "`accounts.toml`, `totp_secret` as plain base32 when `[storage]` has no key",
		config_fields: &[],
		rotate: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "turn on `[storage]` encryption so seeds are sealed, and keep copies of `accounts.toml` off the host; anyone holding a copy can forge codes",
		},
		revoke: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "a seed in a stolen copy stays valid until its account enrols again",
		},
		operator_after: &[
			"treat every copy of `accounts.toml` taken while encryption was off as holding the seeds",
		],
	},
];
