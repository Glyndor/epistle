//! Credentials of the people and programs that sign in.

use super::{Entry, Handling};

pub(super) const ENTRIES: &[Entry] = &[
	Entry {
		id: "api-key",
		name: "Management API keys and the static API token",
		stored_in: "`api_keys.toml` (sha256 digests) and `[api] token_hash`",
		config_fields: &["Api.token_hash"],
		rotate: Handling::Epistle(
			"`epistle rotate --all` gives every key a new secret and prints it once, `epistle api-key rotate LABEL` one key; the static token is replaced by hand (`epistle token-hash`)",
		),
		revoke: Handling::Epistle("`epistle api-key revoke LABEL`, one key at a time"),
		operator_after: &["hand each client its new key; it is shown once"],
	},
	Entry {
		id: "app-password",
		name: "App passwords",
		stored_in: "`app_passwords.toml` (argon2id)",
		config_fields: &[],
		rotate: Handling::Epistle(
			"`epistle rotate --all` gives every app password a new secret and prints it once, `epistle app-password rotate N LABEL` one",
		),
		revoke: Handling::Epistle("`epistle app-password revoke N LABEL`, one at a time"),
		operator_after: &["update every client that used the old secret"],
	},
	Entry {
		id: "account-password",
		name: "Account passwords",
		stored_in: "`accounts.toml` (argon2id and SCRAM verifier) and `[[accounts]] password_hash`",
		config_fields: &["Account.password_hash"],
		rotate: Handling::Epistle(
			"`epistle rotate --all` (or `epistle rotate --accounts-only`) resets the password of every account in `accounts.toml`, and it signs in nowhere until an administrator sets a new one with `epistle account password N`; a static `[[accounts]] password_hash` is replaced in the file",
		),
		revoke: Handling::Epistle(
			"`epistle rotate --accounts-only` refuses every sign-in of every account in `accounts.toml` at once, `epistle account disable N` one account",
		),
		operator_after: &["tell every user to choose a new password"],
	},
	Entry {
		id: "account-totp-secret",
		name: "Second-factor (TOTP) secrets of the accounts",
		stored_in: "`accounts.toml`, sealed with the storage key when storage encryption is on",
		config_fields: &[],
		rotate: Handling::Epistle(
			"`epistle rotate --all` (or `epistle rotate --accounts-only`) deletes every secret, and an account that had one signs in again only once a new one is enrolled, or the second factor is removed on purpose with `epistle account 2fa disable N`",
		),
		revoke: Handling::Epistle(
			"`epistle rotate --accounts-only` for every account, `epistle account 2fa disable N` for one",
		),
		operator_after: &["tell every user to enrol their authenticator again"],
	},
	Entry {
		id: "totp-seed-in-clear",
		name: "TOTP seeds stored in the clear while storage encryption is off",
		stored_in: "`accounts.toml`, `totp_secret` as plain base32 when `[storage]` has no key",
		config_fields: &[],
		rotate: Handling::Epistle(
			"`epistle rotate --all` deletes every seed with the reset of the accounts; turn on `[storage]` encryption so the new ones are sealed",
		),
		revoke: Handling::Epistle(
			"`epistle rotate --accounts-only`: a seed in a stolen copy stops working once its account is reset",
		),
		operator_after: &[
			"treat every copy of `accounts.toml` taken while encryption was off as holding the seeds",
		],
	},
];
