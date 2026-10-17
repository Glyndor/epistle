//! The local half of the password check: the primary password with its TOTP
//! second factor, then the account's app passwords. LDAP and the account
//! rules that apply to every proof live in `directory_bans.rs` and
//! `directory_gate.rs`.

use std::borrow::Cow;

use super::Directory;

impl Directory {
	/// The local credential path: primary password (with TOTP when set), then the
	/// account's app passwords. `None` when the login is unknown locally or no
	/// local secret matches. Split out so [`Directory::authenticate_with_ip`] can
	/// fall back to LDAP afterwards. Returns `(account, Option<label>)`:
	/// `label` is `Some` only when the credential that authenticated is an
	/// app password; primary-password logins return `None` so callers
	/// looking up per-credential overrides fall through to the
	/// account-wide default.
	pub(super) fn authenticate_local(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
	) -> Option<(String, Option<String>)> {
		let (account, hash) = self.credentials(login)?;
		// Disabled check runs after the credential lookup (which lowercases the
		// bare-login path) but before any hashing — argon2id and SCRAM are both
		// skipped, which is the whole point. Lookup is O(1); the disabled set
		// is small in practice.
		if self.disabled.contains(&account) {
			return None;
		}
		// TOTP applies to the primary password only; strip and verify the code.
		let primary = match self.totp.get(&account) {
			Some(secret) => self.totp_strip(password, secret),
			None => Some(password),
		};
		// Compare in the form the storage layer hashed: NFKC under the
		// Unicode policy, as given otherwise. No length or character check
		// here: a stored hash can predate the current rules.
		let prepared: Cow<str> = match primary {
			Some(candidate) => self.password_policy.login_form(candidate),
			None => Cow::Borrowed(""),
		};
		if !prepared.is_empty() && crate::smtp::auth::verify_password(hash, &prepared) {
			self.maybe_upgrade_scram(&account, &prepared);
			return Some((account, None));
		}
		// Primary failed (or its TOTP did): try the account's app passwords. App
		// passwords are not subject to TOTP — they are independent secrets.
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		for app in self
			.app_passwords
			.get(&account)
			.map(Vec::as_slice)
			.unwrap_or(&[])
		{
			if app.admits(password, &self.password_policy, ip, now) {
				return Some((account.clone(), Some(app.label.clone())));
			}
		}
		None
	}

	/// Strip and verify the trailing 6-digit TOTP code from `password`, returning
	/// the remaining password on success, or `None` if the code is missing or
	/// wrong.
	fn totp_strip<'a>(&self, password: &'a str, secret: &str) -> Option<&'a str> {
		// `str::split_at` panics when its index is not on a UTF-8 character
		// boundary. Splitting by byte length is only safe when the trailing
		// six bytes are ASCII digits: a digit is a single-byte character that
		// cannot be a continuation byte, so the byte before them ends a
		// character by construction. This keeps the split safe for non-ASCII
		// passwords, which the policy is about to admit.
		let bytes = password.as_bytes();
		if bytes.len() < 7 || !bytes[bytes.len() - 6..].iter().all(u8::is_ascii_digit) {
			return None;
		}
		let split = bytes.len() - 6;
		let (pass, code) = password.split_at(split);
		let code: u32 = code.parse().ok()?;
		let secret_bytes = crate::totp::decode_base32_secret(secret)?;
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		crate::totp::verify(&secret_bytes, code, now).then_some(pass)
	}
}
