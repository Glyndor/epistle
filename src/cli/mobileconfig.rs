//! `mail mobileconfig`: emit an Apple `.mobileconfig` configuration profile for
//! an account, so an iOS/macOS user can auto-configure Mail by installing it
//! (the profile is distributed to the user, e.g. emailed or downloaded — the
//! server does not host it).

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

/// Write the profile for `account` to `out`. IMAP over implicit TLS (993) and
/// submission over STARTTLS (587), both authenticated with the account address.
pub(super) fn run(config: &Config, account: &str, out: &mut impl std::io::Write) -> ExitCode {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			eprintln!("error: opening account store: {error}");
			return ExitCode::FAILURE;
		}
	};
	let Some((_, addresses, _)) = store
		.account_views()
		.into_iter()
		.find(|(name, _, _)| name == account)
	else {
		eprintln!("error: no such account \"{account}\"");
		return ExitCode::FAILURE;
	};
	let Some(email) = addresses.first() else {
		eprintln!("error: account \"{account}\" has no address");
		return ExitCode::FAILURE;
	};

	let profile = build_profile(account, email, &config.hostname);
	if out.write_all(profile.as_bytes()).is_err() {
		eprintln!("error: writing profile");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

/// Build the `.mobileconfig` plist (Apple `com.apple.mail.managed` payload).
fn build_profile(account: &str, email: &str, hostname: &str) -> String {
	let account = escape(account);
	let email = escape(email);
	let host = escape(hostname);
	// Stable UUIDs derived from the address keep reinstalls idempotent (an
	// updated profile replaces the prior one rather than duplicating it).
	let payload_uuid = stable_uuid(&email);
	let profile_uuid = stable_uuid(&format!("{email}/profile"));
	format!(
		r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>EmailAccountDescription</key><string>{host}</string>
			<key>EmailAccountName</key><string>{account}</string>
			<key>EmailAccountType</key><string>EmailTypeIMAP</string>
			<key>EmailAddress</key><string>{email}</string>
			<key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
			<key>IncomingMailServerHostName</key><string>{host}</string>
			<key>IncomingMailServerPortNumber</key><integer>993</integer>
			<key>IncomingMailServerUseSSL</key><true/>
			<key>IncomingMailServerUsername</key><string>{email}</string>
			<key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
			<key>OutgoingMailServerHostName</key><string>{host}</string>
			<key>OutgoingMailServerPortNumber</key><integer>587</integer>
			<key>OutgoingMailServerUseSSL</key><true/>
			<key>OutgoingMailServerUsername</key><string>{email}</string>
			<key>OutgoingPasswordSameAsIncoming</key><true/>
			<key>PayloadType</key><string>com.apple.mail.managed</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>PayloadIdentifier</key><string>net.glyndor.epistle.mail.{payload_uuid}</string>
			<key>PayloadUUID</key><string>{payload_uuid}</string>
			<key>PayloadDisplayName</key><string>{email}</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key><string>{host} mail ({email})</string>
	<key>PayloadIdentifier</key><string>net.glyndor.epistle.{profile_uuid}</string>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>{profile_uuid}</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
	)
}

/// A deterministic UUID from a SHA-256 of `seed` (avoids a per-run random id so
/// reinstalling the profile updates it in place).
fn stable_uuid(seed: &str) -> uuid::Uuid {
	let digest = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
	let mut bytes = [0u8; 16];
	bytes.copy_from_slice(&digest.as_ref()[..16]);
	uuid::Uuid::from_bytes(bytes)
}

/// Escape the five XML special characters for safe interpolation into the plist.
fn escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

#[cfg(test)]
#[path = "mobileconfig_tests.rs"]
mod tests;
