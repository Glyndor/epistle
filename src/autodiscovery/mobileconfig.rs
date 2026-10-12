//! Apple `.mobileconfig` configuration profile (`com.apple.mail.managed`).
//!
//! Shared by the `mail mobileconfig` CLI command and the `/mobileconfig`
//! endpoint of the autoconfig listener. The profile is unsigned and never
//! carries a password: Mail asks for it when the profile is installed.

use super::escape;

/// Build the `.mobileconfig` plist for `email`: IMAP over implicit TLS (993)
/// and submission over STARTTLS (587), both authenticated with the address.
/// `display_name` fills `EmailAccountName`.
pub fn profile(display_name: &str, email: &str, hostname: &str) -> String {
	let name = escape(display_name);
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
			<key>EmailAccountName</key><string>{name}</string>
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
