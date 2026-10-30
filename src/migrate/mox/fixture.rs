//! A small, realistic Mox configuration for the tests: two domains (one
//! internationalised), DKIM keys the way `mox quickstart` writes them, an
//! alias, a catch-all and an account whose name epistle cannot store.

use std::path::Path;

use crate::migrate::import::tests::test_keys;

/// `mox.conf`, trimmed to what a quickstart writes at the top.
pub(crate) const MOX_CONF: &str = "\
DataDir: ../data
LogLevel: info
Hostname: mail.example.com
AdminPasswordFile: adminpasswd
Postmaster:
	Account: alice
	Mailbox: Postmaster
Listeners:
	public:
		IPs:
			- 0.0.0.0
			- ::
		SMTP:
			Enabled: true
		IMAPS:
			Enabled: true
";

/// `domains.conf`.
pub(crate) const DOMAINS_CONF: &str = "\
# Domains and accounts, written by mox quickstart and edited by hand.
Domains:
	example.com:
		Description: main domain
		LocalpartCatchallSeparator: +
		DKIM:
			Selectors:
				2024a:
					Hash: sha256
					DontSealHeaders: false
					Headers:
						- From
						- To
						- Subject
					PrivateKeyFile: dkim/2024a._domainkey.example.com.ed25519.privatekey.pkcs8.pem
				2024b:
					Hash: sha256
					PrivateKeyFile: dkim/2024b._domainkey.example.com.rsa2048.privatekey.pkcs8.pem
				2023old:
					Hash: sha256
					PrivateKeyFile: dkim/2023old.pem
			Sign:
				- 2024a
				- 2024b
		Aliases:
			team:
				Addresses:
					- alice@example.com
					- bob@example.com
				PostPublic: true
				ListMembers: true
				AllowMsgFrom: true
		DMARC:
			Localpart: dmarc-reports
			Account: alice
			Mailbox: DMARC
	bücher.example:
		DKIM:
			Selectors:
				2024a:
					PrivateKeyFile: dkim/2024a._domainkey.bucher.ed25519.pem
			Sign:
				- 2024a
Accounts:
	alice:
		Domain: example.com
		FullName: Alice Liddell
		Destinations:
			alice@example.com: nil
			postmaster@example.com:
				Mailbox: Postmaster
	bob:
		Domain: example.com
		Destinations:
			bob@example.com: nil
			@example.com: nil
			info@bücher.example:
				Mailbox: Info
				FullName: Bob Builder
		LoginDisabled: account suspended
	Mail Admin:
		Domain: example.com
		Destinations:
			admin@example.com: nil
";

/// The private keys the fixture points at, as written to disk.
pub(crate) struct Written {
	/// The ed25519 key of example.com (PKCS#8 v1 PEM, as Mox writes it).
	pub(crate) ed25519: String,
	/// The RSA key of example.com.
	pub(crate) rsa: String,
	/// The ed25519 key of bücher.example.
	pub(crate) other: String,
}

/// Write the fixture into `dir`.
pub(crate) fn write(dir: &Path) -> Written {
	std::fs::write(dir.join("mox.conf"), MOX_CONF).expect("mox.conf");
	std::fs::write(dir.join("domains.conf"), DOMAINS_CONF).expect("domains.conf");
	std::fs::create_dir_all(dir.join("dkim")).expect("dkim dir");
	let written = Written {
		ed25519: test_keys::ed25519_v1().0,
		rsa: test_keys::rsa_pkcs8_pem().to_string(),
		other: test_keys::ed25519_v1().0,
	};
	for (file, pem) in [
		(
			"2024a._domainkey.example.com.ed25519.privatekey.pkcs8.pem",
			&written.ed25519,
		),
		(
			"2024b._domainkey.example.com.rsa2048.privatekey.pkcs8.pem",
			&written.rsa,
		),
		("2024a._domainkey.bucher.ed25519.pem", &written.other),
		("2023old.pem", &written.other),
	] {
		std::fs::write(dir.join("dkim").join(file), pem).expect("key");
	}
	written
}
