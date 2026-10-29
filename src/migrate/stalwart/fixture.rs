//! A small Stalwart v0.15 `config.toml` for the tests: the listeners and
//! stores a fresh install writes, an in-config memory directory, and two
//! DKIM signatures (an inline PKCS#1 RSA key and an ed25519 key file).

use std::path::Path;

use crate::migrate::import::tests::test_keys;

/// The configuration, with `@RSA@` standing for the inline RSA key.
const CONFIG: &str = r#"
[server]
hostname = "mx.example.org"

[server.listener."smtp"]
bind = ["[::]:25"]
protocol = "smtp"

[server.listener."imaptls"]
bind = ["[::]:993"]
protocol = "imap"
tls.implicit = true

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "memory"

[store."rocksdb"]
type = "rocksdb"
path = "%{env:STALWART_PATH}%/data"

[directory."memory"]
type = "memory"

[[directory."memory".principals]]
class = "individual"
name = "john"
secret = "$6$fixture$not-a-real-hash"
description = "John Doe"
email = ["john@example.org", "j.doe@example.org"]
email-list = ["sales@example.org"]
member-of = ["support"]

[[directory."memory".principals]]
class = "admin"
name = "jane"
secret = "changeme-not-a-real-one"
email = ["jane@example.org", "@example.org"]
email-list = ["sales@example.org"]
member-of = ["staff"]

[[directory."memory".principals]]
class = "group"
name = "support"
email = ["support@example.org"]

[[directory."memory".principals]]
class = "individual"
name = "nobody"

[signature."rsa-example.org"]
private-key = """@RSA@"""
domain = "example.org"
selector = "202401r"
headers = ["From", "To", "Date", "Subject", "Message-ID"]
algorithm = "rsa-sha256"
canonicalization = "relaxed/relaxed"
set-body-length = false
report = true

[signature."ed25519-example.org"]
private-key = "%{file:dkim/example.org.ed25519.pem}%"
domain = "example.org"
selector = "202401e"
algorithm = "ed25519-sha256"

[signature."from-env"]
private-key = "%{env:DKIM_KEY}%"
domain = "example.org"
selector = "envkey"
algorithm = "ed25519-sha256"

[auth.dkim]
sign = [ { if = "is_local_domain('', sender_domain)", then = "['rsa-' + sender_domain, 'ed25519-' + sender_domain]" }, { else = false } ]
"#;

/// The keys the fixture holds.
pub(crate) struct Written {
	/// The PKCS#1 RSA PEM written inline.
	pub(crate) rsa: String,
	/// The ed25519 PEM in the key file.
	pub(crate) ed25519: String,
}

/// Write `config.toml` and its key file into `dir`; returns the file.
pub(crate) fn write(dir: &Path) -> (std::path::PathBuf, Written) {
	let written = Written {
		rsa: test_keys::rsa_pkcs1_pem(),
		ed25519: test_keys::ed25519_v2_pem(),
	};
	std::fs::create_dir_all(dir.join("dkim")).expect("dkim dir");
	std::fs::write(dir.join("dkim/example.org.ed25519.pem"), &written.ed25519).expect("key");
	let file = dir.join("config.toml");
	std::fs::write(&file, CONFIG.replace("@RSA@", &written.rsa)).expect("config");
	(file, written)
}

/// The same configuration with the directory switched to `internal`.
pub(crate) fn write_internal(dir: &Path) -> std::path::PathBuf {
	let (file, _) = write(dir);
	let text = std::fs::read_to_string(&file).expect("read");
	std::fs::write(
		&file,
		text.replace("directory = \"memory\"", "directory = \"internal\""),
	)
	.expect("write");
	file
}
