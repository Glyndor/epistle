//! A way to build the limits of a configuration written in a test.

use std::sync::Arc;

use super::Limits;
use crate::config::Config;

/// The configuration every test starts from: three domains, one tenant that
/// owns `example.com`, and a server cap of 10 MiB.
pub(crate) const BASE: &str = r#"
domains = ["example.com", "example.org", "example.net"]
max_message_size = 10485760

[[tenant]]
name = "acme"
domains = ["example.com"]
"#;

/// The limits of `BASE` with `extra` appended.
pub(crate) fn limits(extra: &str) -> Limits {
	limits_from(&format!("{BASE}\n{extra}"))
}

/// The limits of a configuration written in a test: `text` is the whole
/// configuration, so a test can declare a tenant of its own.
pub(crate) fn limits_from(text: &str) -> Limits {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{text}"
	)
	.expect("write config");
	let config = Config::load(file.path()).expect("config loads");
	Limits::from_config(&config)
}

/// [`limits`], shared.
pub(crate) fn shared(extra: &str) -> Arc<Limits> {
	Arc::new(limits(extra))
}

/// [`limits_from`], shared.
pub(crate) fn shared_from(text: &str) -> Arc<Limits> {
	Arc::new(limits_from(text))
}
