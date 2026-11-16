pub use super::*;

pub(super) mod policy;
pub(super) mod prefs;
pub(super) mod run;
pub(super) mod settings;

/// A policy from a configuration for `example.org` and `other.example`
/// (tenant `acme` owns the second) with `extra` appended.
pub(super) fn policy(extra: &str) -> Policy {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'other.example']\n[[tenant]]\nname = 'acme'\ndomains = ['other.example']\n{extra}",
		dir.path()
	);
	let config = crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect("config");
	Policy::from_config(&config).expect("a [storage.cleanup] section")
}
