pub use super::*;

pub(super) mod base;
pub(super) mod folders;
pub(super) mod policy;

/// A configuration for `example.org` and `other.example`, plus `extra`.
pub(super) fn config(extra: &str) -> (tempfile::TempDir, crate::config::Config) {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'other.example']\n{extra}",
		dir.path()
	);
	let config = crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect("config");
	(dir, config)
}
