//! A webhook switched off with `enabled = false` is not built.

use super::*;

fn config(dir: &std::path::Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {dir:?}\ndomains = [\"example.org\"]\n\
		[webhook]\nurl = \"https://hooks.example.net/in\"\n{extra}"
	))
	.expect("config")
}

fn build(config: &Config) -> SplitCompanions {
	build_split_with_companions(
		config,
		&Arc::new(Metrics::default()),
		DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		MessageCrypto::disabled(),
	)
	.expect("startup")
}

#[test]
fn an_enabled_webhook_is_built() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	assert!(build(&config(&root, "")).webhook.is_some());
}

#[test]
fn a_disabled_webhook_is_not_built() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	assert!(
		build(&config(&root, "enabled = false\n")).webhook.is_none(),
		"a webhook that is off must not post events"
	);
}
