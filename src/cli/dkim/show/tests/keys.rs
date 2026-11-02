//! `dkim show` lists the key of every hosted domain, so a key that several
//! domains share is visible.

use super::*;

fn config(dir: &std::path::Path, overrides: &str) -> Config {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let default_key = dir.join("default.key");
	std::fs::write(&default_key, pem).expect("write");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n\
		 domains = ['a.example', 'b.example', 'c.example']\n\
		 [dkim]\nselector = 'main'\nkey_file = {default_key:?}\n{overrides}"
	))
	.expect("config")
}

fn key<'a>(view: &'a DkimView, domain: &str) -> &'a KeyView {
	view.keys
		.iter()
		.find(|key| key.domain == domain)
		.expect("a key line for the domain")
}

#[tokio::test]
async fn domains_on_the_default_key_name_each_other() {
	let dir = tempfile::tempdir().expect("dir");
	let view = build(&config(dir.path(), ""), None).await.expect("view");
	let a = key(&view, "a.example");
	assert_eq!(a.source, "dkim");
	assert_eq!(a.selector, "main");
	assert_eq!(a.shared_with, vec!["b.example", "c.example"]);
}

#[tokio::test]
async fn a_domain_with_its_own_entry_shares_nothing_and_leaves_the_others_alone() {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let own = dir.path().join("b.key");
	std::fs::write(&own, pem).expect("write");
	let overrides =
		format!("[[dkim.domain]]\nname = 'b.example'\nselector = 'bsel'\nkey_file = {own:?}\n");
	let view = build(&config(dir.path(), &overrides), None)
		.await
		.expect("view");
	let b = key(&view, "b.example");
	assert_eq!((b.source, b.selector.as_str()), ("dkim.domain", "bsel"));
	assert!(b.shared_with.is_empty(), "{b:?}");
	assert_eq!(key(&view, "a.example").shared_with, vec!["c.example"]);
}

#[tokio::test]
async fn the_text_form_says_who_shares_and_who_does_not() {
	let dir = tempfile::tempdir().expect("dir");
	let view = build(&config(dir.path(), ""), None).await.expect("view");
	let mut out = Vec::new();
	assert_eq!(render(&view, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		text.contains("key a.example: main (shared with b.example, c.example)"),
		"{text}"
	);
}
