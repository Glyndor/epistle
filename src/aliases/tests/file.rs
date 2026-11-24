//! The state file: what it holds, how it is read and what it refuses.

use crate::aliases::AliasesFile;
use crate::config::Alias;

fn alias(address: &str, members: &[&str]) -> Alias {
	Alias {
		address: address.to_string(),
		members: members.iter().map(|member| member.to_string()).collect(),
		senders: Vec::new(),
		hidden: true,
		list_id: None,
	}
}

#[test]
fn a_file_is_read_back_as_it_was_written() {
	let file = AliasesFile {
		seed_digest: "sha256:abc".into(),
		aliases: vec![
			alias(
				"team@example.org",
				&["alice@example.org", "bob@example.org"],
			),
			Alias {
				senders: vec!["ceo@example.org".into()],
				hidden: false,
				list_id: Some("team.example.org".into()),
				..alias("list@example.org", &["alice@example.org"])
			},
		],
	};
	let text = file.render().expect("render");
	assert!(text.starts_with("# The address aliases of this server."));
	assert_eq!(AliasesFile::parse(&text).expect("parse"), file);
}

#[test]
fn a_field_it_does_not_know_is_refused() {
	for text in [
		"surprise = 1\n",
		"[[alias]]\naddress = \"a@example.org\"\nmembers = [\"b@example.org\"]\nsurprise = 1\n",
	] {
		assert!(AliasesFile::parse(text).is_err(), "{text}");
	}
}

#[test]
fn a_missing_file_is_none_and_a_broken_one_an_error() {
	let dir = tempfile::tempdir().expect("dir");
	let path = dir.path().join("address-aliases.toml");
	assert_eq!(AliasesFile::read(&path).expect("missing"), None);
	std::fs::write(&path, "[[alias]\n").expect("write");
	assert!(AliasesFile::read(&path).is_err());
}

#[test]
fn an_alias_is_found_in_any_case() {
	let file = AliasesFile {
		aliases: vec![alias("team@example.org", &["a@example.org"])],
		..AliasesFile::default()
	};
	assert!(file.alias("TEAM@Example.ORG").is_some());
	assert!(file.alias("other@example.org").is_none());
}
