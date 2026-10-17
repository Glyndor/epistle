use super::*;
use toml_edit::Value;

const TEXT: &str = "# header
hostname = 'mail.example.org'

# provider section
[dns] # dns
provider = 'cloudflare' # who
zone = 'example.org'
token_env = 'CF_TOKEN' # secret source

[webhook]
url = 'https://hooks.example/mail'
";

fn doc(text: &str) -> (tempfile::NamedTempFile, ConfigDocument) {
	let file = tempfile::NamedTempFile::new_in(".").unwrap();
	std::fs::write(file.path(), text).unwrap();
	let doc = ConfigDocument::open(file.path()).unwrap();
	(file, doc)
}

#[test]
fn set_table_fields_updates_in_place_and_clears_the_rest() {
	let (_file, mut doc) = doc(TEXT);
	doc.set_table_fields(
		&["dns"],
		&[
			("provider", Some(Value::from("desec"))),
			("zone", Some(Value::from("example.org"))),
			("token_env", None),
			("token_file", Some(Value::from("/etc/epistle/dns.token"))),
		],
	)
	.unwrap();
	assert_eq!(
		doc.render(),
		TEXT.replace(
			"provider = 'cloudflare' # who",
			"provider = \"desec\" # who"
		)
		.replace(
			"token_env = 'CF_TOKEN' # secret source\n",
			"token_file = \"/etc/epistle/dns.token\"\n"
		) + "# secret source\n",
		"keys must change in place and the cleared key must leave its comment"
	);
}

#[test]
fn set_table_fields_creates_nested_tables() {
	let (_file, mut doc) = doc(TEXT);
	doc.set_table_fields(
		&["storage", "blobs"],
		&[("backend", Some(Value::from("fs")))],
	)
	.unwrap();
	assert_eq!(
		doc.render(),
		format!("{TEXT}\n[storage]\n\n[storage.blobs]\nbackend = \"fs\"\n"),
		"a missing nested table must be appended after the existing sections"
	);
}

#[test]
fn remove_table_drops_the_section_and_keeps_its_comments() {
	let (_file, mut doc) = doc(TEXT);
	assert!(doc.remove_table(&["dns"]).unwrap());
	assert_eq!(
		doc.render(),
		TEXT.replace(
			"# provider section\n[dns] # dns\nprovider = 'cloudflare' # who\nzone = 'example.org'\ntoken_env = 'CF_TOKEN' # secret source\n\n",
			""
		) + "# provider section\n# dns\n# who\n# secret source\n"
	);
	assert!(!doc.remove_table(&["dns"]).unwrap());
	assert!(!doc.remove_table(&["storage", "blobs"]).unwrap());
}

const INLINE: &str = "hostname = 'mail.example.org'
tenant = [{ name = 'acme', submission_rate_limit_per_min = 5 }, { name = 'other' }]
";

/// The `tenant` entries of a rendered document, as data: the layout of an
/// inline table is toml_edit's business, its content is the contract.
fn tenants(rendered: &str) -> serde_json::Value {
	let parsed: toml::Value = toml::from_str(rendered).expect("rendered document parses");
	serde_json::to_value(&parsed["tenant"]).expect("tenant entries")
}

#[test]
fn an_inline_entry_gets_the_field_not_the_whole_array() {
	let (_file, mut doc) = doc(INLINE);
	let edited = doc
		.edit_array_entry_field(
			&["tenant"],
			"acme",
			"name",
			"enabled",
			Some(Value::from(false)),
		)
		.unwrap();
	assert!(edited);
	assert_eq!(
		tenants(&doc.render()),
		serde_json::json!([
			{ "name": "acme", "submission_rate_limit_per_min": 5, "enabled": false },
			{ "name": "other" },
		])
	);
}

#[test]
fn an_inline_entry_loses_the_field_when_it_is_cleared() {
	let (_file, mut doc) = doc(INLINE);
	let edited = doc
		.edit_array_entry_field(
			&["tenant"],
			"acme",
			"name",
			"submission_rate_limit_per_min",
			None,
		)
		.unwrap();
	assert!(edited);
	assert_eq!(
		tenants(&doc.render()),
		serde_json::json!([{ "name": "acme" }, { "name": "other" }])
	);
}
