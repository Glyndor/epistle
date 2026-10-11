use super::*;
use toml_edit::Value;

const FIXTURE: &str = include_str!("fixtures/mail.toml");

fn document() -> (tempfile::NamedTempFile, ConfigDocument) {
	let file = tempfile::NamedTempFile::new_in(".").unwrap();
	std::fs::write(file.path(), FIXTURE).unwrap();
	let doc = ConfigDocument::open(file.path()).unwrap();
	(file, doc)
}

fn exact(doc: &ConfigDocument, expected: &str) {
	assert!(
		doc.render() == expected,
		"helper must preserve exact comments and unrelated formatting"
	);
}

#[test]
fn scalar_set_and_remove_preserve_exact_text() {
	let (_file, mut doc) = document();
	doc.set_scalar("quota_bytes", 999_i64).unwrap();
	exact(&doc, &FIXTURE.replace("=  123 # quota", "=  999 # quota"));
	doc.remove_scalar("quota_bytes");
	exact(
		&doc,
		&format!(
			"{}# quota\n",
			FIXTURE.replace("quota_bytes  =  123 # quota\n", "")
		),
	);
}

#[test]
fn table_and_map_edits_preserve_exact_text() {
	let (_file, mut doc) = document();
	doc.set_table_key(&["antispam"], "clamd_timeout_secs", 60_i64)
		.unwrap();
	let expected = FIXTURE.replace("=  45 # timeout", "=  60 # timeout");
	exact(&doc, &expected);
	doc.remove_table_key(&["antispam"], "clamd_timeout_secs")
		.unwrap();
	let expected = format!(
		"{}# timeout\n",
		expected.replace("clamd_timeout_secs  =  60 # timeout\n", "")
	);
	exact(&doc, &expected);
	doc.set_map_entry("domain_quotas", "example.org", 789_i64)
		.unwrap();
	let expected = expected.replace("=  123 # domain quota", "=  789 # domain quota");
	exact(&doc, &expected);
	doc.remove_map_entry("domain_quotas", "remove.org").unwrap();
	exact(&doc, &expected.replace("'remove.org' = 456\n", ""));
	doc.set_table_key(&["storage", "blobs"], "backend", "fs")
		.unwrap();
	exact(
		&doc,
		&format!(
			"{}\n[storage]\n\n[storage.blobs]\nbackend = \"fs\"\n# end\n# timeout\n",
			expected
				.replace("'remove.org' = 456\n", "")
				.trim_end_matches("# end\n# timeout\n")
		),
	);
}

#[test]
fn string_array_edits_preserve_exact_text_and_no_ops() {
	let (_file, mut doc) = document();
	doc.add_string("domains", "example.org").unwrap();
	doc.remove_string("domains", "absent.org").unwrap();
	exact(&doc, FIXTURE);
	doc.add_string("domains", "new.org").unwrap();
	let expected = FIXTURE.replace("'remove.org' ]", "'remove.org', \"new.org\" ]");
	exact(&doc, &expected);
	doc.remove_string("domains", "remove.org").unwrap();
	exact(&doc, &expected.replace(" 'remove.org',", ""));
}

#[test]
fn array_of_tables_insert_update_remove_preserve_exact_text() {
	let (_file, mut doc) = document();
	doc.upsert_element("listeners", "kind", "smtp", &[("addr", Value::from("::"))])
		.unwrap();
	let expected = FIXTURE.replace("'0.0.0.0' # bind", "\"::\" # bind");
	exact(&doc, &expected);
	doc.remove_elements("listeners", "kind", "imap").unwrap();
	let expected = expected.replace("\n[[listeners]]\nkind = 'imap'\naddr = '0.0.0.0'\n", "");
	exact(&doc, &expected);
	doc.upsert_element(
		"listeners",
		"kind",
		"web-dav",
		&[("addr", Value::from("0.0.0.0"))],
	)
	.unwrap();
	exact(
		&doc,
		&expected.replace(
			"# end\n",
			"\n[[listeners]]\nkind = \"web-dav\"\naddr = \"0.0.0.0\"\n# end\n",
		),
	);
}

#[test]
fn no_op_scalar_keeps_original_literal_and_array_update_is_unambiguous() {
	let (_file, mut doc) = document();
	doc.set_scalar("hostname", "mail.example.org").unwrap();
	exact(&doc, FIXTURE);
	doc.upsert_element("listeners", "kind", "smtp", &[])
		.unwrap();
	exact(&doc, FIXTURE);
	let duplicate = doc.document["listeners"]
		.as_array_of_tables()
		.unwrap()
		.get(0)
		.unwrap()
		.clone();
	doc.document["listeners"]
		.as_array_of_tables_mut()
		.unwrap()
		.push(duplicate);
	assert_eq!(
		doc.upsert_element("listeners", "kind", "smtp", &[])
			.err()
			.as_deref(),
		Some("multiple array elements match the key")
	);
}

#[test]
fn removing_values_and_elements_retains_nested_comments() {
	let file = tempfile::NamedTempFile::new_in(".").unwrap();
	let text = "# header\nhostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = [\n # inside array\n 'example.org',\n] # domains\n\n# socket\n[[listeners]] # header suffix\nkind = 'smtp' # kind\naddr = '0.0.0.0' # addr\n";
	std::fs::write(file.path(), text).unwrap();
	let mut doc = ConfigDocument::open(file.path()).unwrap();
	doc.remove_scalar("domains");
	assert!(
		doc.render()
			== text.replace(
				"domains = [\n # inside array\n 'example.org',\n] # domains\n",
				""
			) + "# domains\n# inside array\n",
		"removing a value must retain every nested comment"
	);
}
