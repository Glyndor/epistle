use super::*;
use toml_edit::{TableLike, Value};

const TEXT: &str = "# header
hostname = 'mail.example.org'

# default smarthost
[[transport]] # catch-all
kind = 'relay'
host = 'smtp.example.net'
port  =  587 # submission
username = 'u' # who
password = 'p'

[[transport]]
domain = 'example.org'
kind = 'relay'
host = 'a.example.net'
port = 25
# end
";

fn doc(text: &str) -> (tempfile::NamedTempFile, ConfigDocument) {
	let file = tempfile::NamedTempFile::new_in(".").unwrap();
	std::fs::write(file.path(), text).unwrap();
	let doc = ConfigDocument::open(file.path()).unwrap();
	(file, doc)
}

fn catch_all(table: &dyn TableLike) -> bool {
	!table.contains_key("account") && !table.contains_key("domain")
}

fn domain_is(name: &'static str) -> impl Fn(&dyn TableLike) -> bool {
	move |table| table.get("domain").and_then(|v| v.as_str()) == Some(name)
}

#[test]
fn upsert_where_updates_the_selected_element_and_clears_fields() {
	let (_file, mut doc) = doc(TEXT);
	doc.upsert_where(
		"transport",
		&catch_all,
		&[
			("port", Some(Value::from(2525_i64))),
			("username", None),
			("password", None),
		],
	)
	.unwrap();
	assert_eq!(
		doc.render(),
		TEXT.replace("port  =  587 # submission", "port  =  2525 # submission")
			.replace("username = 'u' # who\npassword = 'p'\n", "")
			+ "# who\n",
		"the catch-all element must change in place, keep its comments, and drop cleared keys"
	);
}

#[test]
fn upsert_where_appends_when_nothing_matches_and_keeps_field_order() {
	let (_file, mut doc) = doc(TEXT);
	doc.upsert_where(
		"transport",
		&domain_is("new.org"),
		&[
			("domain", Some(Value::from("new.org"))),
			("kind", Some(Value::from("relay"))),
			("host", Some(Value::from("h.example.net"))),
			("username", None),
		],
	)
	.unwrap();
	assert_eq!(
		doc.render(),
		TEXT.replace(
			"# end\n",
			"\n[[transport]]\ndomain = \"new.org\"\nkind = \"relay\"\nhost = \"h.example.net\"\n# end\n"
		),
		"a new element must be appended with the fields in the given order"
	);
}

#[test]
fn upsert_where_rejects_ambiguous_selectors() {
	let (_file, mut doc) = doc(&format!("{TEXT}\n[[transport]]\nkind = 'fail'\n"));
	let error = doc
		.upsert_where(
			"transport",
			&catch_all,
			&[("port", Some(Value::from(1_i64)))],
		)
		.unwrap_err();
	assert_eq!(error, "multiple array elements match the selector");
}

#[test]
fn remove_where_removes_only_matches_and_keeps_their_comments() {
	let (_file, mut doc) = doc(TEXT);
	assert_eq!(doc.remove_where("transport", &catch_all).unwrap(), 1);
	assert_eq!(
		doc.render(),
		TEXT.replace(
			"# default smarthost\n[[transport]] # catch-all\nkind = 'relay'\nhost = 'smtp.example.net'\nport  =  587 # submission\nusername = 'u' # who\npassword = 'p'\n\n",
			""
		) + "# default smarthost\n# catch-all\n# submission\n# who\n",
		"removing an element must not discard its comments"
	);
	assert_eq!(
		doc.remove_where("transport", &domain_is("absent.org"))
			.unwrap(),
		0
	);
}

#[test]
fn rules_edits_handle_inline_arrays() {
	let (_file, mut doc) = doc(
		"transport = [ { kind = 'relay', host = 'h', port = 25 }, { domain = 'a.org', kind = 'fail' } ]\n",
	);
	doc.upsert_where(
		"transport",
		&catch_all_inline,
		&[("port", Some(Value::from(26_i64)))],
	)
	.unwrap();
	assert_eq!(
		doc.render(),
		"transport = [ { kind = 'relay', host = 'h', port = 26 }, { domain = 'a.org', kind = 'fail' } ]\n"
	);
	assert_eq!(
		doc.remove_where("transport", &domain_is("a.org")).unwrap(),
		1
	);
	assert_eq!(
		doc.render(),
		"transport = [ { kind = 'relay', host = 'h', port = 26 }]\n"
	);
}

fn catch_all_inline(table: &dyn TableLike) -> bool {
	catch_all(table)
}

#[allow(unused_imports)]
use super::super::file;
