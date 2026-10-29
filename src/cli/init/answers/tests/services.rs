//! Answers unit tests for `services.database` and the whole
//! `services` table. `services.database` is the one
//! `Services` field without `serde(default)`, so an answers
//! file that omits it must fail to deserialise with an error
//! the operator can act on; a silent default would let a
//! hand-typed file skip the choice.

use super::*;

#[test]
fn services_database_is_required() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n\
		[services]\n\
		imap = true\n\
		submission = true\n";
	let result: Result<Answers, _> = toml::from_str(toml_text);
	let error = result.expect_err("missing services.database must fail to deserialise");
	let rendered = error.to_string();
	assert!(
		rendered.contains("services.database") || rendered.contains("database"),
		"the parser error must name the missing field, got: {rendered}"
	);
}

/// Both `database = true` and `database = false` are accepted. The
/// `Services` Default impl covers `false`; a hand-typed `true` in an
/// answers file is the other half the operator can ask for.
#[test]
fn services_database_true_and_false_accepted() {
	let base = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n\
		[services]\n\
		imap = true\n\
		submission = true\n";
	let with_true = format!("{base}database = true\n");
	let parsed: Answers = toml::from_str(&with_true).expect("database = true parses");
	assert!(parsed.services.database);
	assert!(parsed.validate().is_ok(), "database = true must validate");
	let with_false = format!("{base}database = false\n");
	let parsed: Answers = toml::from_str(&with_false).expect("database = false parses");
	assert!(!parsed.services.database);
	assert!(parsed.validate().is_ok(), "database = false must validate");
}

/// The whole `[services]` table is required: an answers file that
/// omits it must fail to deserialise with an error that names the
/// missing section. A silent default would let a hand-typed file
/// skip the explicit choice of `database = true | false` and the
/// stack would come up without the postgres antispam features the
/// operator might have wanted. The error path is the parser, not
/// the validator: serde rejects the missing struct field before
/// any application code runs.
#[test]
fn services_table_is_required() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n";
	let result: Result<Answers, _> = toml::from_str(toml_text);
	let error = result.expect_err("a missing [services] table must fail to deserialise");
	let rendered = error.to_string();
	assert!(
		rendered.contains("services"),
		"the parser error must name the missing field, got: {rendered}"
	);
}
