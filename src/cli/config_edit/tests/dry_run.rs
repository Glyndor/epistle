//! `ConfigDocument::dry_run` redacts credential values from the
//! rendered diff so a dry-run listing does not echo a secret the
//! operator just typed in on stdin.

use super::*;
use std::os::unix::fs::PermissionsExt;

fn write_mail_toml(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(&path, body).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	path
}

#[test]
fn dry_run_redacts_changed_secret_value() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[[transport]]\ndomain = \"example.net\"\npassword = \"hunter2\"\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	let transport = doc.document["transport"]
		.as_array_of_tables_mut()
		.unwrap()
		.iter_mut()
		.next()
		.unwrap();
	transport["password"] = toml_edit::value("new-secret");
	let rendered = doc.dry_run().unwrap();
	assert!(
		rendered.contains("+password = <redacted>"),
		"dry_run: {rendered}"
	);
	assert!(
		!rendered.contains("hunter2") && !rendered.contains("new-secret"),
		"plaintext password leaked into dry-run output: {rendered}"
	);
}

#[test]
fn dry_run_redacts_changed_webhook_secret() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[webhook]\nurl = \"https://hooks.example/mail\"\nsecret = \"TOP-SECRET-WEBHOOK\"\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.document["webhook"]["secret"] = toml_edit::value("EVEN-NEWER-WEBHOOK");
	let rendered = doc.dry_run().unwrap();
	assert!(rendered.contains("+secret = <redacted>"), "{rendered}");
	assert!(
		!rendered.contains("TOP-SECRET-WEBHOOK") && !rendered.contains("EVEN-NEWER-WEBHOOK"),
		"plaintext webhook secret leaked: {rendered}"
	);
}

#[test]
fn dry_run_redacts_secret_on_context_line() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\nsrs_secret = \"old-secret\"\nquota_bytes = 1\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.document["quota_bytes"] = toml_edit::value(2_i64);
	let rendered = doc.dry_run().unwrap();
	assert!(rendered.contains(" srs_secret = <redacted>"), "{rendered}");
	assert!(
		!rendered.contains("old-secret"),
		"secret leaked: {rendered}"
	);
	assert!(
		rendered.contains("quota_bytes"),
		"non-secret line kept: {rendered}"
	);
}

#[test]
fn dry_run_redacts_password_in_database_url_userinfo() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[database]\nurl = \"postgres://epistle:OLD-PW@localhost/epistle?sslmode=require\"\ndirectory = true\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.document["database"]["url"] =
		toml_edit::value("postgres://epistle:NEW-PW@localhost/epistle?sslmode=require");
	let rendered = doc.dry_run().unwrap();
	assert!(
		!rendered.contains("OLD-PW") && !rendered.contains("NEW-PW"),
		"database password leaked into dry-run: {rendered}"
	);
	assert!(
		rendered.contains("epistle:") && rendered.contains("@localhost/epistle"),
		"user and host must survive: {rendered}"
	);
}

#[test]
fn dry_run_keeps_unrelated_lines_byte_identical() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\nquota_bytes = 1\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.document["quota_bytes"] = toml_edit::value(2_i64);
	let rendered = doc.dry_run().unwrap();
	assert!(rendered.contains("+quota_bytes = 2"), "{rendered}");
	assert!(rendered.contains("-quota_bytes = 1"), "{rendered}");
}

/// A credential on a line that is only context, next to the line being
/// edited, is redacted too: the diff shows three lines either side.
#[test]
fn dry_run_redacts_credentials_that_are_only_context() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = write_mail_toml(
		dir.path(),
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n\
		 [[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n\
		 password_hash = \"$argon2id$v=19$m=65536,t=2,p=1$CONTEXTSALTAAAAAAAAAAA$CONTEXTHASHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
		 [dns]\nprovider = \"route53\"\nzone = \"example.org\"\n\
		 access_key = \"AKIACONTEXTKEYID\"\nconsumer_key = \"CONTEXTCONSUMER\"\nkey_name = \"k\"\n",
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.document["dns"]["zone"] = toml_edit::value("example.net");
	let rendered = doc.dry_run().unwrap();
	for leaked in [
		"CONTEXTHASH",
		"CONTEXTSALT",
		"AKIACONTEXTKEYID",
		"CONTEXTCONSUMER",
	] {
		assert!(
			!rendered.contains(leaked),
			"a credential reached the diff as context: {rendered}"
		);
	}
	for redacted in [
		" password_hash = <redacted>",
		" access_key = <redacted>",
		" consumer_key = <redacted>",
	] {
		assert!(rendered.contains(redacted), "{redacted}: {rendered}");
	}
}
