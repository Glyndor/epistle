//! A fifo where a file `init` reads belongs is refused, not waited on.
//!
//! `init` reads the generated compose file, the OAuth key pair and the
//! self-signed key of an earlier run. A plain read parks on a fifo for a
//! writer that may never come, with no message, and the apply phase does it
//! after other steps have taken effect. Each test hands the run to `bounded`,
//! so a read that waits is a failed assertion and not a hung suite.

use super::*;
use crate::cli::regular::read::{bounded, fifo_at};

fn answers(root: &std::path::Path) -> Answers {
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.data_dir = root.join("data");
	answers.config_path = root.join("etc/mail.toml");
	answers.image = Some("localhost/epistle:dev".to_string());
	answers
}

/// A fresh install on disk, so the files a rerun reads exist.
fn installed(root: &std::path::Path) -> Answers {
	let answers = answers(root);
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	answers
}

fn replace_with_fifo(path: &std::path::Path) {
	std::fs::remove_file(path).expect("remove the file the fifo replaces");
	fifo_at(path);
}

#[test]
fn the_plan_does_not_wait_on_a_fifo_where_the_compose_file_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let compose = crate::cli::init::compose::compose_file_path(&answers.data_dir);
	replace_with_fifo(&compose);
	bounded(&compose, move |_| {
		let _ = plan(&answers);
	});
}

#[test]
fn the_plan_refuses_a_fifo_where_the_oauth_key_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let private = crate::cli::init::host_secrets::oauth_signing_key(&answers.data_dir);
	replace_with_fifo(&private);
	let result = bounded(&private, move |_| plan(&answers));
	let error = result.expect_err("a fifo is not a key to read");
	assert!(error.to_string().contains("not a regular file"), "{error}");
}

#[test]
fn the_plan_refuses_a_fifo_where_the_oauth_public_key_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let public = answers.data_dir.join("keys/oauth_public.key");
	replace_with_fifo(&public);
	let result = bounded(&public, move |_| plan(&answers));
	let error = result.expect_err("a fifo is not a key to read");
	assert!(error.to_string().contains("not a regular file"), "{error}");
}

#[test]
fn the_apply_refuses_a_fifo_where_the_oauth_key_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let private = crate::cli::init::host_secrets::oauth_signing_key(&answers.data_dir);
	replace_with_fifo(&private);
	let outcome = bounded(&private, move |_| apply(&answers));
	let error = outcome.error.expect("a fifo is not a key to read");
	assert!(error.to_string().contains("not a regular file"), "{error}");
}

#[test]
fn the_apply_refuses_a_fifo_where_the_self_signed_key_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let keys = answers.data_dir.join("keys");
	std::fs::remove_file(keys.join("cert.pem")).expect("remove the certificate");
	replace_with_fifo(&keys.join("key.pem"));
	let key = keys.join("key.pem");
	let outcome = bounded(&key, move |_| apply(&answers));
	let error = outcome.error.expect("a fifo is not a key to read");
	assert!(error.to_string().contains("not a regular file"), "{error}");
}

#[test]
fn the_apply_refuses_a_fifo_where_the_compose_readme_belongs() {
	let root = tempfile::tempdir().unwrap();
	let answers = installed(root.path());
	let compose = crate::cli::init::compose::compose_file_path(&answers.data_dir);
	let readme = compose.with_file_name("README");
	assert!(readme.exists(), "a fresh install writes the README");
	replace_with_fifo(&readme);
	let outcome = bounded(&readme, move |_| apply(&answers));
	let error = outcome.error.expect("a fifo is not a file to write over");
	assert!(error.to_string().contains("not a regular file"), "{error}");
}
