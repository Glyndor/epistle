//! `config-check` says when hosted domains still share one SRS secret.

use crate::cli::config::check::tests::*;
use crate::test_support::fixtures::fresh_secret;
use std::io::Write;

fn check(body: &str) -> (ExitCode, String) {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(body.as_bytes()).expect("write");
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = run(file.path(), false, &mut out, &mut err);
	(code, String::from_utf8_lossy(&err).into_owned())
}

#[test]
fn two_domains_on_one_secret_warn_and_still_pass() {
	let secret = fresh_secret();
	let (code, err) = check(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{secret}\"\n"
	));
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(err.contains("a.example, b.example"), "{err}");
	assert!(err.contains("epistle srs split"), "{err}");
	assert!(!err.contains(&secret), "the warning printed the secret");
}

#[test]
fn once_each_domain_has_its_own_secret_the_warning_goes() {
	let (global, a, b) = (fresh_secret(), fresh_secret(), fresh_secret());
	let (code, err) = check(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"b.example\"]\nsrs_secret = \"{global}\"\n\
		 [[srs_domain]]\nname = \"a.example\"\nsecret = \"{a}\"\n\
		 [[srs_domain]]\nname = \"b.example\"\nsecret = \"{b}\"\n"
	));
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!err.contains("srs_secret"), "{err}");
}

#[test]
fn two_domains_sharing_a_secret_fail_the_check() {
	let shared = fresh_secret();
	let (code, err) = check(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"b.example\"]\n\
		 [[srs_domain]]\nname = \"a.example\"\nsecret = \"{shared}\"\n\
		 [[srs_domain]]\nname = \"b.example\"\nsecret = \"{shared}\"\n"
	));
	assert_ne!(code, ExitCode::SUCCESS);
	assert!(err.contains("shares a secret"), "{err}");
}
