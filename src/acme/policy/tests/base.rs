//! The policy that decides where the ACME client may send a signed request.

use super::*;
use crate::acme::directory::Directory;

/// The policy of a client bound to an `https` directory: the case of a real
/// CA, and the one where nothing but `https` and a global address pass.
fn https_policy() -> Policy {
	Policy::for_directory("https://acme.example/dir").expect("policy")
}

/// The message of a refusal, with the URL and the reason it names.
fn refusal(error: AcmeError) -> String {
	match error {
		AcmeError::RefusedUrl { url, reason } => format!("{url} :: {reason}"),
		other => panic!("expected AcmeError::RefusedUrl, got {other:?}"),
	}
}

#[test]
fn an_https_url_to_a_public_host_is_accepted() {
	// The CA's own host, named by a name: nothing about it is a place the
	// operator did not choose, and https is the only scheme admitted.
	let url = https_policy()
		.check("https://ca.example/new-order")
		.expect("a public host is accepted");
	assert_eq!(url, "https://ca.example/new-order");
}

#[test]
fn an_https_url_to_a_public_address_is_accepted() {
	let url = https_policy()
		.check("https://93.184.216.34/new-order")
		.expect("a public address is accepted");
	assert_eq!(url, "https://93.184.216.34/new-order");
}

#[test]
fn a_plain_http_url_is_refused_when_the_directory_is_https() {
	let error = https_policy()
		.check("http://ca.example/new-order")
		.expect_err("plain http must be refused");
	let message = refusal(error);
	assert!(
		message.contains("http://ca.example/new-order"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("https"),
		"the reason must name the scheme that is admitted: {message}"
	);
}

#[test]
fn another_scheme_is_refused() {
	let error = https_policy()
		.check("ftp://ca.example/new-order")
		.expect_err("another scheme must be refused");
	let message = refusal(error);
	assert!(
		message.contains("ftp://ca.example/new-order"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn the_cloud_metadata_address_is_refused() {
	let error = https_policy()
		.check("https://169.254.169.254/latest/meta-data/")
		.expect_err("the metadata address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("link-local"),
		"the reason must name the kind of address: {message}"
	);
}

#[test]
fn the_loopback_address_is_refused() {
	let error = https_policy()
		.check("https://127.0.0.1:8080/acme/new-order")
		.expect_err("the loopback address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("127.0.0.1:8080"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("loopback"),
		"the reason must name the kind of address: {message}"
	);
}

#[test]
fn a_private_address_is_refused() {
	for host in ["10.0.0.1", "172.16.5.4", "192.168.1.10"] {
		let url = format!("https://{host}/acme/new-order");
		let error = https_policy()
			.check(&url)
			.expect_err("a private address must be refused");
		let message = refusal(error);
		assert!(
			message.contains(host),
			"the refused URL must be named: {message}"
		);
		assert!(
			message.contains("private"),
			"the reason must name the kind of address: {message}"
		);
	}
}

#[test]
fn the_loopback_address_v6_is_refused() {
	let error = https_policy()
		.check("https://[::1]/acme/new-order")
		.expect_err("the loopback address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("[::1]"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("loopback"),
		"the reason must name the kind of address: {message}"
	);
}

#[test]
fn a_unique_local_address_is_refused() {
	let error = https_policy()
		.check("https://[fc00::1]/acme/new-order")
		.expect_err("a unique-local address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("[fc00::1]"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn a_link_local_address_v6_is_refused() {
	let error = https_policy()
		.check("https://[fe80::1]/acme/new-order")
		.expect_err("a link-local address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("[fe80::1]"),
		"the refused URL must be named: {message}"
	);
	assert!(
		message.contains("link-local"),
		"the reason must name the kind of address: {message}"
	);
}

#[test]
fn an_ipv4_address_hidden_in_an_ipv6_one_is_refused() {
	// ::ffff:127.0.0.1 is the loopback interface written in another form.
	let error = https_policy()
		.check("https://[::ffff:127.0.0.1]/acme/new-order")
		.expect_err("a mapped loopback address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("127.0.0.1") || message.contains("loopback"),
		"the reason must name the address it carries: {message}"
	);
}

#[test]
fn a_legacy_ipv4_notation_is_refused() {
	// The URL parser normalizes the notations a resolver still accepts, so
	// the loopback interface cannot be spelled in a way that slips past.
	let error = https_policy()
		.check("https://2130706433/acme/new-order")
		.expect_err("a decimal loopback address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("127.0.0.1"),
		"the normalized address must be named: {message}"
	);
	assert!(
		message.contains("loopback"),
		"the reason must name the kind of address: {message}"
	);
}

#[test]
fn a_local_ca_on_loopback_keeps_working() {
	// Pebble and the local test CAs speak plain http on the loopback
	// interface: the operator configured that directory on purpose, so the
	// URLs the CA names there are admitted.
	let policy = Policy::for_directory("http://127.0.0.1:14000/dir").expect("policy");
	let url = policy
		.check("http://127.0.0.1:14000/acme/new-order")
		.expect("the local CA must keep working");
	assert_eq!(url, "http://127.0.0.1:14000/acme/new-order");
	let url = policy
		.check("http://localhost:14000/acme/new-order")
		.expect("the local CA under another name must keep working");
	assert_eq!(url, "http://localhost:14000/acme/new-order");
}

#[test]
fn a_local_ca_on_loopback_does_not_reach_the_metadata_address() {
	// The operator chose a local CA; that does not make the cloud metadata
	// address one of the CA's resources.
	let policy = Policy::for_directory("http://127.0.0.1:14000/dir").expect("policy");
	let error = policy
		.check("http://169.254.169.254/latest/meta-data/")
		.expect_err("the metadata address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn a_private_directory_admits_a_private_address_but_not_the_loopback_one() {
	let policy = Policy::for_directory("http://10.0.0.1/acme/dir").expect("policy");
	let url = policy
		.check("http://10.0.0.1/acme/new-order")
		.expect("the CA the operator configured must keep working");
	assert_eq!(url, "http://10.0.0.1/acme/new-order");
	let error = policy
		.check("http://127.0.0.1/acme/new-order")
		.expect_err("another kind of internal address must be refused");
	let message = refusal(error);
	assert!(
		message.contains("127.0.0.1"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn a_relative_url_is_resolved_against_the_directory() {
	let url = https_policy()
		.check("/acme/new-order")
		.expect("a relative URL is resolved against the directory");
	assert_eq!(url, "https://acme.example/acme/new-order");
}

#[test]
fn a_url_with_credentials_is_refused() {
	let error = https_policy()
		.check("https://user:secret@ca.example/new-order")
		.expect_err("a URL with credentials must be refused");
	let message = refusal(error);
	assert!(
		message.contains("credentials"),
		"the reason must be named: {message}"
	);
	assert!(
		!message.contains("secret"),
		"the credentials must not be repeated: {message}"
	);
}

#[test]
fn a_directory_url_that_is_not_a_url_is_refused() {
	let error = Policy::for_directory("not a url").expect_err("a broken directory URL must fail");
	assert!(
		matches!(error, AcmeError::Protocol(_)),
		"the failure must be a protocol error: {error:?}"
	);
}

#[test]
fn a_directory_url_with_another_scheme_is_refused() {
	let error = Policy::for_directory("ftp://acme.example/dir").expect_err("ftp must fail");
	assert!(
		matches!(error, AcmeError::Protocol(_)),
		"the failure must be a protocol error: {error:?}"
	);
}

#[test]
fn every_url_of_a_directory_is_checked() {
	// The directory is where the CA names its resources; one hostile URL in
	// it must stop the client before it reaches any of them.
	let directory = Directory {
		new_nonce: "https://acme.example/new-nonce".into(),
		new_account: "https://acme.example/new-acct".into(),
		new_order: "https://169.254.169.254/new-order".into(),
		revoke_cert: Some("https://acme.example/revoke-cert".into()),
		key_change: Some("https://acme.example/key-change".into()),
	};
	let error = https_policy()
		.check_directory(&directory)
		.expect_err("a hostile URL must stop the directory");
	let message = refusal(error);
	assert!(
		message.contains("169.254.169.254"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn a_hostile_optional_url_of_a_directory_is_refused() {
	let directory = Directory {
		new_nonce: "https://acme.example/new-nonce".into(),
		new_account: "https://acme.example/new-acct".into(),
		new_order: "https://acme.example/new-order".into(),
		revoke_cert: Some("http://10.0.0.1/revoke-cert".into()),
		key_change: None,
	};
	let error = https_policy()
		.check_directory(&directory)
		.expect_err("a hostile revoke URL must stop the directory");
	let message = refusal(error);
	assert!(
		message.contains("10.0.0.1"),
		"the refused URL must be named: {message}"
	);
}

#[test]
fn a_directory_whose_urls_pass_is_returned_with_them_checked() {
	let directory = Directory {
		new_nonce: "/new-nonce".into(),
		new_account: "https://acme.example/new-acct".into(),
		new_order: "https://ca.example/new-order".into(),
		revoke_cert: Some("https://ca.example/revoke-cert".into()),
		key_change: None,
	};
	let checked = https_policy()
		.check_directory(&directory)
		.expect("a directory of public URLs passes");
	assert_eq!(checked.new_nonce, "https://acme.example/new-nonce");
	assert_eq!(checked.new_account, "https://acme.example/new-acct");
	assert_eq!(checked.new_order, "https://ca.example/new-order");
	assert_eq!(
		checked.revoke_cert.as_deref(),
		Some("https://ca.example/revoke-cert")
	);
	assert!(checked.key_change.is_none());
}
