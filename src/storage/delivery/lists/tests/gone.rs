//! A recipient that does not resolve is gone for good, unless it is only
//! switched off: a domain or a masked address that can come back is a
//! failure that passes.

use super::*;

fn directory() -> Directory {
	Directory::new(
		["example.org".to_string(), "off.example".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("carol@off.example".to_string(), "carol".to_string()),
		],
	)
	.with_disabled_domains(["off.example".to_string()])
	.with_masked_paused(["mask.paused@example.org".to_string()])
}

fn message(recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "bob@sender.example".into(),
		recipients: vec![recipient.to_string()],
		data: b"Subject: s\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[test]
fn an_address_nobody_has_is_gone() {
	let refused = accounts_for(&directory(), &message("ghost@example.org"));
	assert!(
		matches!(refused, Err(SinkError::Gone(_))),
		"an unknown address is gone"
	);
}

#[test]
fn a_switched_off_domain_is_only_unavailable() {
	let refused = accounts_for(&directory(), &message("carol@off.example"));
	assert!(
		matches!(refused, Err(SinkError::Unavailable(_))),
		"the address is unavailable"
	);
}

#[test]
fn a_switched_off_masked_address_is_only_unavailable() {
	let refused = accounts_for(&directory(), &message("mask.paused@example.org"));
	assert!(
		matches!(refused, Err(SinkError::Unavailable(_))),
		"the address is unavailable"
	);
}

#[test]
fn an_address_that_resolves_is_not_refused() {
	assert!(accounts_for(&directory(), &message("alice@example.org")).is_ok());
}
