//! Tests for the system resolver construction shared by SPF and the queue.
//!
//! The system resolver must speak only TCP: behind systemd-resolved's stub,
//! DNSSEC-validating UDP replies can come back truncated, and hickory decodes
//! the message before noticing the TC bit, which surfaces as an "incorrect
//! rdata length" error and never retries over TCP. Forcing TCP keeps DNSSEC
//! validation working across the stub and through pasta.

use hickory_resolver::config::ProtocolConfig;

#[test]
fn shared_system_resolver_uses_only_tcp() {
	let config = super::system_resolver_config().expect("system resolver config must build");

	assert!(
		!config.name_servers().is_empty(),
		"the system resolver must keep at least one name server from /etc/resolv.conf",
	);

	for server in config.name_servers() {
		assert!(
			!server.connections.is_empty(),
			"every name server must keep at least one connection configured"
		);
		for connection in &server.connections {
			assert!(
				matches!(connection.protocol, ProtocolConfig::Tcp),
				"name server {} connection must be TCP, got {:?}",
				server.ip,
				connection.protocol,
			);
		}
	}
}

#[test]
fn truncated_dnssec_reply_fails_to_decode() {
	// Saved from the Debian 13 host behind pasta+systemd-resolved: the stub
	// trimmed an oversized DO=1 reply to 512 bytes, set TC, and kept the
	// original record count so the last record is incomplete. hickory decodes
	// the message before looking at TC, which surfaces as a length mismatch
	// and never retries over TCP. This regression test pins that behavior so
	// nobody quietly switches the resolver back to UDP thinking the decode
	// error is harmless.
	let bytes = include_bytes!("../../tests/fixtures/dns/ds_tc_pasta.bin");
	let result = hickory_resolver::proto::op::Message::from_vec(bytes);
	let message = match result {
		Ok(_) => panic!(
			"the saved 512-byte reply is truncated; hickory must NOT accept it as a valid message \
			 (got {:?} bytes)",
			bytes.len()
		),
		Err(error) => format!("{error}"),
	};
	assert!(
		message.contains("incorrect rdata length") || message.contains("rdata length"),
		"expected the rdata-length decode error documented in the systemd-resolved \
		 truncation incident, got: {message}",
	);
}

#[test]
fn shared_system_resolver_options_enable_dnssec() {
	let options = super::system_resolver_options();
	assert!(
		options.validate,
		"DNSSEC validation must stay enabled so DANE TLSA records stay trustworthy (RFC 7672 §2.1)",
	);
}