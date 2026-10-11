//! Spaceship provider tests for the record types with structured RDATA.
//! Split from `spaceship_tests.rs` for the per-file line limit; the mock lives
//! in the first half.
//!
//! Spaceship takes dedicated JSON fields rather than a presentation-form
//! string, and its field names differ per type (`target` for SRV, `flag` for
//! CAA, `exchange` for MX). Getting one wrong publishes a record that parses
//! and means something else, which is why each has its own assertion.

use super::tests::{Shared, mock};
use super::*;

fn record(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind,
		value: value.to_string(),
		ttl: 3600,
	}
}

/// The body of the PUT that carries the new record.
fn put_body(state: &Shared) -> String {
	state
		.lock()
		.unwrap()
		.bodies
		.iter()
		.rev()
		.find(|b| b.contains("\"items\""))
		.expect("a PUT body")
		.clone()
}

#[tokio::test]
async fn srv_upsert_sends_priority_weight_port_and_target() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert(
			"example.org",
			record(
				"_submissions._tcp.example.org",
				RecordKind::Srv,
				"10 5 465 mail.example.org",
			),
		)
		.await
		.expect("srv upsert");
	let body = put_body(&state);
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
	assert!(body.contains("\"weight\":5"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"target\":\"mail.example.org\""), "{body}");
}

#[tokio::test]
async fn caa_upsert_sends_flag_tag_and_value() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert(
			"example.org",
			record(
				"example.org",
				RecordKind::Caa,
				"0 issue \"letsencrypt.org\"",
			),
		)
		.await
		.expect("caa upsert");
	let body = put_body(&state);
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	// `flag`, singular — Spaceship's spelling, not DigitalOcean's `priority`.
	assert!(body.contains("\"flag\":0"), "{body}");
	assert!(body.contains("\"tag\":\"issue\""), "{body}");
	assert!(body.contains("\"value\":\"letsencrypt.org\""), "{body}");
}

#[tokio::test]
async fn mx_upsert_sends_preference_and_exchange() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert(
			"example.org",
			record("example.org", RecordKind::Mx, "10 mail.example.org"),
		)
		.await
		.expect("mx upsert");
	let body = put_body(&state);
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"exchange\":\"mail.example.org\""), "{body}");
	assert!(body.contains("10"), "{body}");
}

#[tokio::test]
async fn a_malformed_srv_value_is_refused_rather_than_published() {
	let (provider, _state) = mock(Vec::new()).await;
	let error = provider
		.upsert(
			"example.org",
			record("_x._tcp.example.org", RecordKind::Srv, "nonsense"),
		)
		.await
		.expect_err("a value we cannot split must not be sent");
	assert!(matches!(error, ProviderError::Remote(_)), "{error:?}");
}

#[tokio::test]
async fn a_caa_value_missing_a_field_is_refused() {
	let (provider, _state) = mock(Vec::new()).await;
	let error = provider
		.upsert(
			"example.org",
			record("example.org", RecordKind::Caa, "0 issue"),
		)
		.await
		.expect_err("an incomplete CAA must not be sent");
	assert!(matches!(error, ProviderError::Remote(_)), "{error:?}");
}
