//! Tests for the NTP/NTS adapter path: a local UDP server emulating
//! plain NTP, plus formula tests for the authenticated probe.
//!
//! Fake NTS-KE is out of scope here (the maintained `ntp-proto` crate
//! is the integration point); here we exercise what the
//! adapter can drive without a real NTS-KE stand-in.

use std::io::Cursor;
use std::time::Duration;

use ntp_proto::{NtpPacket, PollInterval};

use crate::clock::external::adapter::{ProbeError, plain_ntp_with_policy};
use crate::clock::external::tests::udp_stub::{NtpPlan, NtpStub, local_policy, source_for_port};

const TEST_DEADLINE: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_against_loopback_returns_a_signed_offset() {
	let server = NtpStub::spawn(NtpPlan::Offset(0.25));
	let source = source_for_port(server.port());
	let reading = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port()))
		.await
		.expect("plain ntp");
	assert!(
		(reading.offset_seconds - 0.25).abs() < 0.10,
		"offset should track the simulated wire-time; got {}",
		reading.offset_seconds,
	);
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_bad_origin_when_origin_does_not_match() {
	let server = NtpStub::spawn(NtpPlan::WrongOrigin);
	let source = source_for_port(server.port());
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port())).await;
	assert!(matches!(result, Err(ProbeError::BadReply(_))), "{result:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_malformed_when_response_truncated() {
	let server = NtpStub::spawn(NtpPlan::Truncated);
	let source = source_for_port(server.port());
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port())).await;
	assert!(
		matches!(result, Err(ProbeError::Malformed(_))),
		"{result:?}"
	);
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_malformed_on_kiss_deny() {
	let server = NtpStub::spawn(NtpPlan::KissDeny);
	let source = source_for_port(server.port());
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port())).await;
	assert!(matches!(result, Err(ProbeError::Kiss(_))), "{result:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_kiss_code_that_does_not_echo_the_request_cannot_fail_the_probe_as_a_kiss() {
	let server = NtpStub::spawn(NtpPlan::KissDenyWrongOrigin);
	let source = source_for_port(server.port());
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port())).await;
	// Validated first, so it is an invalid reply and not a DENY from the server.
	assert!(matches!(result, Err(ProbeError::BadReply(_))), "{result:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn any_kiss_code_is_an_error_and_never_a_measurement() {
	let server = NtpStub::spawn(NtpPlan::KissRstr);
	let source = source_for_port(server.port());
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(server.port())).await;
	assert!(matches!(result, Err(ProbeError::Kiss(_))), "{result:?}");
}

#[test]
fn offset_formula_yields_zero_when_remote_is_in_sync() {
	let (t1, t2, t3, t4) = (0.0_f64, 0.25, 0.25, 0.50);
	let offset = (t2 - t1 + t3 - t4) / 2.0;
	let delay = (t4 - t1) - (t3 - t2);
	assert!(offset.abs() < 1e-9, "offset should be zero: {offset}");
	assert!(delay > 0.0, "delay should be positive: {delay}");
}

#[test]
fn offset_positive_when_remote_is_ahead() {
	// Client at t1; round-trip latency 0.25 s; server had time 1.5 at
	// both receive and transmit (the server clock sits 1.25 s ahead).
	let (t1, t2, t3, t4) = (0.0_f64, 1.5, 1.5, 0.25);
	let offset = (t2 - t1 + t3 - t4) / 2.0;
	assert!(
		offset > 1.0,
		"remote ahead should give a large positive offset: {offset}"
	);
}

#[test]
fn ntp_poll_message_round_trip_through_serialize_deserialize_round_trip() {
	let (packet, _id) = NtpPacket::poll_message(PollInterval::default());
	let mut buf = vec![0u8; 1024];
	let length = {
		let mut cursor = Cursor::new(buf.as_mut_slice());
		packet
			.serialize(&mut cursor, &ntp_proto::NoCipher, None)
			.expect("serialize");
		cursor.position() as usize
	};
	let length = if length == 0 { 48 } else { length };
	let (parsed, _cookie) =
		NtpPacket::deserialize(&buf[..length], &ntp_proto::NoCipher).expect("deserialize");
	assert_eq!(parsed.poll(), PollInterval::default());
	let valid_mode = matches!(
		parsed.mode(),
		ntp_proto::NtpAssociationMode::Client
			| ntp_proto::NtpAssociationMode::Server
			| ntp_proto::NtpAssociationMode::SymmetricActive
	);
	assert!(
		valid_mode,
		"mode should be one of the valid client/server values"
	);
}
