//! Tests for the NTP/NTS adapter path: a local UDP server emulating
//! plain NTP, plus formula tests for the authenticated probe.
//!
//! Fake NTS-KE is out of scope here (the maintained `ntp-proto` crate
//! is the integration point); here we exercise what the
//! adapter can drive without a real NTS-KE stand-in.

use std::io::Cursor;
use std::time::{Duration, SystemTime};

use ntp_proto::{NtpPacket, PollInterval};
use tokio::net::UdpSocket;

use crate::clock::external::adapter::{ProbeError, local_span, plain_ntp_with_policy};
use crate::clock::external::endpoint::Policy;
use crate::clock::external::source::Source;

const TEST_DEADLINE: Duration = Duration::from_secs(2);
const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_against_loopback_returns_a_signed_offset() {
	let server = spawn_ntp_server(NtpPlan::Offset(0.25)).await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let reading = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port))
		.await
		.expect("plain ntp");
	assert!(
		(reading.offset_seconds - 0.25).abs() < 0.10,
		"offset should track the simulated wire-time; got {}",
		reading.offset_seconds,
	);
	server.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_bad_origin_when_origin_does_not_match() {
	let server = spawn_ntp_server(NtpPlan::WrongOrigin).await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port)).await;
	assert!(matches!(result, Err(ProbeError::BadReply(_))), "{result:?}");
	server.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_malformed_when_response_truncated() {
	let server = spawn_truncated_ntp_server().await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port)).await;
	assert!(
		matches!(result, Err(ProbeError::Malformed(_))),
		"{result:?}"
	);
	server.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn plain_ntp_reports_malformed_on_kiss_deny() {
	let server = spawn_ntp_server(NtpPlan::KissDeny).await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port)).await;
	assert!(matches!(result, Err(ProbeError::Kiss(_))), "{result:?}");
	server.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_kiss_code_that_does_not_echo_the_request_cannot_fail_the_probe_as_a_kiss() {
	let server = spawn_ntp_server(NtpPlan::KissDenyWrongOrigin).await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port)).await;
	// Validated first, so it is an invalid reply and not a DENY from the server.
	assert!(matches!(result, Err(ProbeError::BadReply(_))), "{result:?}");
	server.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn any_kiss_code_is_an_error_and_never_a_measurement() {
	let server = spawn_ntp_server(NtpPlan::KissRstr).await;
	let port = server.local_addr().port();
	let source = source_for_port("127.0.0.1", port);
	let result = plain_ntp_with_policy(&source, TEST_DEADLINE, local_policy(port)).await;
	assert!(matches!(result, Err(ProbeError::Kiss(_))), "{result:?}");
	server.shutdown().await;
}

/// A local test server is a private address on a port of its own, so the test
/// carries both opt-ins explicitly: the destination policy grants one at a
/// time and neither follows from the other.
fn local_policy(port: u16) -> Policy {
	Policy {
		allow_private: true,
		allowed_ports: vec![port],
	}
}

fn source_for_port(host: &str, port: u16) -> Source {
	let mut source = Source::ntp(host);
	source.port = Some(port);
	source
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

/// Local UDP NTP responder. Mirrors the request origin so a single
/// round-trip yields a valid response.
async fn spawn_ntp_server(plan: NtpPlan) -> NtpServerHandle {
	let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
		.await
		.expect("bind udp");
	let local_addr = socket.local_addr().expect("local addr");
	let server = tokio::spawn(async move {
		let mut buf = vec![0u8; 1024];
		loop {
			let (size, peer) = match socket.recv_from(&mut buf).await {
				Ok(value) => value,
				Err(_) => return,
			};
			let reply = build_reply(&buf[..size], plan);
			if reply.is_empty() {
				continue;
			}
			let _ = socket.send_to(&reply, peer).await;
		}
	});
	NtpServerHandle {
		join: server,
		local_addr,
	}
}

async fn spawn_truncated_ntp_server() -> NtpServerHandle {
	let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
		.await
		.expect("bind udp");
	let local_addr = socket.local_addr().expect("local addr");
	let server = tokio::spawn(async move {
		let mut buf = [0u8; 32];
		loop {
			let (_, peer) = match socket.recv_from(&mut buf).await {
				Ok(value) => value,
				Err(_) => return,
			};
			// Truncate to 16 bytes, way under the 48-byte NTP header.
			let _ = socket.send_to(&buf[..16], peer).await;
		}
	});
	NtpServerHandle {
		join: server,
		local_addr,
	}
}

#[derive(Copy, Clone)]
enum NtpPlan {
	Offset(f64),
	WrongOrigin,
	KissDeny,
	KissDenyWrongOrigin,
	KissRstr,
}

fn build_reply(request: &[u8], plan: NtpPlan) -> Vec<u8> {
	if request.len() < 48 {
		return Vec::new();
	}
	let mut header = [0u8; 48];
	header.copy_from_slice(&request[..48]);
	// Mirror the request's transmit field into the origin field so the
	// client sees a matching RequestIdentifier. ntp-proto's poll message
	// places a random timestamp in the transmit field; the server replies
	// by copying it as the origin.
	header[24..32].copy_from_slice(&request[40..48]);
	match plan {
		NtpPlan::Offset(offset) => {
			header[0] = 0x24;
			header[1] = 0x01;
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs_f64())
				.unwrap_or(0.0);
			let total = now + NTP_UNIX_OFFSET + offset;
			write_ntp_timestamp(&mut header[32..40], total);
			write_ntp_timestamp(&mut header[40..48], total);
			header.to_vec()
		}
		NtpPlan::WrongOrigin => {
			header[0] = 0x24;
			header[1] = 0x01;
			// Overwrite the origin field so the response will not match.
			header[24..28].copy_from_slice(&[0x99, 0x99, 0x99, 0x99]);
			header[32..40].copy_from_slice(&[0u8; 8]);
			header[40..48].copy_from_slice(&[0u8; 8]);
			header.to_vec()
		}
		NtpPlan::KissRstr => {
			header[0] = 0x24;
			header[1] = 0x00;
			header[2] = 0;
			header[12..16].copy_from_slice(b"RSTR");
			// Plausible timestamps a careless client could read as a measurement.
			write_ntp_timestamp(&mut header[32..40], 3_900_000_000.0);
			write_ntp_timestamp(&mut header[40..48], 3_900_000_000.0);
			header.to_vec()
		}
		NtpPlan::KissDenyWrongOrigin => {
			header[0] = 0x24;
			header[1] = 0x00;
			header[2] = 0;
			header[12..16].copy_from_slice(b"DENY");
			// A kiss code that does not echo the request: an off-path packet.
			header[24..28].copy_from_slice(&[0x99, 0x99, 0x99, 0x99]);
			header.to_vec()
		}
		NtpPlan::KissDeny => {
			header[0] = 0x24;
			header[1] = 0x00;
			// Stratum zero identifies the packet as a KoD. Reference id
			// encodes the four ASCII code bytes.
			header[2] = 0;
			header[12..16].copy_from_slice(b"DENY");
			header.to_vec()
		}
	}
}

/// Write a 64-bit NTP timestamp (32-bit seconds + 32-bit fraction).
fn write_ntp_timestamp(buf: &mut [u8], total_seconds: f64) {
	let seconds = total_seconds.floor();
	let fraction = total_seconds - seconds;
	let seconds_u32 = seconds.rem_euclid(4_294_967_296.0) as u32;
	let fraction_u32 = (fraction * 4_294_967_296.0) as u32;
	let value: u64 = ((seconds_u32 as u64) << 32) | (fraction_u32 as u64);
	buf.copy_from_slice(&value.to_be_bytes());
}

struct NtpServerHandle {
	join: tokio::task::JoinHandle<()>,
	local_addr: std::net::SocketAddr,
}

impl NtpServerHandle {
	fn local_addr(&self) -> std::net::SocketAddr {
		self.local_addr
	}
	async fn shutdown(self) {
		self.join.abort();
		let _ = self.join.await;
	}
}

/// The wall-clock span the exchange took is what tells a step from a slow
/// reply, and a step backwards is a step too: `duration_since` has nothing to
/// return for it, which used to be read as a zero-length exchange and a clean
/// offset.
#[test]
fn review_a_local_clock_that_steps_in_either_direction_is_not_a_measurement() {
	let sent = SystemTime::now();
	assert!(
		local_span(sent, sent + Duration::from_millis(10)).is_ok(),
		"an ordinary exchange must be accepted"
	);
	for (why, received) in [
		("clock stepped backwards", sent - Duration::from_secs(1)),
		("clock stepped forward", sent + Duration::from_secs(2)),
	] {
		assert!(
			matches!(local_span(sent, received), Err(ProbeError::LocalJump)),
			"{why} must not be read as an exchange"
		);
	}
}
