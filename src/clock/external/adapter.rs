//! Thin wrapper around the maintained `ntp-proto` crate. All NTPv4 and
//! NTS-KE protocol logic lives behind this module so the public area
//! deals only with [`crate::clock::external::ProbeReading`] and the
//! assessed median/verdict.
//!
//! Exposes:
//! - [`ke_then_ntp`]: TLS 1.3 NTS key exchange plus one authenticated NTP
//!   measurement, returning a signed offset and round-trip delay.
//! - [`plain_ntp`]: one plaintext NTPv4 exchange, returning a signed
//!   offset and round-trip delay.
//!
//! Timestamps T1 (client send) and T4 (client receive) are captured at
//! the socket edge so DNS, dial, TLS and KE do not appear as network
//! delay. Cookies and AEAD keys never reach the log path; only the
//! short surfaced error string does.
//!
//! The crypto provider for [`ntp_proto::KeyExchangeClient`] is
//! installed once through [`crate::tls::ensure_crypto_provider`]
//! before the first TLS handshake. That is the same hook
//! `acceptor()` in `src/tls` uses, so the rest of the process sees a
//! single deterministic provider instead of picking one at random.
//!
//! Every entry point takes one `deadline` and spends it once. The wait
//! on each stage is armed against the same instant rather than against
//! a fresh copy of the deadline, so the caller gets the budget it asked
//! for and not one per stage.

use std::borrow::Cow;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls_pki_types::CertificateDer;
use tokio::net::UdpSocket;
use tokio::time::timeout_at;

use ntp_proto::{KeyExchangeClient, NtpPacket, NtsClientConfig, PollInterval, ProtocolVersion};

use crate::clock::external::source::{NTP_PORT, NTS_KE_PORT, Source, SourceKind};

/// Time the whole probe is allowed to spend (DNS + dial + handshake +
/// KE + receive).
#[allow(dead_code)]
pub(crate) const DEFAULT_SOURCE_DEADLINE: Duration = Duration::from_secs(2);

/// Maximum UDP datagram an NTP source may emit; we keep one extra byte
/// at receive time to catch oversize cleanly.
pub(crate) const UDP_RECV_BUFFER: usize = 4096;

/// Size of the NTP/NTS request buffer. The protocol fits well under 1 KiB.
const REQUEST_BUFFER: usize = 1024;

/// Seconds between the Unix epoch (1970-01-01) and the NTP epoch
/// (1900-01-01). Used to align `SystemTime` with NTP timestamps.
const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;

/// What a successful probe reports.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OneShot {
	/// Remote minus local, in seconds. Positive means the host clock is
	/// behind the remote.
	pub offset_seconds: f64,
	/// Round-trip delay in seconds the NTP exchange measured.
	pub delay_seconds: f64,
}

/// What went wrong during a probe. Cookies, keys and full certificates
/// never appear here; only the surfaced reason string does.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeError {
	/// The whole probe exceeded the deadline.
	Timeout,
	/// DNS or TCP dial did not complete.
	Dial(String),
	/// The NTS TLS handshake failed (certificate, ALPN, version).
	Tls(String),
	/// The NTS-KE reply was rejected by `ntp-proto`.
	Ke(String),
	/// The plain NTP reply did not match the request (origin/uid/stratum).
	BadReply(String),
	/// The reply was malformed (truncated, oversize, wrong magic).
	Malformed(String),
	/// The remote answered a Kiss-o'-Death code.
	Kiss(String),
	/// The local clock stepped during the probe; the measurement is invalid.
	LocalJump,
}

impl std::fmt::Display for ProbeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ProbeError::Timeout => f.write_str("probe exceeded the deadline"),
			ProbeError::Dial(why) => write!(f, "dial: {why}"),
			ProbeError::Tls(why) => write!(f, "TLS handshake: {why}"),
			ProbeError::Ke(why) => write!(f, "NTS-KE: {why}"),
			ProbeError::BadReply(why) => write!(f, "bad reply: {why}"),
			ProbeError::Malformed(why) => write!(f, "malformed reply: {why}"),
			ProbeError::Kiss(why) => write!(f, "kiss-of-death: {why}"),
			ProbeError::LocalJump => f.write_str("local clock jumped during the probe"),
		}
	}
}

impl std::error::Error for ProbeError {}

/// Run a single NTS-KE-over-TLS handshake followed by one authenticated
/// NTPv4 measurement.
///
/// The TLS handshake is performed inside [`KeyExchangeClient`]: it
/// owns its own rustls config plus a [`ntp_proto::tls_utils::PlatformVerifier`]
/// rooted in the operating system trust store. We pass the raw
/// `TcpStream` straight through and let the kex do the wrap so we
/// are not racing the stream through two TLS layers. The
/// `crate::tls::ensure_crypto_provider` hook in front picks the ring
/// provider before the first call so the builder has a single
/// deterministic provider to fall back on.
///
/// `deadline` bounds the whole probe, dial and key exchange included,
/// not each stage of it: every wait below is armed against the same
/// instant, so a server that accepts the connection and then stalls
/// costs the operator one `deadline` and not one per stage.
pub async fn ke_then_ntp(source: &Source, deadline: Duration) -> Result<OneShot, ProbeError> {
	ke_then_ntp_with_roots(source, deadline, &[]).await
}

/// [`ke_then_ntp`] with certificate roots the operating system trust
/// store does not carry. Production passes none; the fake-server test
/// under `tests/` injects the root of its own throwaway certificate.
pub(crate) async fn ke_then_ntp_with_roots(
	source: &Source,
	deadline: Duration,
	extra_roots: &[CertificateDer<'static>],
) -> Result<OneShot, ProbeError> {
	crate::tls::ensure_crypto_provider();
	let stop = Instant::now() + deadline;
	let host = source.host.clone();
	let port = source.dial_port();
	let tcp = timeout_at(
		stop.into(),
		tokio::net::TcpStream::connect((host.as_str(), port)),
	)
	.await
	.map_err(|_| ProbeError::Timeout)?
	.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let config = NtsClientConfig {
		certificates: Arc::from(extra_roots.to_vec()),
		protocol_version: ProtocolVersion::V4,
	};
	let kex =
		KeyExchangeClient::new(&config).map_err(|error| ProbeError::Tls(error.to_string()))?;
	let result = timeout_at(
		stop.into(),
		kex.exchange_keys(tcp, host.clone(), std::iter::empty::<Cow<str>>()),
	)
	.await
	.map_err(|_| ProbeError::Timeout)?
	.map_err(|error| ProbeError::Ke(error.to_string()))?;
	exchange_via_nts(result.remote, result.port, *result.nts, source, stop).await
}

/// One authenticated NTP exchange using cookies and keys from a prior
/// NTS-KE. The probe owns no state; this is a self-contained measurement.
async fn exchange_via_nts(
	remote: String,
	remote_port: u16,
	mut nts_data: ntp_proto::SourceNtsData,
	source: &Source,
	stop: Instant,
) -> Result<OneShot, ProbeError> {
	let port = if remote_port != 0 {
		remote_port
	} else {
		source.dial_port()
	};
	let cookie = nts_data
		.get_cookie()
		.ok_or_else(|| ProbeError::Ke("no cookie to send".into()))?;
	let (c2s_box, s2c_box) = nts_data.get_keys();
	let ntp_port = if source.kind == SourceKind::Nts && port == NTS_KE_PORT {
		NTP_PORT
	} else {
		port
	};
	let poll = PollInterval::default();
	let (packet, identifier) = NtpPacket::nts_poll_message(&cookie, 0, poll);
	let mut buf = vec![0u8; REQUEST_BUFFER];
	let length = {
		let c2s: Option<&dyn ntp_proto::Cipher> = Some(c2s_box.as_ref());
		let mut cursor = Cursor::new(buf.as_mut_slice());
		packet
			.serialize(&mut cursor, &c2s, None)
			.map_err(|error| ProbeError::Malformed(error.to_string()))?;
		cursor.position() as usize
	};
	if length == 0 {
		return Err(ProbeError::Malformed("serialized request empty".into()));
	}
	let bind = timeout_at(
		stop.into(),
		UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)),
	)
	.await
	.map_err(|_| ProbeError::Timeout)?
	.map_err(|error| ProbeError::Dial(error.to_string()))?;
	timeout_at(stop.into(), bind.connect((remote.as_str(), ntp_port)))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let t1_wall = SystemTime::now();
	timeout_at(stop.into(), bind.send(&buf[..length]))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let mut reply = [0u8; UDP_RECV_BUFFER + 1];
	let (size, _peer) = timeout_at(stop.into(), bind.recv_from(&mut reply))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let t4_wall = SystemTime::now();
	let round_trip = t4_wall
		.duration_since(t1_wall)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0);
	if round_trip > 1.0 {
		return Err(ProbeError::LocalJump);
	}
	let reply_cipher: Option<&dyn ntp_proto::Cipher> = Some(s2c_box.as_ref());
	let (response, _cookie) =
		NtpPacket::deserialize(&reply[..size], &reply_cipher).map_err(|error| match error {
			ntp_proto::PacketParsingError::DecryptError(_) => {
				ProbeError::BadReply("decrypt failed".into())
			}
			other => ProbeError::Malformed(format!("{other:?}")),
		})?;
	// Check the reply belongs to this request (origin timestamp, and the unique
	// identifier on the NTS path) before it is trusted for anything, a kiss code
	// included: an off-path packet must not be able to fail the probe.
	if !response.valid_server_response(identifier, true) {
		return Err(ProbeError::BadReply(
			"origin/uid does not match the request".into(),
		));
	}
	if response.is_kiss_deny() {
		return Err(ProbeError::Kiss("DENY".into()));
	}
	if response.is_kiss_rate(PollInterval::default()) {
		return Err(ProbeError::Kiss("RATE".into()));
	}
	let t1 = unix_seconds(t1_wall);
	let t4 = unix_seconds(t4_wall);
	let t2 = ntp_to_unix_seconds(response.receive_timestamp());
	let t3 = ntp_to_unix_seconds(response.transmit_timestamp());
	let offset = (t2 - t1 + t3 - t4) / 2.0;
	let delay = (t4 - t1) - (t3 - t2);
	Ok(OneShot {
		offset_seconds: offset,
		delay_seconds: delay.abs(),
	})
}

/// One plaintext NTPv4 exchange. Returns the signed offset and the
/// round-trip delay. `deadline` bounds the whole exchange the same way
/// [`ke_then_ntp`] bounds the authenticated one.
pub async fn plain_ntp(source: &Source, deadline: Duration) -> Result<OneShot, ProbeError> {
	let stop = Instant::now() + deadline;
	let host = source.host.clone();
	let port = source.dial_port();
	let bind = timeout_at(
		stop.into(),
		UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)),
	)
	.await
	.map_err(|_| ProbeError::Timeout)?
	.map_err(|error| ProbeError::Dial(error.to_string()))?;
	timeout_at(stop.into(), bind.connect((host.as_str(), port)))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let poll = PollInterval::default();
	let (packet, identifier) = NtpPacket::poll_message(poll);
	let mut buf = vec![0u8; REQUEST_BUFFER];
	let length = {
		let mut cursor = Cursor::new(buf.as_mut_slice());
		packet
			.serialize(&mut cursor, &ntp_proto::NoCipher, None)
			.map_err(|error| ProbeError::Malformed(error.to_string()))?;
		cursor.position() as usize
	};
	if length == 0 {
		return Err(ProbeError::Malformed("serialized request empty".into()));
	}
	let t1_wall = SystemTime::now();
	timeout_at(stop.into(), bind.send(&buf[..length]))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let mut reply = [0u8; UDP_RECV_BUFFER + 1];
	let (size, _peer) = timeout_at(stop.into(), bind.recv_from(&mut reply))
		.await
		.map_err(|_| ProbeError::Timeout)?
		.map_err(|error| ProbeError::Dial(error.to_string()))?;
	let t4_wall = SystemTime::now();
	if t4_wall
		.duration_since(t1_wall)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0)
		> 1.0
	{
		return Err(ProbeError::LocalJump);
	}
	if size > UDP_RECV_BUFFER {
		return Err(ProbeError::Malformed("datagram oversize".into()));
	}
	let (response, _cookie) = NtpPacket::deserialize(&reply[..size], &ntp_proto::NoCipher)
		.map_err(|error| ProbeError::Malformed(format!("{error:?}")))?;
	// Check the reply belongs to this request (origin timestamp, and the unique
	// identifier on the NTS path) before it is trusted for anything, a kiss code
	// included: an off-path packet must not be able to fail the probe.
	if !response.valid_server_response(identifier, false) {
		return Err(ProbeError::BadReply(
			"origin does not match the request".into(),
		));
	}
	if response.is_kiss_deny() {
		return Err(ProbeError::Kiss("DENY".into()));
	}
	if response.is_kiss_rate(PollInterval::default()) {
		return Err(ProbeError::Kiss("RATE".into()));
	}
	let t1 = unix_seconds(t1_wall);
	let t4 = unix_seconds(t4_wall);
	let t2 = ntp_to_unix_seconds(response.receive_timestamp());
	let t3 = ntp_to_unix_seconds(response.transmit_timestamp());
	let offset = (t2 - t1 + t3 - t4) / 2.0;
	let delay = (t4 - t1) - (t3 - t2);
	Ok(OneShot {
		offset_seconds: offset,
		delay_seconds: delay.abs(),
	})
}

/// Convert a `SystemTime` to Unix seconds (f64).
fn unix_seconds(time: SystemTime) -> f64 {
	time.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0)
}

/// Convert an `NtpTimestamp` to Unix seconds (f64). NTP timestamps
/// are seconds since the NTP epoch (1900-01-01); we subtract the
/// 70-year offset to land in Unix seconds. The `ntp-proto` crate
/// exposes the timestamp bits only via its `Debug` impl; the public
/// subtraction + `to_seconds` path wraps for era 0 timestamps past
/// the 2036 boundary, so we read the bits through `{:?}` instead.
fn ntp_to_unix_seconds(ts: ntp_proto::NtpTimestamp) -> f64 {
	let raw_str = format!("{ts:?}");
	let raw: u64 = raw_str
		.strip_prefix("NtpTimestamp(")
		.and_then(|s| s.strip_suffix(")"))
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(0);
	let seconds = (raw >> 32) as f64;
	let fraction = (raw & 0xFFFF_FFFF) as f64 / 4_294_967_296.0;
	seconds + fraction - NTP_UNIX_OFFSET
}

#[cfg(test)]
#[path = "tests/adapter_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/nts_ke_tests.rs"]
mod nts_ke_tests;
