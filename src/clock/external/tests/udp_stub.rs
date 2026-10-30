//! A local UDP server that answers as an NTP source, or stays silent.
//!
//! The stub binds the loopback address of the machine that runs the test
//! and answers on a port of its own, so a probe can be pointed at it
//! without a route to the outside. The destination policy of the probe
//! refuses the loopback by default, so the test asks for that address and
//! for that port explicitly; the production policy is not relaxed.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::clock::external::endpoint::Policy;
use crate::clock::external::source::Source;

/// Seconds between the Unix epoch (1970-01-01) and the NTP epoch (1900-01-01).
const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;

/// How long the thread waits for a datagram before it looks at the flag
/// that tells it to stop.
const READ_TIMEOUT: Duration = Duration::from_millis(50);

/// What the stub answers with.
#[derive(Copy, Clone)]
pub(in super::super) enum NtpPlan {
	/// A valid server reply whose timestamps carry `offset` seconds.
	Offset(f64),
	/// A valid server reply that arrives late.
	Late(Duration),
	/// A reply whose origin field does not echo the request.
	WrongOrigin,
	/// A kiss-o'-death reply with the DENY code.
	KissDeny,
	/// A kiss-o'-death reply that does not echo the request.
	KissDenyWrongOrigin,
	/// A kiss-o'-death reply with the RSTR code.
	KissRstr,
	/// A reply cut short, under the size of the NTP header.
	Truncated,
	/// No reply at all.
	Silent,
}

impl NtpPlan {
	/// The offset the reply carries, in seconds.
	fn offset(self) -> f64 {
		match self {
			NtpPlan::Offset(offset) => offset,
			_ => 0.0,
		}
	}
}

/// The stub, bound to a port on the loopback address.
pub(in super::super) struct NtpStub {
	port: u16,
	stop: Arc<AtomicBool>,
	join: Option<JoinHandle<()>>,
}

impl NtpStub {
	/// Bind the stub and start the thread that answers it.
	pub(in super::super) fn spawn(plan: NtpPlan) -> Self {
		let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the udp stub");
		socket
			.set_read_timeout(Some(READ_TIMEOUT))
			.expect("the read timeout of the stub");
		let port = socket
			.local_addr()
			.expect("the local address of the stub")
			.port();
		let stop = Arc::new(AtomicBool::new(false));
		let flag = Arc::clone(&stop);
		let join = std::thread::spawn(move || serve(socket, plan, flag));
		NtpStub {
			port,
			stop,
			join: Some(join),
		}
	}

	/// The port the stub answers on.
	pub(in super::super) fn port(&self) -> u16 {
		self.port
	}
}

impl Drop for NtpStub {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Relaxed);
		if let Some(join) = self.join.take() {
			let _ = join.join();
		}
	}
}

/// The policy a local stub needs: the loopback address is a private one and
/// the stub answers on a port of its own, so the test asks for both.
pub(in super::super) fn local_policy(port: u16) -> Policy {
	Policy {
		allow_private: true,
		allowed_ports: vec![port],
	}
}

/// A source that points at the local stub.
pub(in super::super) fn source_for_port(port: u16) -> Source {
	let mut source = Source::ntp("127.0.0.1");
	source.port = Some(port);
	source
}

/// Answer every datagram the stub receives until it is told to stop.
fn serve(socket: UdpSocket, plan: NtpPlan, stop: Arc<AtomicBool>) {
	let mut buf = vec![0u8; 1024];
	while !stop.load(Ordering::Relaxed) {
		let (size, peer) = match socket.recv_from(&mut buf) {
			Ok(value) => value,
			Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
			Err(_) => return,
		};
		match plan {
			NtpPlan::Silent => continue,
			NtpPlan::Late(delay) => wait(&stop, delay),
			_ => {}
		}
		let reply = build_reply(&buf[..size], plan);
		if reply.is_empty() {
			continue;
		}
		let _ = socket.send_to(&reply, peer);
	}
}

/// Sleep in short steps, so the thread notices it has been told to stop.
fn wait(stop: &AtomicBool, total: Duration) {
	let mut left = total;
	while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
		let chunk = left.min(READ_TIMEOUT);
		std::thread::sleep(chunk);
		left -= chunk;
	}
}

/// Build the answer to a request, following the plan.
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
		NtpPlan::Offset(_) | NtpPlan::Late(_) => {
			header[0] = 0x24;
			header[1] = 0x01;
			let now = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map(|d| d.as_secs_f64())
				.unwrap_or(0.0);
			let total = now + NTP_UNIX_OFFSET + plan.offset();
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
		NtpPlan::Truncated => request[..16].to_vec(),
		NtpPlan::Silent => Vec::new(),
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
