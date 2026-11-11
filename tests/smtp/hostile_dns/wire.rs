//! Bounded loopback authority; the production resolver performs every lookup.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use epistle::spf::SystemDns;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::{
	Name, RData, Record,
	rdata::{CNAME, TXT},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

use super::smtp_harness::AbortOnDrop;

#[derive(Clone, Copy)]
pub enum Reply {
	Loop,
	LargeTxt,
	Thousand,
	Nodata,
	Nxdomain,
	Servfail,
}

/// Lookups after which the TCP authority gives up on a client as a storm.
/// Above what a screen capped at 50 hosts needs: two lookups per host, each
/// asking for A and AAAA.
const STORM: usize = 512;

pub struct Wire {
	pub dns: SystemDns,
	queries: Arc<AtomicUsize>,
	_task: AbortOnDrop,
}

impl Wire {
	pub async fn tcp(reply: Reply) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind DNS TCP");
		let port = listener.local_addr().expect("DNS address").port();
		let queries = Arc::new(AtomicUsize::new(0));
		let count = queries.clone();
		let task = tokio::spawn(async move {
			// Dropping the accept task also aborts all open connections.
			let mut clients = JoinSet::new();
			loop {
				tokio::select! {
					accepted = listener.accept() => {
						let (stream, _) = accepted.expect("accept DNS");
						clients.spawn(serve(stream, reply, count.clone()));
					}
					Some(result) = clients.join_next(), if !clients.is_empty() => {
						result.expect("DNS fixture task");
					}
				}
			}
		});
		Self {
			dns: resolver(port, false),
			queries,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	/// Return TC=1 over UDP with a tempting partial policy, while TCP at
	/// this port refuses connections. This is not a generic SERVFAIL test.
	pub async fn truncated_without_tcp() -> Self {
		// Reserve the same TCP port without listening: deterministic refusal.
		// The kernel picks the UDP port; another test may hold a TCP listener
		// on that number, so a taken one is given up and another is drawn.
		let (socket, reserved) = {
			let mut attempts = 0;
			loop {
				let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind DNS UDP");
				let port = socket.local_addr().expect("DNS address").port();
				let reserved =
					socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
						.expect("reserve refused TCP port");
				match reserved.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into()) {
					Ok(()) => break (socket, reserved),
					Err(error)
						if attempts < 100 && error.kind() == std::io::ErrorKind::AddrInUse =>
					{
						attempts += 1;
					}
					Err(error) => panic!("reserve DNS TCP address: {error}"),
				}
			}
		};
		let port = socket.local_addr().expect("DNS address").port();
		let queries = Arc::new(AtomicUsize::new(0));
		let count = queries.clone();
		let task = tokio::spawn(async move {
			let _reserved = reserved;
			let mut buffer = [0u8; 4096];
			loop {
				let (n, peer) = socket.recv_from(&mut buffer).await.expect("DNS datagram");
				let query = Message::from_vec(&buffer[..n]).expect("decode query");
				assert!(
					count.fetch_add(1, Ordering::Relaxed) < 64,
					"DNS query storm"
				);
				let mut answer = response(&query, Reply::Nodata);
				answer.metadata.truncation = true;
				let owner = query.queries[0].name().clone();
				answer.add_answer(txt(owner.clone(), policy(&owner, "pass")));
				socket
					.send_to(&answer.to_vec().expect("encode TC"), peer)
					.await
					.expect("send TC");
			}
		});
		Self {
			dns: resolver(port, true),
			queries,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub fn assert_queries(&self) {
		check_queries(&self.queries);
	}

	/// Hand the resolver to a listener, which needs to own it. The authority
	/// keeps running for as long as the returned guard lives.
	pub fn shared(self) -> (Arc<SystemDns>, Authority) {
		let authority = Authority {
			queries: self.queries,
			_task: self._task,
		};
		(Arc::new(self.dns), authority)
	}
}

/// The running authority of a `Wire` whose resolver was handed away.
pub struct Authority {
	queries: Arc<AtomicUsize>,
	_task: AbortOnDrop,
}

impl Authority {
	pub fn queries(&self) -> usize {
		self.queries.load(Ordering::Relaxed)
	}
}

fn check_queries(queries: &AtomicUsize) {
	let count = queries.load(Ordering::Relaxed);
	assert!(
		(1..=64).contains(&count),
		"expected bounded real DNS traffic, got {count}"
	);
}

fn resolver(port: u16, udp: bool) -> SystemDns {
	let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
	let mut server = if udp {
		NameServerConfig::udp_and_tcp(ip)
	} else {
		NameServerConfig::tcp(ip)
	};
	for connection in &mut server.connections {
		connection.port = port;
	}
	let mut opts = ResolverOpts::default();
	opts.validate = false; // This local authority has no DNSSEC signing keys.
	opts.use_hosts_file = ResolveHosts::Never;
	opts.cache_size = 0;
	opts.attempts = 1;
	opts.timeout = Duration::from_millis(200);
	SystemDns::with_config(ResolverConfig::from_name_servers(vec![server]), opts).expect("resolver")
}

async fn serve(mut stream: TcpStream, reply: Reply, count: Arc<AtomicUsize>) {
	loop {
		let Ok(len) = stream.read_u16().await else {
			return;
		};
		let mut body = vec![0; usize::from(len)];
		if stream.read_exact(&mut body).await.is_err() {
			return;
		}
		let query = Message::from_vec(&body).expect("decode query");
		assert!(
			count.fetch_add(1, Ordering::Relaxed) < STORM,
			"DNS query storm"
		);
		let bytes = response(&query, reply).to_vec().expect("encode response");
		let len = u16::try_from(bytes.len()).expect("response fits DNS TCP frame");
		if stream.write_u16(len).await.is_err() || stream.write_all(&bytes).await.is_err() {
			return;
		}
	}
}

fn txt(owner: Name, value: String) -> Record {
	// DNS character-strings are at most 255 bytes; concatenation must not
	// insert spaces. These fixtures contain ASCII only.
	let chunks = value
		.as_bytes()
		.chunks(255)
		.map(|s| String::from_utf8(s.to_vec()).unwrap())
		.collect();
	Record::from_rdata(owner, 0, RData::TXT(TXT::new(chunks)))
}

fn policy(owner: &Name, suffix: &str) -> String {
	let name = owner.to_utf8();
	if name.starts_with("_dmarc.") {
		format!("v=DMARC1; p=reject; x={suffix}")
	} else if name.starts_with("_mta-sts.") {
		format!("v=STSv1; id={suffix}")
	} else {
		format!("v=spf1 -all x={suffix}")
	}
}

fn response(query: &Message, reply: Reply) -> Message {
	let mut answer = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
	answer.metadata.recursion_desired = query.metadata.recursion_desired;
	answer.metadata.recursion_available = true;
	for q in &query.queries {
		answer.add_query(q.clone());
	}
	let owner = query.queries[0].name().clone();
	match reply {
		Reply::Loop => {
			answer.add_answer(Record::from_rdata(
				owner.clone(),
				0,
				RData::CNAME(CNAME(owner)),
			));
		}
		Reply::LargeTxt => {
			let name = owner.to_utf8();
			let prefix = if name.starts_with("_dmarc.") {
				"v=DMARC1; p="
			} else if name.starts_with("_mta-sts.") {
				"v=STSv1; id="
			} else {
				"v=spf1 "
			};
			let value = format!("{prefix}{}", "x".repeat(64_000 - prefix.len()));
			answer.add_answer(txt(owner, value));
		}
		Reply::Thousand => {
			for n in 0..1000 {
				answer.add_answer(txt(owner.clone(), policy(&owner, &n.to_string())));
			}
		}
		Reply::Nodata => {}
		Reply::Nxdomain => answer.metadata.response_code = ResponseCode::NXDomain,
		Reply::Servfail => answer.metadata.response_code = ResponseCode::ServFail,
	}
	answer
}
