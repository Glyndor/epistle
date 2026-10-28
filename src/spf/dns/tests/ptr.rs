//! Reverse lookups through [`SystemDns`] against an in-process resolver.
//!
//! Most reverse zones are unsigned, and some that are (deep `ip6.arpa`
//! delegations behind empty non-terminals) fail hickory's DNSSEC proof of
//! insecurity even though a validating `delv` reads them as plain unsigned
//! answers. Nobody trusts a PTR because of DNSSEC, so a reverse lookup must
//! not depend on validation: the fake server below never signs anything,
//! the way most of the reverse tree behaves.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::PTR;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{DnsLookup, SystemDns};

/// `2001:db8::25` in the `ip6.arpa` nibble format (RFC 3596 §2.5): the 32
/// hex digits of the address, least significant first, one label each.
const V6_REVERSE: &str =
	"5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
const V4_REVERSE: &str = "25.2.0.192.in-addr.arpa.";

/// Answer PTR queries for the names in `zone` and everything else with an
/// empty NOERROR, over DNS-over-TCP framing. Returns the listening port.
async fn spawn_resolver(zone: HashMap<&'static str, &'static str>) -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let zone = Arc::new(zone);
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			tokio::spawn(serve(stream, zone.clone()));
		}
	});
	port
}

async fn serve(mut stream: TcpStream, zone: Arc<HashMap<&'static str, &'static str>>) {
	loop {
		let mut len = [0u8; 2];
		if stream.read_exact(&mut len).await.is_err() {
			return;
		}
		let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
		if stream.read_exact(&mut body).await.is_err() {
			return;
		}
		let Ok(query) = Message::from_vec(&body) else {
			return;
		};
		let reply = answer(&query, &zone).to_vec().expect("encode reply");
		let framed = u16::try_from(reply.len()).expect("reply fits a frame");
		if stream.write_all(&framed.to_be_bytes()).await.is_err()
			|| stream.write_all(&reply).await.is_err()
		{
			return;
		}
	}
}

fn answer(query: &Message, zone: &HashMap<&'static str, &'static str>) -> Message {
	let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
	reply.metadata.response_code = ResponseCode::NoError;
	reply.metadata.recursion_desired = query.metadata.recursion_desired;
	reply.metadata.recursion_available = true;
	for question in &query.queries {
		reply.add_query(question.clone());
		let asked = question.name().to_ascii().to_ascii_lowercase();
		if question.query_type() == RecordType::PTR
			&& let Some(target) = zone.get(asked.as_str())
		{
			let target = Name::from_ascii(target).expect("target name");
			reply.add_answer(Record::from_rdata(
				question.name().clone(),
				300,
				RData::PTR(PTR(target)),
			));
		}
	}
	reply
}

/// A resolver built the way production builds it (DNSSEC validation on)
/// but pointed at the fake server.
fn resolver(port: u16) -> SystemDns {
	let mut server = NameServerConfig::tcp(IpAddr::V4(Ipv4Addr::LOCALHOST));
	for connection in &mut server.connections {
		connection.port = port;
	}
	let mut opts = ResolverOpts::default();
	opts.validate = true;
	opts.attempts = 1;
	opts.timeout = std::time::Duration::from_secs(2);
	SystemDns::with_config(ResolverConfig::from_name_servers(vec![server]), opts).expect("resolver")
}

#[tokio::test]
async fn an_unsigned_ptr_resolves_for_ipv6_like_for_ipv4() {
	let port = spawn_resolver(HashMap::from([
		(V6_REVERSE, "mail.example.org."),
		(V4_REVERSE, "mail.example.org."),
	]))
	.await;
	let dns = resolver(port);
	for address in ["2001:db8::25", "192.0.2.25"] {
		let ip: IpAddr = address.parse().expect("address");
		let found = tokio::time::timeout(std::time::Duration::from_secs(20), dns.ptr(ip))
			.await
			.expect("the lookup finishes");
		assert_eq!(
			found,
			Ok(vec!["mail.example.org".to_string()]),
			"PTR of {address} through the system resolver"
		);
	}
}

#[tokio::test]
async fn an_address_without_ptr_has_no_names() {
	let port = spawn_resolver(HashMap::new()).await;
	let dns = resolver(port);
	let ip: IpAddr = "2001:db8::25".parse().expect("address");
	let found = tokio::time::timeout(std::time::Duration::from_secs(20), dns.ptr(ip))
		.await
		.expect("the lookup finishes");
	assert_eq!(found, Ok(Vec::new()), "PTR of an address with none");
}
