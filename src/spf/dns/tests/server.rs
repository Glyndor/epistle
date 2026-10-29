//! The in-process DNS server the resolver tests answer with.
//!
//! It speaks DNS-over-TCP only, the way the system resolver is forced to
//! speak (see [`super::system_resolver_config`]), and it answers every
//! query with the reply the test asks for: the records of a name, an empty
//! answer, NXDOMAIN or SERVFAIL.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::Record;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::SystemDns;

/// What the fake server answers to a query.
#[derive(Debug)]
pub enum Reply {
	/// NOERROR with these answers. An empty vector is an answer with no
	/// record of the queried type: the name exists and publishes nothing
	/// of it.
	Answers(Vec<Record>),
	/// NXDOMAIN: the name does not exist.
	NotFound,
	/// SERVFAIL: the server could not answer.
	Failed,
}

/// Answer the queries with `respond`, over DNS-over-TCP. Returns the port
/// the server listens on.
pub async fn spawn(respond: impl Fn(&Message) -> Reply + Send + Sync + 'static) -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let respond = Arc::new(respond);
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			tokio::spawn(serve(stream, respond.clone()));
		}
	});
	port
}

async fn serve(mut stream: TcpStream, respond: Arc<dyn Fn(&Message) -> Reply + Send + Sync>) {
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
		let reply = answer(&query, respond.as_ref());
		let framed = u16::try_from(reply.len()).expect("reply fits a frame");
		if stream.write_all(&framed.to_be_bytes()).await.is_err()
			|| stream.write_all(&reply).await.is_err()
		{
			return;
		}
	}
}

/// The reply to a query: the records the test asks for, or the response
/// code it asks for.
fn answer(query: &Message, respond: &dyn Fn(&Message) -> Reply) -> Vec<u8> {
	let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
	reply.metadata.recursion_desired = query.metadata.recursion_desired;
	reply.metadata.recursion_available = true;
	for question in &query.queries {
		reply.add_query(question.clone());
	}
	match respond(query) {
		Reply::Answers(records) => {
			reply.metadata.response_code = ResponseCode::NoError;
			for record in records {
				reply.add_answer(record);
			}
		}
		Reply::NotFound => reply.metadata.response_code = ResponseCode::NXDomain,
		Reply::Failed => reply.metadata.response_code = ResponseCode::ServFail,
	}
	reply.to_vec().expect("encode reply")
}

/// A resolver built the way production builds it (TCP only, the system
/// name servers) but pointed at the fake server.
///
/// The DNSSEC validation is off here, and only here. The fake server signs
/// nothing, and a validating resolver that cannot prove an answer calls it
/// bogus, so every answer the fake gives would be a failure and no test
/// would ever read a record. The production resolver keeps the validation
/// on, and the resolver tests pin that it does.
pub fn resolver(port: u16) -> SystemDns {
	let mut server = NameServerConfig::tcp(IpAddr::V4(Ipv4Addr::LOCALHOST));
	for connection in &mut server.connections {
		connection.port = port;
	}
	let mut opts = ResolverOpts::default();
	opts.validate = false;
	opts.attempts = 1;
	opts.timeout = Duration::from_secs(2);
	SystemDns::with_config(ResolverConfig::from_name_servers(vec![server]), opts).expect("resolver")
}
