//! Minimal bounded BER exchange: bind success, then search result done.
//! Every connection receives the same self-referral, so following it loops.

use super::super::{DEADLINE, Peer};
use std::sync::{
	Arc,
	atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
	assert!(value.len() < 256, "small fixture only");
	let mut out = vec![tag];
	if value.len() >= 128 {
		out.push(0x81);
	}
	out.push(value.len() as u8);
	out.extend_from_slice(value);
	out
}

/// Recover the message id and operation from a bounded request frame.
async fn request(tcp: &mut TcpStream) -> (u8, u8) {
	assert_eq!(tcp.read_u8().await.expect("sequence"), 0x30);
	let first = tcp.read_u8().await.expect("length");
	let size = if first < 128 {
		usize::from(first)
	} else {
		let count = first & 0x7f;
		assert!((1..=2).contains(&count), "bounded BER length");
		let mut size = 0usize;
		for _ in 0..count {
			size = size * 256 + usize::from(tcp.read_u8().await.expect("length byte"));
		}
		size
	};
	assert!(size <= 8192, "bounded fake request");
	let mut body = vec![0; size];
	tcp.read_exact(&mut body).await.expect("request body");
	assert_eq!(&body[..2], &[0x02, 0x01], "small message id");
	(body[2], body[3])
}

async fn done(tcp: &mut TcpStream, id: u8, operation: u8, url: Option<&str>) {
	let mut result = vec![
		0x0a,
		0x01,
		if url.is_some() { 10 } else { 0 },
		0x04,
		0,
		0x04,
		0,
	];
	if let Some(url) = url {
		result.extend(tlv(0xa3, &tlv(0x04, url.as_bytes())));
	}
	let mut message = vec![0x02, 0x01, id];
	message.extend(tlv(operation, &result));
	tcp.write_all(&tlv(0x30, &message))
		.await
		.expect("LDAP reply");
}

pub(super) async fn start(referral: bool) -> (String, Arc<AtomicUsize>, Peer) {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind LDAP peer");
	let url = format!(
		"ldap://{}/dc=example,dc=org",
		listener.local_addr().expect("address")
	);
	let connections = Arc::new(AtomicUsize::new(0));
	let count = connections.clone();
	let target = url.clone();
	let peer = Peer(tokio::spawn(async move {
		let mut clients = tokio::task::JoinSet::new();
		while let Ok((mut tcp, _)) = listener.accept().await {
			count.fetch_add(1, Ordering::SeqCst);
			let target = target.clone();
			clients.spawn(async move {
				tokio::time::timeout(DEADLINE * 2, async {
					let (id, op) = request(&mut tcp).await;
					assert_eq!(op, 0x60, "bind request");
					done(&mut tcp, id, 0x61, None).await;
					let (id, op) = request(&mut tcp).await;
					assert_eq!(op, 0x63, "search request");
					done(&mut tcp, id, 0x65, referral.then_some(target.as_str())).await;
					// Stay connected until unbind/close, rather than using
					// EOF as a substitute for the referral result.
					let mut rest = [0; 32];
					let _ = tcp.read(&mut rest).await;
				})
				.await
				.expect("fake exchange deadline");
			});
			// Bound even a broken client that repeatedly reconnects.
			if count.load(Ordering::SeqCst) >= 16 {
				break;
			}
		}
	}));
	(url, connections, peer)
}
