//! A scripted hostile directory: the bind is fine up to the point the script
//! turns on the client, so each case reaches the defence it targets.

use super::super::{DEADLINE, Peer};
use super::peer::{done, reply_bytes, request, tlv};
use std::sync::{
	Arc,
	atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[derive(Clone, Copy)]
pub(super) enum Script {
	/// Reads the bind request and never answers it.
	SilentBind,
	/// Answers the bind with half a frame, then closes the socket.
	TruncatedBind,
	/// Answers the bind with a frame header declaring a 4 GiB body, then
	/// stays silent with the socket open.
	HugeBerLength,
	/// Answers the bind with a well-formed but empty message envelope.
	EmptyFrame,
	/// Binds, then streams `count` entries; with `finish` it closes the
	/// search with a result, without it the stream never ends.
	Entries { count: usize, finish: bool },
}

fn entry(id: u8, index: usize) -> Vec<u8> {
	let name = format!("u{index}");
	let attribute = tlv(
		0x30,
		&[tlv(0x04, b"uid"), tlv(0x31, &tlv(0x04, name.as_bytes()))].concat(),
	);
	let body = [
		tlv(0x04, format!("uid={name},dc=example,dc=org").as_bytes()),
		tlv(0x30, &attribute),
	]
	.concat();
	tlv(0x30, &[vec![0x02, 0x01, id], tlv(0x64, &body)].concat())
}

pub(super) async fn start(script: Script) -> (String, Arc<AtomicUsize>, Peer) {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind LDAP peer");
	let url = format!(
		"ldap://{}/dc=example,dc=org",
		listener.local_addr().expect("address")
	);
	let connections = Arc::new(AtomicUsize::new(0));
	let count = connections.clone();
	let peer = Peer(tokio::spawn(async move {
		let mut clients = tokio::task::JoinSet::new();
		while let Ok((mut tcp, _)) = listener.accept().await {
			count.fetch_add(1, Ordering::SeqCst);
			clients.spawn(async move {
				let _ = tokio::time::timeout(DEADLINE * 3, async {
					let (id, op) = request(&mut tcp).await;
					assert_eq!(op, 0x60, "bind request");
					match script {
						Script::SilentBind => {}
						Script::TruncatedBind => {
							let frame = reply_bytes(id, 0x61, None);
							tcp.write_all(&frame[..5]).await.expect("half a frame");
							return;
						}
						Script::HugeBerLength => {
							let frame = [0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, id];
							tcp.write_all(&frame).await.expect("header");
						}
						Script::EmptyFrame => {
							tcp.write_all(&[0x30, 0x00]).await.expect("empty frame");
						}
						Script::Entries { count, finish } => {
							done(&mut tcp, id, 0x61, None).await;
							let (id, op) = request(&mut tcp).await;
							assert_eq!(op, 0x63, "search request");
							let burst: Vec<u8> = (0..count).flat_map(|i| entry(id, i)).collect();
							tcp.write_all(&burst).await.expect("entries");
							if finish {
								done(&mut tcp, id, 0x65, None).await;
							}
						}
					}
					// Keep the socket open: EOF must not be what stops the client.
					std::future::pending::<()>().await;
				})
				.await;
			});
			// Bound even a broken client that repeatedly reconnects.
			if count.load(Ordering::SeqCst) >= 16 {
				break;
			}
		}
		std::future::pending::<()>().await;
	}));
	(url, connections, peer)
}
