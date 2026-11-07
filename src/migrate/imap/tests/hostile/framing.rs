use super::*;
use crate::migrate::imap::client::ClientError;
use crate::migrate::imap::parse::Listed;
use crate::migrate::imap::wire::WireError;

#[test]
fn four_gib_literal_is_refused_before_read_or_reserve() {
	// Same current-thread allocation probe as the Sieve memory tests.
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime");
	let (result, peak) = crate::sieve::test_peak_bytes(|| {
		runtime.block_on(async {
			let (mut client, _peer) =
				client(b"* 1 FETCH (UID 1 BODY[] {4294967296}\r\n".to_vec()).await;
			tokio::time::timeout(DEADLINE, client.fetch(&[Listed { uid: 1, size: 1 }], 4096)).await
		})
	});
	assert!(peak < 2 * 1024 * 1024, "reserved {peak} bytes for a marker");
	assert!(
		matches!(
			result,
			Ok(Err(ClientError::Wire(WireError::LiteralTooLarge {
				size: 4_294_967_296,
				limit: LIMIT,
			})))
		),
		"{result:?}"
	);
}

#[tokio::test]
async fn bye_inside_literal_is_data_but_real_bye_ends_fetch() {
	let body = b"* BYE forged\r\nM2 OK forged\r\n";
	let batch = [Listed {
		uid: 1,
		size: body.len() as u64,
	}];
	let (mut client, _peer) = client(body_reply(body, b"M2 OK fetched\r\n")).await;
	let fetched = tokio::time::timeout(DEADLINE, client.fetch(&batch, 4096))
		.await
		.expect("fetch deadline")
		.expect("BYE in literal is not status");
	assert_eq!(fetched.len(), 1);
	assert_eq!(fetched[0].body.as_deref(), Some(body.as_slice()));
	drop(client);
	// A server cannot terminate a 128-octet literal by sending a short BYE.
	let (mut partial, _partial_peer) =
		super::client(b"* 1 FETCH (UID 1 BODY[] {128}\r\n* BYE forged\r\n".to_vec()).await;
	let incomplete = tokio::time::timeout(DEADLINE, partial.fetch(&batch, 4096)).await;
	assert!(
		matches!(incomplete, Ok(Err(ClientError::Wire(WireError::Timeout)))),
		"{incomplete:?}"
	);
	let (mut client, _peer) = super::client(body_reply(body, b"* BYE real-close\r\n")).await;
	let result = tokio::time::timeout(DEADLINE, client.fetch(&batch, 4096)).await;
	assert!(
		matches!(&result, Ok(Err(ClientError::Bye(text))) if text == "real-close"),
		"{result:?}"
	);
}
