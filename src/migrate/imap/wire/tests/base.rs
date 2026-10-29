use std::time::Duration;

use super::*;

fn limits() -> Limits {
	Limits {
		line: 64,
		literal: 16,
		idle: Duration::from_secs(1),
		response: Duration::from_secs(5),
	}
}

async fn read(input: &[u8]) -> Result<Response, WireError> {
	let mut reader = tokio::io::BufReader::new(input);
	read_response(&mut reader, &limits()).await
}

#[tokio::test]
async fn a_plain_line_is_one_segment() {
	let response = read(b"* OK ready\r\n").await.expect("read");
	assert_eq!(response.head(), b"* OK ready");
	assert_eq!(response.segments.len(), 1);
}

#[tokio::test]
async fn a_literal_is_read_exactly_and_the_line_continues() {
	let response = read(b"* 1 FETCH (BODY[] {5}\r\nhe\r\no)\r\n")
		.await
		.expect("read");
	assert_eq!(response.segments.len(), 2);
	assert_eq!(
		response.segments[0].literal.as_deref(),
		Some(&b"he\r\no"[..])
	);
	assert_eq!(response.segments[1].text, b")");
}

#[tokio::test]
async fn a_literal_at_the_limit_is_accepted_and_one_past_refused() {
	let mut at = b"* 1 FETCH (BODY[] {16}\r\n".to_vec();
	at.extend([b'x'; 16]);
	at.extend(b")\r\n");
	assert!(read(&at).await.is_ok());
	let over = b"* 1 FETCH (BODY[] {17}\r\nxxxxxxxxxxxxxxxxx)\r\n";
	assert!(matches!(
		read(over).await,
		Err(WireError::LiteralTooLarge {
			size: 17,
			limit: 16
		})
	));
}

#[tokio::test]
async fn a_literal_size_that_overflows_is_refused() {
	let line = b"* 1 FETCH (BODY[] {99999999999999999999999}\r\n";
	assert!(matches!(
		read(line).await,
		Err(WireError::LiteralTooLarge { size: u64::MAX, .. })
	));
}

#[tokio::test]
async fn a_line_at_the_limit_is_accepted_and_one_past_refused() {
	// 62 octets of text plus CRLF is 64.
	let mut at = vec![b'a'; 62];
	at.extend(b"\r\n");
	assert!(read(&at).await.is_ok());
	let mut over = vec![b'a'; 63];
	over.extend(b"\r\n");
	assert!(matches!(read(&over).await, Err(WireError::LineTooLong(64))));
}

#[tokio::test]
async fn too_many_literals_are_refused() {
	let input = b"* X {1}\r\na {1}\r\nb {1}\r\nc {1}\r\nd {1}\r\ne\r\n";
	assert!(matches!(read(input).await, Err(WireError::TooManyLiterals)));
}

#[tokio::test]
async fn a_closed_connection_is_reported() {
	assert!(matches!(read(b"* OK no end").await, Err(WireError::Closed)));
	assert!(matches!(
		read(b"* 1 FETCH {9}\r\nabc").await,
		Err(WireError::Closed)
	));
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out() {
	let (client, _server) = tokio::io::duplex(64);
	let mut reader = tokio::io::BufReader::new(client);
	let result = read_response(&mut reader, &limits()).await;
	assert!(matches!(result, Err(WireError::Timeout)));
}

#[tokio::test(start_paused = true)]
async fn a_dripping_server_hits_the_response_deadline() {
	let (client, mut server) = tokio::io::duplex(64);
	tokio::spawn(async move {
		use tokio::io::AsyncWriteExt;
		loop {
			tokio::time::sleep(Duration::from_millis(900)).await;
			if server.write_all(b"a").await.is_err() {
				return;
			}
		}
	});
	let mut reader = tokio::io::BufReader::new(client);
	let mut limits = limits();
	limits.line = 1 << 20;
	let result = read_response(&mut reader, &limits).await;
	assert!(matches!(result, Err(WireError::Timeout)), "{result:?}");
}
