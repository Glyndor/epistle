use super::*;
use tokio::io::AsyncReadExt;

/// What `send_data` puts on the wire for `data`.
async fn wire(data: &[u8]) -> Vec<u8> {
	let (near, mut far) = tokio::io::duplex(64 * 1024);
	let mut conn = Conn::new(Box::new(near));
	conn.send_data(data).await.expect("send");
	drop(conn);
	let mut out = Vec::new();
	far.read_to_end(&mut out).await.expect("read");
	out
}

#[tokio::test]
async fn a_dot_at_the_start_of_a_line_is_doubled() {
	assert_eq!(wire(b".a\r\n.b\r\n").await, b"..a\r\n..b\r\n.\r\n");
}

#[tokio::test]
async fn a_dot_after_a_bare_cr_or_lf_is_doubled() {
	assert_eq!(wire(b"a\r.\r\n").await, b"a\r..\r\n.\r\n");
	assert_eq!(wire(b"a\n.b\r\n").await, b"a\n..b\r\n.\r\n");
}

#[tokio::test]
async fn the_terminator_is_added_once() {
	assert_eq!(wire(b"a\r\n").await, b"a\r\n.\r\n");
	assert_eq!(wire(b"a").await, b"a\r\n.\r\n");
}
