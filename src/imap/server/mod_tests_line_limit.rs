//! The command line limit fits the largest ID command RFC 2971 allows.

use super::*;

/// Read until `needle` appears; the peer closing first fails the test.
async fn read_until(client: &mut tokio::io::DuplexStream, needle: &str) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	while !got.contains(needle) {
		let n = client.read(&mut chunk).await.expect("read");
		assert!(n > 0, "closed waiting for {needle:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
	got
}

#[tokio::test]
async fn largest_id_command_is_answered() {
	// RFC 2971 §3.3: at most 30 pairs, fields of 30 octets, values of 1024.
	let pairs: Vec<String> = (0..30)
		.map(|i| format!("\"{:030}\" \"{}\"", i, "1".repeat(1024)))
		.collect();
	let line = format!("a1 ID ({})\r\n", pairs.join(" "));
	assert!(line.len() > 31_000, "{}", line.len());
	let (mut client, task) = super::plaintext_server();
	read_until(&mut client, "* OK").await;
	client.write_all(line.as_bytes()).await.expect("write");
	let reply = read_until(&mut client, "a1 OK").await;
	assert!(reply.starts_with("* ID "), "{reply}");
	drop(client);
	let _ = task.await;
}
