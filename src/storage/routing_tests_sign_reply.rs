//! A reply the server wrote is framed before it is signed, so the signature
//! covers the bytes that are queued.

use super::*;

use crate::dkim::{PerDomainSigner, ReloadableSigner, Signer};

fn reply(data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["carol@example.net".into()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn split(dir: &std::path::Path) -> SplitDelivery {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key_file = dir.join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	SplitDelivery::new(dir, directory)
		.expect("sink")
		.with_signer(PerDomainSigner::new(signer, Vec::new()))
}

#[test]
fn a_reply_with_mixed_line_ends_is_framed_and_then_signed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let split = split(dir.path());
	for raw in [
		b"From: alice@example.org\nSubject: s\n\nbody".as_slice(),
		b"From: alice@example.org\r\nSubject: s\r\n\r\nbo\rdy\0\n.\r\n".as_slice(),
		b"From: alice@example.org\r\nSubject: s\r\n\r\nbody\r".as_slice(),
	] {
		let mut message = reply(raw);
		split.sign_reply(&mut message);
		assert!(message.data.starts_with(b"DKIM-Signature:"), "signed");
		assert!(
			!crate::util::header_block::has_unframed_byte(&message.data),
			"{:?}",
			String::from_utf8_lossy(&message.data)
		);
		assert!(message.data.ends_with(b"\r\n"));
		let lone_lf = message
			.data
			.iter()
			.enumerate()
			.any(|(at, byte)| *byte == b'\n' && (at == 0 || message.data[at - 1] != b'\r'));
		assert!(!lone_lf);
	}
}
