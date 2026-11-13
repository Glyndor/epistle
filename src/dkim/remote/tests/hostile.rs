//! Requests a compromised client could send: each is refused for its own
//! reason, before the key holder sees it, and the well-formed request of
//! the same shape is signed.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::dkim::remote::frame::{MAX_REQUEST_BYTES, OP_SIGN_DKIM};
use crate::dkim::{HeaderBlock, Refusal};

/// A key holder that counts the blocks it is handed and signs each with
/// the same text.
#[derive(Default)]
struct Counting(AtomicUsize);

const FIXED: &str = "DKIM-Signature: v=1; fixed\r\n";

impl KeyHolder for Counting {
	fn sign_block(&self, _domain: &str, _block: &HeaderBlock) -> Result<String, Refusal> {
		self.0.fetch_add(1, Ordering::SeqCst);
		Ok(FIXED.into())
	}
}

fn counting_server() -> (Arc<Counting>, Running) {
	let holder = Arc::new(Counting::default());
	let running = start(SignerServer::new(holder.clone()));
	(holder, running)
}

fn request(domain: &str, names: &str, canonical: &str, hash: &[u8]) -> Vec<u8> {
	framed(&body(
		VERSION,
		OP_SIGN_DKIM,
		&[
			domain.as_bytes(),
			names.as_bytes(),
			canonical.as_bytes(),
			hash,
		],
	))
}

#[tokio::test]
async fn each_hostile_request_is_refused_for_its_reason_before_the_holder() {
	let (holder, running) = counting_server();
	let (names, canonical, hash) = plain_fields();
	let mut trailing = body(
		VERSION,
		OP_SIGN_DKIM,
		&[
			b"example.org",
			names.as_bytes(),
			canonical.as_bytes(),
			&hash,
		],
	);
	trailing.push(0);
	let label_64 = format!("{}.org", "a".repeat(64));
	let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
		(
			"a body cut after the operation",
			framed(&[VERSION, OP_SIGN_DKIM]),
			Reason::Frame,
		),
		(
			"a byte after the last field",
			framed(&trailing),
			Reason::Frame,
		),
		(
			"another version",
			framed(&body(2, OP_SIGN_DKIM, &[])),
			Reason::Version,
		),
		(
			"another operation",
			framed(&body(VERSION, 2, &[])),
			Reason::Operation,
		),
		(
			"a tag smuggled in d=",
			request("example.org; s=evil", &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"a line break in d=",
			request("example.org\r\nBcc: x", &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"an empty d=",
			request("", &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"a space in d=",
			request("exa mple.org", &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"an empty label in d=",
			request("example..org", &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"a label of 64 bytes",
			request(&label_64, &names, &canonical, &hash),
			Reason::Domain,
		),
		(
			"an uppercase name in h=",
			request(
				"example.org",
				&names.replacen("from", "From", 1),
				&canonical,
				&hash,
			),
			Reason::Block,
		),
		(
			"a second From line",
			request(
				"example.org",
				&format!("from:{names}"),
				&format!("from:mallory@example.net\r\n{canonical}"),
				&hash,
			),
			Reason::Block,
		),
	];
	for (case, frame, reason) in cases {
		let answer = decode_answer(&raw_exchange(&running.socket, &frame).await);
		assert_eq!(answer, SignResponse::Refused(reason), "{case}");
	}
	assert_eq!(
		holder.0.load(Ordering::SeqCst),
		0,
		"no refused block reached the holder"
	);

	for domain in [
		"example.org",
		"Example.ORG",
		"a-b.example",
		"xn--bcher-kva.example",
	] {
		let frame = request(domain, &names, &canonical, &hash);
		let answer = decode_answer(&raw_exchange(&running.socket, &frame).await);
		assert_eq!(answer, SignResponse::Signed(FIXED.into()), "{domain}");
	}
	assert_eq!(holder.0.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn an_oversized_request_is_refused_from_its_length_alone() {
	let (holder, running) = counting_server();
	let announced = u32::try_from(MAX_REQUEST_BYTES + 1).expect("fits");
	// The prefix and a few bytes, never the body it announces: the answer
	// has to come from the prefix.
	let mut frame = announced.to_be_bytes().to_vec();
	frame.extend_from_slice(&[VERSION, OP_SIGN_DKIM]);
	let answer = decode_answer(&raw_exchange(&running.socket, &frame).await);
	assert_eq!(answer, SignResponse::Refused(Reason::TooLarge));

	// At the cap the length is taken and the signer waits for the body,
	// which never comes: it closes without answering, not with TooLarge.
	let mut frame = u32::try_from(MAX_REQUEST_BYTES)
		.expect("fits")
		.to_be_bytes()
		.to_vec();
	frame.extend_from_slice(&[VERSION, OP_SIGN_DKIM]);
	assert_eq!(raw_exchange(&running.socket, &frame).await, b"");

	let (names, canonical, hash) = plain_fields();
	let valid = request("example.org", &names, &canonical, &hash);
	let answer = decode_answer(&raw_exchange(&running.socket, &valid).await);
	assert_eq!(answer, SignResponse::Signed(FIXED.into()));
	assert_eq!(holder.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_operation_but_signing_exists_on_the_socket() {
	let (holder, running) = counting_server();
	let refusal = SignResponse::Refused(Reason::Operation).encode();
	for operation in (0..=u8::MAX).filter(|op| *op != OP_SIGN_DKIM) {
		let (names, canonical, hash) = plain_fields();
		let frame = framed(&body(
			VERSION,
			operation,
			&[
				b"example.org",
				names.as_bytes(),
				canonical.as_bytes(),
				&hash,
			],
		));
		// The whole answer is the eleven bytes of the refusal: there is no
		// operation that could hand back anything else, key material
		// included.
		assert_eq!(
			raw_exchange(&running.socket, &frame).await,
			refusal,
			"op {operation}"
		);
	}
	assert_eq!(refusal.len(), 4 + 1 + 1 + 4 + 1);
	assert_eq!(holder.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_host_name_is_letters_digits_and_hyphens_in_dotted_labels() {
	use super::super::server::is_host_name;
	let longest = format!(
		"{}.{}.{}.{}",
		"a".repeat(63),
		"b".repeat(63),
		"c".repeat(63),
		"d".repeat(61)
	);
	assert_eq!(longest.len(), 253);
	assert!(is_host_name(&longest));
	assert!(!is_host_name(&format!("{longest}e")));
	for bad in [
		"",
		".",
		"a.",
		".a",
		"a..b",
		"a_b.example",
		"a=b",
		"a;b",
		"a\tb",
		"a\0b",
		"é.example",
	] {
		assert!(!is_host_name(bad), "{bad:?}");
	}
}
