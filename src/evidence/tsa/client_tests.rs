use std::sync::Arc;

use super::*;
use crate::evidence::record::sha256;
use crate::evidence::tsa::der::{parse_one, tag};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::oid;

const NOW: u64 = 1_792_038_711;

fn authority(url: String, tsa: &FakeTsa) -> Authority {
	Authority {
		url,
		anchors: vec![crate::evidence::record::to_hex(&tsa.anchor)],
	}
}

#[tokio::test]
async fn a_token_is_obtained_and_only_the_digest_was_sent() {
	let tsa = Arc::new(FakeTsa::new(NOW));
	let url = Arc::clone(&tsa).serve().await;
	let digest = sha256(b"checkpoint");
	let obtained = obtain(&[authority(url, &tsa)], &digest)
		.await
		.expect("token");
	assert_eq!(obtained.stamp.gen_time, NOW);
	let received = tsa.received.lock().expect("lock").clone();
	assert_eq!(received.len(), 1);
	// The body is a TimeStampReq of exactly four fields: version, the
	// SHA-256 imprint of the digest, a nonce and certReq.
	let request = parse_one(&received[0], tag::SEQUENCE).expect("request");
	let mut fields = request.reader();
	assert_eq!(fields.expect(tag::INTEGER).expect("version").value, &[1]);
	let imprint = fields.expect(tag::SEQUENCE).expect("imprint");
	let mut imprint = imprint.reader();
	let algorithm = imprint.expect(tag::SEQUENCE).expect("algorithm");
	assert_eq!(
		algorithm.reader().expect(tag::OID).expect("oid").value,
		oid::SHA256
	);
	assert_eq!(
		imprint.expect(tag::OCTET_STRING).expect("digest").value,
		&digest
	);
	fields.expect(tag::INTEGER).expect("nonce");
	assert_eq!(fields.expect(tag::BOOLEAN).expect("certReq").value, &[0xff]);
	assert!(
		fields.is_empty(),
		"the request carries something besides the digest"
	);
}

#[tokio::test]
async fn the_next_authority_is_tried_when_one_fails() {
	let broken = Arc::new({
		let mut tsa = FakeTsa::new(NOW);
		tsa.faults.bad_signature = true;
		tsa
	});
	let good = Arc::new(FakeTsa::new(NOW));
	let broken_url = Arc::clone(&broken).serve().await;
	let good_url = Arc::clone(&good).serve().await;
	let digest = sha256(b"checkpoint");
	let obtained = obtain(
		&[
			authority(broken_url, &broken),
			authority(good_url.clone(), &good),
		],
		&digest,
	)
	.await
	.expect("token from the second");
	assert_eq!(obtained.url, good_url);
}

#[tokio::test]
async fn every_failure_is_reported_without_remote_text() {
	let tsa = Arc::new({
		let mut tsa = FakeTsa::new(NOW);
		tsa.faults.refuse = Some(2);
		tsa
	});
	let url = Arc::clone(&tsa).serve().await;
	let unreachable = "http://127.0.0.1:9/tsr".to_string();
	let error = obtain(
		&[
			authority(url.clone(), &tsa),
			authority(unreachable.clone(), &tsa),
		],
		&sha256(b"x"),
	)
	.await
	.expect_err("no token");
	assert_eq!(
		error,
		format!(
			"{url}: the TSA refused the request (status 2); {unreachable}: request failed: could not connect"
		)
	);
}
