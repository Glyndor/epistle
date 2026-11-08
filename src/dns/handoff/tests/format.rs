//! The request and the answer: what they carry and what they refuse.

use super::super::{Operation, Outcome, Request, Write};

/// A request as the asking side builds it.
fn request() -> Request {
	Write::dkim("ed1._domainkey.example.org", "v=DKIM1; k=ed25519; p=abc")
		.request("0198a1b2-c3d4-7000-8000-000000000001", 1_700_000_000)
}

#[test]
fn a_request_survives_the_round_trip() {
	let original = request();
	let bytes = serde_json::to_vec(&original).expect("encode");
	let read: Request = serde_json::from_slice(&bytes).expect("decode");
	assert_eq!(read, original);
	assert_eq!(read.operation, Operation::Publish);
	assert_eq!(read.kind, "TXT");
	assert_eq!(read.ttl, 300);
	assert_eq!(read.created_at, 1_700_000_000);
}

#[test]
fn a_request_with_an_unknown_field_is_refused() {
	let mut value = serde_json::to_value(request()).expect("encode");
	value.as_object_mut().expect("object").insert(
		"zone".to_string(),
		serde_json::Value::String("evil.test".to_string()),
	);
	let refused = serde_json::from_slice::<Request>(&serde_json::to_vec(&value).expect("encode"));
	assert!(
		refused.is_err(),
		"a field this hand-off does not write must be refused"
	);
}

#[test]
fn a_withdrawal_carries_no_value() {
	let write = Write::withdraw("ed1._domainkey.example.org");
	assert_eq!(write.operation, Operation::Withdraw);
	assert!(write.value.is_empty());
	assert_eq!(write.kind, "TXT");
}

#[test]
fn the_answer_reads_as_a_result_or_a_reason() {
	let ok = Outcome::ok("id");
	assert_eq!(ok.answer(), Ok(()));
	let failed = Outcome::failed("id", "the zone refused the write");
	assert_eq!(
		failed.answer(),
		Err("the zone refused the write".to_string())
	);
	let silent = Outcome {
		id: "id".to_string(),
		ok: false,
		error: None,
	};
	assert!(silent.answer().is_err());
}
