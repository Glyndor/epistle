//! Raw ListObjects responses through the production signed HTTP client.
mod limits;
mod peer;
mod raw;

use super::DEADLINE;
use crate::storage::{BlobBackend, BlobError};

#[tokio::test]
async fn truncated_list_objects_xml_returns_a_parse_error() {
	let xml = b"<?xml version=\"1.0\"?><ListBucketResult><Contents><Key>";
	let (backend, _peer) = peer::start(xml).await;
	let result = tokio::time::timeout(DEADLINE, backend.list()).await;
	assert!(
		matches!(&result, Ok(Err(BlobError::Remote(_)))),
		"{result:?}"
	);
}

/// Positive control: malformed XML rejection alone is vacuous if the
/// implementation rejects all XML, including a complete ListObjects page.
#[tokio::test]
async fn complete_list_objects_xml_returns_the_payload_id() {
	let xml = b"<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>0198f2c1-9a4b-7000-8000-000000000001</Key></Contents></ListBucketResult>";
	let (backend, _peer) = peer::start(xml).await;
	let result = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("ListObjects deadline")
		.expect("valid S3 XML");
	assert_eq!(
		result,
		vec![uuid::Uuid::parse_str("0198f2c1-9a4b-7000-8000-000000000001").expect("id")]
	);
}

#[tokio::test]
async fn complete_json_control_reaches_the_existing_list_parser() {
	let json = br#"{"Contents":[{"Key":"0198f2c1-9a4b-7000-8000-000000000002"}]}"#;
	let (backend, _peer) = peer::start(json).await;
	let ids = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("ListObjects deadline")
		.expect("legacy JSON control");
	assert_eq!(
		ids,
		vec![uuid::Uuid::parse_str("0198f2c1-9a4b-7000-8000-000000000002").expect("id")]
	);
}

#[tokio::test]
async fn several_keys_are_read_and_the_sidecars_are_left_out() {
	let xml = b"<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>\
<Contents><Key>0198f2c1-9a4b-7000-8000-000000000003</Key><Size>5</Size></Contents>\
<Contents><Key>0198f2c1-9a4b-7000-8000-000000000003.type</Key></Contents>\
<Contents><Key>p/0198f2c1-9a4b-7000-8000-000000000004</Key></Contents></ListBucketResult>";
	let (backend, _peer) = peer::start(xml).await;
	let ids = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("ListObjects deadline")
		.expect("valid S3 XML");
	assert_eq!(
		ids,
		vec![
			uuid::Uuid::parse_str("0198f2c1-9a4b-7000-8000-000000000003").expect("id"),
			uuid::Uuid::parse_str("0198f2c1-9a4b-7000-8000-000000000004").expect("id"),
		]
	);
}
