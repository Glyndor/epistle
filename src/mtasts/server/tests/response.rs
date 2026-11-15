//! `policy_response` answers for the file it is given: the same function
//! backs the MTA-STS listener and the public endpoint of `serve`.

use axum::http::{Method, StatusCode, header};

use super::*;

const POLICY: &str = "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 777\n";

async fn answer(
	path: &std::path::Path,
	method: Method,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
	let response = policy_response(path, &method).await;
	let (parts, body) = response.into_parts();
	let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
	(parts.status, parts.headers, bytes.to_vec())
}

fn file(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mta-sts.txt");
	std::fs::write(&path, content).expect("policy");
	(dir, path)
}

#[tokio::test]
async fn get_answers_the_bytes_with_the_type_and_the_cache_lifetime_of_the_file() {
	let (_dir, path) = file(POLICY);
	let (status, headers, body) = answer(&path, Method::GET).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, POLICY.as_bytes());
	assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
	assert_eq!(headers[header::CACHE_CONTROL], "max-age=777");
}

#[tokio::test]
async fn head_answers_the_length_and_no_body() {
	let (_dir, path) = file(POLICY);
	let (status, headers, body) = answer(&path, Method::HEAD).await;
	assert_eq!(status, StatusCode::OK);
	assert!(body.is_empty());
	assert_eq!(headers[header::CONTENT_LENGTH], POLICY.len().to_string());
}

#[tokio::test]
async fn other_methods_answer_405_with_the_allow_header() {
	let (_dir, path) = file(POLICY);
	for method in [Method::POST, Method::PUT, Method::DELETE] {
		let (status, headers, _) = answer(&path, method).await;
		assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
		assert_eq!(headers[header::ALLOW], "GET, HEAD");
	}
}

#[tokio::test]
async fn a_file_that_is_not_there_is_404() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, _, _) = answer(&dir.path().join("mta-sts.txt"), Method::GET).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_path_that_cannot_be_read_or_does_not_parse_is_500() {
	// A directory is not a file: reading it fails with something other
	// than "not found".
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, _, _) = answer(dir.path(), Method::GET).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
	let (_dir, path) = file("this is not a policy");
	let (status, _, _) = answer(&path, Method::GET).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
	let (_dir, path) = file("");
	let (status, _, _) = answer(&path, Method::GET).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
