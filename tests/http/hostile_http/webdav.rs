//! Confinement, bounded XML and upload handling through the production DAV router.

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};

use super::harness::{Harness, call, dav_request, repeated_body};

#[tokio::test]
async fn traversal_spellings_cannot_read_or_write_bobs_tree() {
	let h = Harness::new();
	let sentinel = h.dav_root("bob").join("secret.txt");
	std::fs::write(&sentinel, b"bob-private-sentinel").expect("sentinel");
	for path in [
		"/../bob/dav/secret.txt",
		"/%2e%2e/bob/dav/secret.txt",
		"/%2E%2E%2fbob%2fdav%2fsecret.txt",
		"/a/../../bob/dav/secret.txt",
		"/%5c..%5cbob%5cdav%5csecret.txt",
	] {
		for method in ["GET", "PUT"] {
			let reply = call(&h.dav, dav_request(method, path, Body::from("overwrite"))).await;
			assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
			assert_eq!(
				std::fs::read(&sentinel).expect("sentinel"),
				b"bob-private-sentinel"
			);
			h.healthy_dav().await;
		}
	}
}

#[tokio::test]
async fn double_encoding_is_not_decoded_twice() {
	let h = Harness::new();
	std::fs::write(h.dav_root("bob").join("secret.txt"), b"bob-private").expect("sentinel");
	for path in [
		"/%252e%252e/bob/dav/secret.txt",
		"/%252e%252e%252fbob%252fdav%252fsecret.txt",
	] {
		let reply = call(&h.dav, dav_request("GET", path, Body::empty())).await;
		assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
		assert!(!reply.body.windows(11).any(|w| w == b"bob-private"));
		h.healthy_dav().await;
	}
}

#[tokio::test]
async fn nul_in_path_is_rejected_before_filesystem_access() {
	let h = Harness::new();
	for method in ["GET", "PUT"] {
		let reply = call(
			&h.dav,
			dav_request(method, "/secret%00.txt", Body::from("bad")),
		)
		.await;
		assert_eq!(reply.status, StatusCode::BAD_REQUEST);
		assert!(!h.dav_root("alice").join("secret").exists());
		h.healthy_dav().await;
	}
}

#[cfg(unix)]
#[tokio::test]
async fn external_symlink_at_leaf_or_parent_cannot_escape() {
	let h = Harness::new();
	let outside = h.dav_root("bob").canonicalize().expect("bob root");
	let sentinel = outside.join("secret.txt");
	std::fs::write(&sentinel, b"bob-private").expect("sentinel");
	std::os::unix::fs::symlink(&outside, h.dav_root("alice").join("escape")).expect("parent link");
	std::os::unix::fs::symlink(&sentinel, h.dav_root("alice").join("leaf")).expect("leaf link");
	for path in ["/escape/secret.txt", "/leaf"] {
		for method in ["GET", "PUT", "DELETE"] {
			let reply = call(&h.dav, dav_request(method, path, Body::from("overwrite"))).await;
			assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
			assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"bob-private");
			h.healthy_dav().await;
		}
	}
}

#[tokio::test]
async fn infinite_depth_on_large_tree_is_refused() {
	let h = Harness::new();
	for n in 0..1024 {
		let dir = h.dav_root("alice").join(format!("tree/{n}/nested"));
		std::fs::create_dir_all(&dir).expect("large tree");
		std::fs::write(dir.join("item"), b"entry").expect("tree entry");
	}
	for depth in [None, Some("infinity"), Some("InFiNiTy")] {
		let mut request = dav_request("PROPFIND", "/tree", Body::empty());
		if let Some(depth) = depth {
			request
				.headers_mut()
				.insert("depth", HeaderValue::from_static(depth));
		}
		let reply = call(&h.dav, request).await;
		assert_eq!(reply.status, StatusCode::FORBIDDEN);
		assert!(String::from_utf8_lossy(&reply.body).contains("propfind-finite-depth"));
		assert!(reply.body.len() < 1024);
		h.healthy_dav().await;
	}
}

async fn inert_xml(h: &Harness, xml: String) {
	let mut request = dav_request("PROPFIND", "/", Body::from(xml));
	request
		.headers_mut()
		.insert("depth", HeaderValue::from_static("0"));
	let reply = call(&h.dav, request).await;
	assert_eq!(reply.status, StatusCode::MULTI_STATUS);
	assert!(
		reply.body.len() < 8192,
		"entity expansion must not enlarge the reply"
	);
	let text = String::from_utf8_lossy(&reply.body);
	assert!(!text.contains("XXE-PRIVATE-SENTINEL"));
	assert!(!text.contains("laugh-sentinel"));
	h.healthy_dav().await;
}

#[tokio::test]
async fn billion_laughs_entities_are_not_expanded() {
	let h = Harness::new();
	let mut xml = String::from("<!DOCTYPE propfind [<!ENTITY e0 'laugh-sentinel'>");
	for n in 1..=9 {
		xml.push_str(&format!(
			"<!ENTITY e{n} '{}'>",
			format!("&e{};", n - 1).repeat(10)
		));
	}
	xml.push_str(
		"]><D:propfind xmlns:D='DAV:'><D:prop><D:displayname>&e9;</D:displayname></D:prop></D:propfind>",
	);
	inert_xml(&h, xml).await;
}

#[tokio::test]
async fn external_xml_entity_cannot_disclose_local_file() {
	let h = Harness::new();
	let secret = h.dav_root("bob").join("xxe-secret");
	std::fs::write(&secret, b"XXE-PRIVATE-SENTINEL").expect("XXE fixture");
	let url =
		url::Url::from_file_path(secret.canonicalize().expect("secret path")).expect("file URL");
	inert_xml(&h, format!("<!DOCTYPE propfind [<!ENTITY xxe SYSTEM '{url}'>]><D:propfind xmlns:D='DAV:'><D:prop><D:displayname>&xxe;</D:displayname></D:prop></D:propfind>")).await;
}

#[tokio::test]
async fn xml_body_over_limit_is_refused_without_creating_resources() {
	let h = Harness::new();
	let mut request = dav_request("PROPFIND", "/", repeated_body(1024 * 1024 + 1));
	request
		.headers_mut()
		.insert("depth", HeaderValue::from_static("0"));
	assert_eq!(
		call(&h.dav, request).await.status,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	h.healthy_dav().await;
}

#[tokio::test]
async fn put_without_content_length_uses_actual_stream_size() {
	let h = Harness::new();
	let request = dav_request("PUT", "/stream.bin", repeated_body(65537));
	assert!(!request.headers().contains_key("content-length"));
	assert_eq!(call(&h.dav, request).await.status, StatusCode::CREATED);
	assert_eq!(
		std::fs::read(h.dav_root("alice").join("stream.bin")).expect("uploaded"),
		vec![b'x'; 65537]
	);
	h.healthy_dav().await;
}

#[tokio::test]
async fn oversized_streaming_put_cannot_replace_existing_file() {
	let h = Harness::new();
	let target = h.dav_root("alice").join("large.bin");
	std::fs::write(&target, b"original").expect("existing file");
	let request = dav_request("PUT", "/large.bin", repeated_body(50 * 1024 * 1024 + 1));
	assert_eq!(
		call(&h.dav, request).await.status,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	assert_eq!(std::fs::read(target).expect("existing file"), b"original");
	h.healthy_dav().await;
}

#[tokio::test]
async fn copy_and_move_destination_cannot_reach_bob() {
	let h = Harness::new();
	let source = h.dav_root("alice").join("source.txt");
	let sentinel = h.dav_root("bob").join("secret.txt");
	std::fs::write(&source, b"alice-source").expect("source");
	std::fs::write(&sentinel, b"bob-private").expect("sentinel");
	for method in ["COPY", "MOVE"] {
		for destination in [
			"/../../bob/dav/secret.txt",
			"https://example.test/%2e%2e/%2e%2e/bob/dav/secret.txt",
		] {
			let mut request = dav_request(method, "/source.txt", Body::empty());
			request
				.headers_mut()
				.insert("destination", destination.parse().expect("destination"));
			assert_eq!(call(&h.dav, request).await.status, StatusCode::FORBIDDEN);
			assert_eq!(
				std::fs::read(&source).expect("source kept"),
				b"alice-source"
			);
			assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"bob-private");
			h.healthy_dav().await;
		}
	}
}

async fn mismatched_etag(value: &'static str, expected: StatusCode) {
	let h = Harness::new();
	let target = h.dav_root("alice").join("conditional.txt");
	std::fs::write(&target, b"original").expect("original");
	let mut request = dav_request("PUT", "/conditional.txt", Body::from("overwrite"));
	request
		.headers_mut()
		.insert("if-match", HeaderValue::from_static(value));
	let reply = call(&h.dav, request).await;
	h.healthy_dav().await;
	assert_eq!(reply.status, expected);
	assert_eq!(
		std::fs::read(target).expect("original retained"),
		b"original"
	);
}

#[tokio::test]
async fn stale_if_match_cannot_overwrite() {
	mismatched_etag("\"stale\"", StatusCode::PRECONDITION_FAILED).await;
}

#[tokio::test]
async fn weak_if_match_cannot_overwrite() {
	mismatched_etag("W/\"stale\"", StatusCode::PRECONDITION_FAILED).await;
}

#[tokio::test]
async fn if_match_list_cannot_overwrite() {
	mismatched_etag(
		"\"old-one\", W/\"old-two\"",
		StatusCode::PRECONDITION_FAILED,
	)
	.await;
}

#[tokio::test]
async fn malformed_if_match_cannot_overwrite() {
	mismatched_etag("not-an-entity-tag", StatusCode::BAD_REQUEST).await;
}
