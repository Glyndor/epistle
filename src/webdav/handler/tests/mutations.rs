//! Deleting, copying and moving resources, path traversal, authentication and account isolation.

use super::base::{alice, bob, send, test_app};
use axum::http::{StatusCode, header};

#[tokio::test]
async fn delete_removes_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/x.txt", Some(&alice()), &[], b"x").await;
	let (status, _, _) = send(&app, "DELETE", "/x.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, _, _) = send(&app, "GET", "/x.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_collection_recursively() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(&alice()), &[], b"").await;
	send(&app, "PUT", "/d/a.txt", Some(&alice()), &[], b"a").await;
	let (status, _, _) = send(&app, "DELETE", "/d", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, _, _) = send(&app, "GET", "/d/a.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_missing_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "DELETE", "/none", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn copy_duplicates_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/src.txt", Some(&alice()), &[], b"data").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/src.txt",
		Some(&alice()),
		&[("Destination", "/dst.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (_, src, _) = send(&app, "GET", "/src.txt", Some(&alice()), &[], b"").await;
	let (_, dst, _) = send(&app, "GET", "/dst.txt", Some(&alice()), &[], b"").await;
	assert_eq!(src, b"data");
	assert_eq!(dst, b"data");
}

#[tokio::test]
async fn move_relocates_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/src.txt", Some(&alice()), &[], b"data").await;
	let (status, _, _) = send(
		&app,
		"MOVE",
		"/src.txt",
		Some(&alice()),
		&[("Destination", "/moved.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, _, _) = send(&app, "GET", "/src.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (_, dst, _) = send(&app, "GET", "/moved.txt", Some(&alice()), &[], b"").await;
	assert_eq!(dst, b"data");
}

#[tokio::test]
async fn copy_no_overwrite_is_precondition_failed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/a.txt", Some(&alice()), &[], b"a").await;
	send(&app, "PUT", "/b.txt", Some(&alice()), &[], b"b").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/a.txt",
		Some(&alice()),
		&[
			("Destination", "/b.txt".to_string()),
			("Overwrite", "F".to_string()),
		],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn copy_with_absolute_url_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/s.txt", Some(&alice()), &[], b"u").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/s.txt",
		Some(&alice()),
		&[("Destination", "https://dav.example.org/d.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, _, _) = send(&app, "GET", "/d.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn traversal_in_path_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/%2e%2e/escape.txt", Some(&alice()), &[], b"x").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn traversal_in_destination_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/s.txt", Some(&alice()), &[], b"x").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/s.txt",
		Some(&alice()),
		&[("Destination", "/../../bob/dav/stolen.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "GET", "/x.txt", None, &[], b"").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert!(
		resp_headers
			.get(header::WWW_AUTHENTICATE)
			.unwrap()
			.to_str()
			.unwrap()
			.starts_with("Basic ")
	);
}

#[tokio::test]
async fn wrong_password_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "GET", "/x.txt", Some("alice:wrong"), &[], b"").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_isolation_is_enforced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	// Alice writes a private file.
	send(
		&app,
		"PUT",
		"/secret.txt",
		Some(&alice()),
		&[],
		b"alice-only",
	)
	.await;
	// Bob requests the same path: he gets his own (empty) tree, never Alice's.
	let (status, _, _) = send(&app, "GET", "/secret.txt", Some(&bob()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	// Bob writes his own file; Alice's is untouched and distinct.
	send(&app, "PUT", "/secret.txt", Some(&bob()), &[], b"bob-only").await;
	let (_, alice_body, _) = send(&app, "GET", "/secret.txt", Some(&alice()), &[], b"").await;
	let (_, bob_body, _) = send(&app, "GET", "/secret.txt", Some(&bob()), &[], b"").await;
	assert_eq!(alice_body, b"alice-only");
	assert_eq!(bob_body, b"bob-only");
}

#[tokio::test]
async fn unknown_method_is_method_not_allowed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "LOCK", "/x.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
