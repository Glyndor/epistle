//! Requests the server refuses: overlapping move and copy, malformed depth, control characters and oversize resources.

use super::bounds::{alice, seed_overlap_fixture, send, test_app};
use axum::http::StatusCode;

#[tokio::test]
async fn move_into_descendant_is_refused_and_data_intact() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	seed_overlap_fixture(&app).await;
	// MOVE /a to /a/b/, `dest` is a descendant of `source`. Without the
	// fix, the destination is removed first and then the source is moved,
	// destroying everything under /a/.
	let (status, _) = send(
		&app,
		"MOVE",
		"/a",
		Some(&alice()),
		&[
			("Destination", "/a/b/".to_string()),
			("Overwrite", "T".to_string()),
		],
		b"",
	)
	.await;
	assert!(
		status == StatusCode::FORBIDDEN || status == StatusCode::CONFLICT,
		"expected 403 or 409, got {status}"
	);
	// /a/file1, /a/file2, /a/b/before must still exist with the same bytes.
	let (status1, body1) = send(&app, "GET", "/a/file1", Some(&alice()), &[], b"").await;
	assert_eq!(
		status1,
		StatusCode::OK,
		"/a/file1 vanished after refused MOVE"
	);
	assert_eq!(body1, b"one");
	let (status2, body2) = send(&app, "GET", "/a/file2", Some(&alice()), &[], b"").await;
	assert_eq!(
		status2,
		StatusCode::OK,
		"/a/file2 vanished after refused MOVE"
	);
	assert_eq!(body2, b"two");
	let (statusb, bodyb) = send(&app, "GET", "/a/b/before", Some(&alice()), &[], b"").await;
	assert_eq!(
		statusb,
		StatusCode::OK,
		"/a/b/before vanished after refused MOVE"
	);
	assert_eq!(bodyb, b"before");
}

#[tokio::test]
async fn copy_onto_self_is_refused_and_data_intact() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	seed_overlap_fixture(&app).await;
	// COPY /a to /a with Overwrite:T, destination is identical to the
	// source. The wrong behaviour is to delete the directory and try to
	// copy from it.
	let (status, _) = send(
		&app,
		"COPY",
		"/a",
		Some(&alice()),
		&[
			("Destination", "/a".to_string()),
			("Overwrite", "T".to_string()),
		],
		b"",
	)
	.await;
	assert!(
		status == StatusCode::FORBIDDEN || status == StatusCode::CONFLICT,
		"expected 403 or 409, got {status}"
	);
	let (status1, body1) = send(&app, "GET", "/a/file1", Some(&alice()), &[], b"").await;
	assert_eq!(
		status1,
		StatusCode::OK,
		"/a/file1 vanished after refused COPY"
	);
	assert_eq!(body1, b"one");
	let (status2, body2) = send(&app, "GET", "/a/file2", Some(&alice()), &[], b"").await;
	assert_eq!(
		status2,
		StatusCode::OK,
		"/a/file2 vanished after refused COPY"
	);
	assert_eq!(body2, b"two");
}

#[tokio::test]
async fn propfind_malformed_depth_returns_400_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	for depth in ["2", "-1", "bogus", ""] {
		let (status, body) = send(
			&app,
			"PROPFIND",
			"/",
			Some(&alice()),
			&[("Depth", depth.into())],
			b"",
		)
		.await;
		assert!(
			status == StatusCode::BAD_REQUEST && body.is_empty(),
			"malformed PROPFIND Depth must return 400 with an empty body"
		);
	}
	for headers in [vec![], vec![("Depth", "infinity".into())]] {
		let (status, body) = send(&app, "PROPFIND", "/", Some(&alice()), &headers, b"").await;
		let expected = concat!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
			"<D:error xmlns:D=\"DAV:\">\n",
			"  <D:propfind-finite-depth/>\n",
			"</D:error>\n"
		);
		assert!(
			status == StatusCode::FORBIDDEN && body == expected.as_bytes(),
			"infinite PROPFIND Depth must return the exact finite-depth precondition"
		);
	}
}

/// A name holding a control character is refused for every method that
/// would create it, in a plain collection and in a calendar, and creating
/// no other member is affected.
#[tokio::test]
async fn a_name_with_a_control_character_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(&alice()), &[], b"").await;
	send(&app, "PUT", "/d/a.txt", Some(&alice()), &[], b"a").await;
	send(
		&app,
		"MKCOL",
		"/cal",
		Some(&alice()),
		&[],
		crate::webdav::test_support::MKCOL_CALENDAR,
	)
	.await;
	for name in ["a%0Ab.txt", "a%09b.txt"] {
		let (status, _) = send(
			&app,
			"PUT",
			&format!("/d/{name}"),
			Some(&alice()),
			&[],
			b"x",
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "PUT {name}");
		let (status, _) = send(
			&app,
			"PUT",
			&format!("/cal/{name}"),
			Some(&alice()),
			&[],
			b"x",
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "PUT in calendar {name}");
		let (status, _) = send(
			&app,
			"MKCOL",
			&format!("/d/{name}"),
			Some(&alice()),
			&[],
			b"",
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "MKCOL {name}");
		let destination = format!("http://localhost/d/{name}");
		let (status, _) = send(
			&app,
			"COPY",
			"/d/a.txt",
			Some(&alice()),
			&[("Destination", destination.clone())],
			b"",
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "COPY {name}");
		let (status, _) = send(
			&app,
			"MOVE",
			"/d/a.txt",
			Some(&alice()),
			&[("Destination", destination)],
			b"",
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "MOVE {name}");
	}
	let (status, _) = send(&app, "PUT", "/d/b.txt", Some(&alice()), &[], b"x").await;
	assert!(status.is_success());
}

/// A file whose name already holds a control character cannot be read or
/// listed through DAV, but it can still be removed.
#[tokio::test]
async fn a_file_with_a_control_character_made_earlier_can_still_be_removed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(&alice()), &[], b"").await;
	let root = crate::webdav::path::account_root(dir.path(), "alice").expect("root");
	let old = root.join("d").join("old\nname.txt");
	std::fs::write(&old, b"x").expect("write");
	let (status, _) = send(&app, "GET", "/d/old%0Aname.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	let (status, _) = send(
		&app,
		"DELETE",
		"/d/old%0Aname.txt",
		Some(&alice()),
		&[],
		b"",
	)
	.await;
	assert!(status.is_success(), "{status}");
	assert!(!old.exists());
}

/// A calendar object or contact is held to what a report can always return
/// on its own, while other files keep the larger upload limit.
#[tokio::test]
async fn a_calendar_object_or_contact_over_the_resource_limit_is_refused() {
	use crate::webdav::report_bounds::MAX_RESOURCE_BYTES;
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(&alice()), &[], b"").await;
	let exact = vec![b'x'; MAX_RESOURCE_BYTES as usize];
	let over = vec![b'x'; MAX_RESOURCE_BYTES as usize + 1];
	for name in ["a.ics", "a.vcf"] {
		let (status, _) = send(
			&app,
			"PUT",
			&format!("/d/{name}"),
			Some(&alice()),
			&[],
			&exact,
		)
		.await;
		assert!(status.is_success(), "{name} at the limit: {status}");
		let (status, _) = send(
			&app,
			"PUT",
			&format!("/d/{name}"),
			Some(&alice()),
			&[],
			&over,
		)
		.await;
		assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{name} over it");
	}
	let (status, _) = send(&app, "PUT", "/d/a.bin", Some(&alice()), &[], &over).await;
	assert!(status.is_success(), "{status}");
}

/// Renaming or copying a big file onto a `.ics` or `.vcf` name meets the same
/// limit as uploading it there.
#[tokio::test]
async fn a_big_file_cannot_take_a_calendar_object_name_by_move_or_copy() {
	use crate::webdav::report_bounds::MAX_RESOURCE_BYTES;
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let big = vec![b'x'; MAX_RESOURCE_BYTES as usize + 1];
	let (status, _) = send(&app, "PUT", "/big.bin", Some(&alice()), &[], &big).await;
	assert!(status.is_success(), "{status}");
	for method in ["MOVE", "COPY"] {
		for name in ["moved.ics", "moved.vcf"] {
			let destination = format!("http://localhost/{name}");
			let (status, _) = send(
				&app,
				method,
				"/big.bin",
				Some(&alice()),
				&[("Destination", destination)],
				b"",
			)
			.await;
			assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {name}");
		}
	}
	let (status, _) = send(
		&app,
		"COPY",
		"/big.bin",
		Some(&alice()),
		&[("Destination", "http://localhost/copy.bin".to_string())],
		b"",
	)
	.await;
	assert!(status.is_success(), "{status}");
}
