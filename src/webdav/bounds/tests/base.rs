use std::path::Path;

use axum::Router;
use axum::http::StatusCode;

use super::{MAX_DEPTH, Refusal, check_now, forget_counts, subtree_depth};
use crate::webdav::test_support::{send_as_alice, test_app_with_quota};

fn dav(dir: &Path) -> std::path::PathBuf {
	dir.join("accounts/alice/dav")
}

/// An app whose account has no quota, so only the structural bounds apply.
fn unlimited(dir: &Path) -> Router {
	test_app_with_quota(dir, Some(0))
}

fn nested(root: &Path, levels: usize) -> std::path::PathBuf {
	let mut path = root.to_path_buf();
	for _ in 0..levels {
		path.push("d");
	}
	std::fs::create_dir_all(&path).expect("tree");
	path
}

#[test]
fn a_collection_holds_a_bounded_number_of_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dav(dir.path());
	std::fs::create_dir_all(&root).expect("dav");
	for n in 0..3 {
		let target = root.join(format!("{n}.bin"));
		assert_eq!(check_now(&root, &target, None, 3), Ok(()));
		std::fs::write(&target, b"x").expect("write");
	}
	assert_eq!(
		check_now(&root, &root.join("more.bin"), None, 3),
		Err(Refusal::TooMany)
	);
	// Replacing an entry that is there adds none.
	assert_eq!(check_now(&root, &root.join("1.bin"), None, 3), Ok(()));
	// Removing entries drops the kept count.
	std::fs::remove_file(root.join("2.bin")).expect("remove");
	forget_counts(&[&root.join("2.bin")]);
	assert_eq!(check_now(&root, &root.join("more.bin"), None, 3), Ok(()));
}

#[test]
fn the_depth_of_a_subtree_adds_to_the_depth_of_its_target() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dav(dir.path());
	let tree = nested(&root.join("src"), 5);
	assert_eq!(subtree_depth(&root.join("src")), 5);
	assert_eq!(subtree_depth(&tree), 0);
	let near = root.join("a/b/c");
	assert_eq!(
		check_now(&root, &near, Some(&root.join("src")), 100),
		Ok(())
	);
	let far = nested(&root.join("dst"), MAX_DEPTH - 4).join("copy");
	assert_eq!(
		check_now(&root, &far, Some(&root.join("src")), 100),
		Err(Refusal::TooDeep)
	);
	assert_eq!(check_now(&root, &far, None, 100), Ok(()));
}

#[tokio::test]
async fn the_depth_bound_holds_for_an_account_with_no_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = unlimited(dir.path());
	let mut path = String::new();
	for _ in 0..MAX_DEPTH {
		path.push_str("/d");
		let status = send_as_alice(&app, "MKCOL", &format!("{path}/"), &[], b"")
			.await
			.0;
		assert_eq!(status, StatusCode::CREATED, "{path}");
	}
	let deeper = format!("{path}/d/");
	assert_eq!(
		send_as_alice(&app, "MKCOL", &deeper, &[], b"").await.0,
		StatusCode::FORBIDDEN
	);
	let file = format!("{path}/f.bin");
	assert_eq!(
		send_as_alice(&app, "PUT", &file, &[], b"x").await.0,
		StatusCode::FORBIDDEN
	);
}

#[tokio::test]
async fn move_and_copy_check_the_depth_of_what_they_bring() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dav(dir.path());
	nested(&root.join("a"), 10);
	nested(&root.join("b"), 10);
	let app = unlimited(dir.path());
	for method in ["MOVE", "COPY"] {
		let (status, _) = send_as_alice(
			&app,
			method,
			"/a/",
			&[("Destination", "http://localhost/b/d/d/d/d/d/d/d/d/d/d/a/")],
			b"",
		)
		.await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{method}");
	}
	assert!(root.join("a/d").exists(), "nothing was moved");
	assert!(!root.join("b/d/d/d/d/d/d/d/d/d/d/a").exists());
	let (status, _) = send_as_alice(
		&app,
		"MOVE",
		"/a/",
		&[("Destination", "http://localhost/b/a/")],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}

#[test]
fn forgetting_one_collection_keeps_the_counts_of_the_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (a, b) = (dav(dir.path()).join("a"), dav(dir.path()).join("b"));
	std::fs::create_dir_all(&a).expect("a");
	std::fs::create_dir_all(&b).expect("b");
	let root = dav(dir.path());
	// Two creates are counted in each collection before either is written.
	for name in ["1", "2"] {
		assert_eq!(check_now(&root, &a.join(name), None, 2), Ok(()));
		assert_eq!(check_now(&root, &b.join(name), None, 2), Ok(()));
	}
	// A removal in b reopens b, and only b: the counted creates of a stay.
	forget_counts(&[&b.join("1")]);
	assert_eq!(check_now(&root, &b.join("3"), None, 2), Ok(()));
	assert_eq!(
		check_now(&root, &a.join("3"), None, 2),
		Err(Refusal::TooMany)
	);
}

#[test]
fn forgetting_a_collection_forgets_what_is_below_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dav(dir.path());
	let inner = root.join("a/b");
	std::fs::create_dir_all(&inner).expect("tree");
	assert_eq!(check_now(&root, &inner.join("1"), None, 1), Ok(()));
	assert_eq!(
		check_now(&root, &inner.join("2"), None, 1),
		Err(Refusal::TooMany)
	);
	forget_counts(&[&root.join("a")]);
	assert_eq!(check_now(&root, &inner.join("2"), None, 1), Ok(()));
}

#[test]
fn a_check_that_could_not_run_is_an_error_not_a_pass() {
	let response = super::refusal_response(Refusal::Unavailable);
	assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
