//! Hostile mailbox names must neither escape the account nor mutate its tree.

use std::path::{Path, PathBuf};

use super::harness::*;

/// Include directory names and file contents, so an empty escaped folder counts.
fn tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
	fn visit(root: &Path, dir: &Path, found: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
		for entry in std::fs::read_dir(dir).expect("read tree") {
			let entry = entry.expect("tree entry");
			let path = entry.path();
			let relative = path
				.strip_prefix(root)
				.expect("contained fixture")
				.to_path_buf();
			if entry.file_type().expect("entry type").is_dir() {
				found.push((relative, None));
				visit(root, &path, found);
			} else {
				found.push((
					relative,
					Some(std::fs::read(path).expect("fixture contents")),
				));
			}
		}
	}
	let mut found = Vec::new();
	visit(root, root, &mut found);
	found.sort();
	found
}

async fn hostile_names(names: &[String]) {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	send(&mut client, b"C CREATE Real\r\n").await;
	expect(&mut client, "C OK CREATE completed\r\n").await;
	// Protected fixtures are inside the temp root but outside this user's account.
	for dir in ["etc/new", "accounts/etc/new", "accounts/victim/new"] {
		let path = server.data.path().join(dir);
		std::fs::create_dir_all(&path).expect("protected fixture directory");
		std::fs::write(path.join("canary"), b"must remain unchanged").expect("canary");
	}
	let before = tree(server.data.path());
	for name in names {
		for (command, reply) in [
			(
				format!("A SELECT \"{name}\"\r\n"),
				"A NO no such mailbox\r\n",
			),
			(
				format!("A CREATE \"{name}\"\r\n"),
				"A NO invalid mailbox name\r\n",
			),
			(
				format!("A RENAME Real \"{name}\"\r\n"),
				"A NO cannot rename\r\n",
			),
			(
				format!("A RENAME \"{name}\" Other\r\n"),
				"A NO cannot rename\r\n",
			),
		] {
			send(&mut client, command.as_bytes()).await;
			expect(&mut client, reply).await;
			assert_eq!(
				tree(server.data.path()),
				before,
				"mutation after {command:?}"
			);
			noop(&mut client).await;
			server.healthy().await;
		}
	}
	assert!(epistle::imap::mailbox::exists(
		server.data.path(),
		"tester",
		"Real"
	));
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn traversal_in_select_create_and_both_rename_operands_is_refused() {
	hostile_names(&[
		"../../etc".into(),
		"INBOX/../..".into(),
		"../victim".into(),
		"a//b".into(),
	])
	.await;
}

#[tokio::test]
async fn oversized_names_in_select_create_and_rename_are_refused() {
	// Both fit the command-line limit, so only mailbox validation can reject them.
	hostile_names(&["x".repeat(256), "x".repeat(4096)]).await;
}

#[tokio::test]
async fn enormous_depth_in_select_create_and_rename_is_refused() {
	hostile_names(&[vec!["x"; 17].join("/"), vec!["x"; 4096].join("/")]).await;
}

#[tokio::test]
async fn nul_names_in_select_create_and_rename_close_without_mutation() {
	let server = Harness::start(|s| s).await;
	let mut setup = server.authenticated().await;
	send(&mut setup, b"C CREATE Real\r\n").await;
	expect(&mut setup, "C OK CREATE completed\r\n").await;
	logout(&mut setup).await;
	for command in [
		b"A SELECT \"INBOX\0/../..\"\r\n".as_slice(),
		b"A CREATE \"bad\0name\"\r\n",
		b"A RENAME Real \"bad\0name\"\r\n",
		b"A RENAME \"bad\0name\" Other\r\n",
	] {
		let mut client = server.authenticated().await;
		let before = tree(server.data.path());
		send(&mut client, command).await;
		expect(&mut client, PROTOCOL).await;
		closed(&mut client).await;
		assert_eq!(tree(server.data.path()), before);
		server.healthy().await;
	}
}
