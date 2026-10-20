//! Tests for the client-address clause the `--ip-cidr` advisories read.

use std::path::Path;

use super::*;

/// A data directory holding a compose file whose `mail` service carries
/// `network_mode`, or none at all when `mode` is `None`.
fn data_dir(dir: &Path, mode: Option<&str>) -> std::path::PathBuf {
	let network_mode = mode.map(|mode| format!("\"network_mode\": {mode:?},"));
	let compose = format!(
		"{{\"services\": {{\"mail\": {{ {} \"restart\": \"always\" }}}}}}",
		network_mode.unwrap_or_default()
	);
	let path = super::super::init::compose_file_path(dir);
	std::fs::create_dir_all(path.parent().expect("a parent")).expect("create dir");
	std::fs::write(&path, compose).expect("write compose");
	dir.to_path_buf()
}

#[test]
fn pasta_keeps_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(hidden_clause(&data_dir(dir.path(), Some("pasta"))), None);
}

#[test]
fn host_keeps_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(hidden_clause(&data_dir(dir.path(), Some("host"))), None);
}

#[test]
fn a_bridge_names_itself() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clause = hidden_clause(&data_dir(dir.path(), Some("bridge"))).expect("a clause");
	assert!(clause.contains("\"bridge\""), "{clause}");
}

#[test]
fn slirp4netns_names_itself_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clause = hidden_clause(&data_dir(dir.path(), Some("slirp4netns"))).expect("a clause");
	assert!(clause.contains("\"slirp4netns\""), "{clause}");
}

#[test]
fn no_network_mode_is_the_engine_default_bridge() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clause = hidden_clause(&data_dir(dir.path(), None)).expect("a clause");
	assert!(clause.contains("no network_mode"), "{clause}");
}

#[test]
fn without_a_stack_there_is_nothing_to_say() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(hidden_clause(dir.path()), None);
}

#[test]
fn an_unparseable_compose_file_says_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = super::super::init::compose_file_path(dir.path());
	std::fs::create_dir_all(path.parent().expect("a parent")).expect("create dir");
	std::fs::write(&path, "not json").expect("write compose");
	assert_eq!(hidden_clause(dir.path()), None);
}
