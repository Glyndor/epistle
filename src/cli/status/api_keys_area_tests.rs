//! Tests for API key expiry and SCIM domain warnings.

use super::{Level, check};
use crate::cli::status::test_support::ctx;

fn keys_file(dir: &std::path::Path, body: &str) {
	std::fs::write(dir.join("api_keys.toml"), body).expect("write API key store");
}

fn key(label: &str, expiry: &str, scopes: &str, domains: &str) -> String {
	format!(
		"[[keys]]\nlabel = {label:?}\nhash = \"sha256:stored-hash-must-not-leak\"\n{expiry}{scopes}{domains}\n"
	)
}

/// The compose file `epistle init` would leave, with the `network_mode` the
/// `mail` service ends up on.
fn compose(data_dir: &std::path::Path, mode: &str) {
	let path = crate::cli::init::compose_file_path(data_dir);
	std::fs::create_dir_all(path.parent().expect("a parent")).expect("create dir");
	std::fs::write(
		&path,
		format!("{{\"services\": {{\"mail\": {{\"network_mode\": {mode:?}}}}}}}"),
	)
	.expect("write compose");
}

/// A key with an `--ip-cidr` and an expiry, so the only advisory it can carry
/// is the one about the network.
fn pinned(expiry: bool) -> String {
	let expiry = if expiry {
		"expires_at = 4102444800\n"
	} else {
		""
	};
	format!(
		"[[keys]]\nlabel = \"ci\"\nhash = \"sha256:stored-hash-must-not-leak\"\n{expiry}\
		 scopes = [\"read\"]\nip_cidr = \"10.0.0.0/24\"\n"
	)
}

#[tokio::test]
async fn a_missing_key_file_is_an_empty_healthy_store() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	let report = check(&context).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[tokio::test]
async fn a_key_without_expiry_warns_with_label_and_scope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	keys_file(
		&dir.path().join("data"),
		&key("automation", "", "scopes = [\"read\"]\n", ""),
	);
	let report = check(&context).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items.len(), 1);
	assert!(report.items[0].name.contains("automation"));
	assert!(report.items[0].name.contains("read"));
	assert!(report.items[0].detail.contains("no expiry"));
}

#[tokio::test]
async fn a_scim_key_without_domains_warns_with_its_scope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	keys_file(
		&dir.path().join("data"),
		&key(
			"provisioner",
			"expires_at = 4102444800\n",
			"scopes = [\"scim\"]\n",
			"",
		),
	);
	let report = check(&context).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items.len(), 1);
	assert!(report.items[0].name.contains("provisioner"));
	assert!(report.items[0].name.contains("scim"));
	assert!(report.items[0].detail.contains("no associated domain"));
}

#[tokio::test]
async fn expiring_keys_and_scim_keys_with_domains_are_healthy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	let body = format!(
		"{}{}",
		key(
			"reader",
			"expires_at = 4102444800\n",
			"scopes = [\"read\"]\n",
			""
		),
		key(
			"provisioner",
			"expires_at = 4102444800\n",
			"scopes = [\"scim\"]\n",
			"domains = [\"example.org\"]\n"
		)
	);
	keys_file(&dir.path().join("data"), &body);
	let report = check(&context).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[tokio::test]
async fn a_pinned_key_warns_when_the_network_hides_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	let data = dir.path().join("data");
	keys_file(&data, &pinned(true));
	compose(&data, "bridge");
	let report = check(&context).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items.len(), 1, "{report:?}");
	assert!(report.items[0].name.contains("ci"));
	assert!(report.items[0].detail.contains("10.0.0.0/24"));
	assert!(report.items[0].detail.contains("bridge"));
}

#[tokio::test]
async fn a_pinned_key_is_healthy_when_pasta_keeps_the_client_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	let data = dir.path().join("data");
	keys_file(&data, &pinned(true));
	compose(&data, "pasta");
	let report = check(&context).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[tokio::test]
async fn a_pinned_key_says_nothing_without_a_container_stack() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	keys_file(&dir.path().join("data"), &pinned(true));
	let report = check(&context).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[tokio::test]
async fn malformed_store_warns_without_echoing_stored_values() {
	let dir = tempfile::tempdir().expect("tempdir");
	let context = ctx(dir.path(), "");
	keys_file(
		&dir.path().join("data"),
		"not valid TOML: stored-hash-must-not-leak",
	);
	let report = check(&context).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let output = format!("{report:?}");
	assert!(!output.contains("stored-hash-must-not-leak"));
}
