use super::*;

#[test]
fn existing_destination_is_reused_but_never_replaced_with_another_token() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("secrets/dns_provider_token");
	store(&path, "original-token").unwrap();
	store(&path, "original-token").unwrap();
	let error = store(&path, "replacement-token").unwrap_err();
	assert!(error.contains("different token"));
	assert!(!error.contains("original-token") && !error.contains("replacement-token"));
	assert!(fs::read_to_string(path).unwrap() == "original-token");
}
