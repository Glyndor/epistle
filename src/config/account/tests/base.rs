use super::*;

#[test]
fn parses_account() {
	let account: Account = toml::from_str(
		r#"
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
	)
	.expect("parse account");
	assert_eq!(account.name, "alice");
	assert_eq!(account.addresses.len(), 2);
}

#[test]
fn rejects_unknown_keys() {
	let result: Result<Account, _> = toml::from_str(
		r#"
name = "alice"
addresses = []
quota = "1G"
"#,
	);
	assert!(result.is_err());
}
