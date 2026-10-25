use super::*;

#[test]
fn an_address_used_by_another_principal_stops_both_runs_before_anything_is_written() {
	for owner in [
		"dynamic account",
		"static account",
		"alias",
		"masked address",
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let initial = if owner == "alias" {
			"alice@example.org"
		} else {
			"owner@example.org"
		};
		let table = first_account_table(dir.path(), initial);
		assert_eq!(
			init(answers(dir.path(), &table), false).0,
			ExitCode::from(EXIT_OK)
		);
		let same = first_account_table(dir.path(), initial);
		assert_eq!(
			init(answers(dir.path(), &same), true).0,
			ExitCode::from(EXIT_OK),
			"{owner} keeps its own address"
		);
		let requested = match owner {
			"dynamic account" | "static account" => "Taken@Example.ORG".to_string(),
			"alias" => "Postmaster@Example.ORG".to_string(),
			"masked address" => store(dir.path())
				.add_masked("owner", "Taken", "example.org", 1)
				.expect("masked address")
				.address
				.to_ascii_uppercase(),
			_ => unreachable!(),
		};
		if owner == "dynamic account" {
			let config = crate::config::Config::load(&dir.path().join("etc").join("mail.toml"))
				.expect("config");
			let policy = crate::password::Policy::from_config(&config.auth);
			let account = crate::directory_store::DynamicAccount::with_password(
				"other".to_string(),
				vec!["taken@example.org".to_string()],
				password(),
				&policy,
				config.auth.scram,
			)
			.expect("account");
			store(dir.path()).add(account).expect("add account");
		}
		if owner == "static account" {
			let config = dir.path().join("etc").join("mail.toml");
			let mut text = std::fs::read_to_string(&config).expect("read config");
			text.push_str(
				"\n[[accounts]]\nname = \"other\"\naddresses = [\"taken@example.org\"]\n",
			);
			std::fs::write(&config, text).expect("write config");
		}
		let before = listing(dir.path());
		let clash = first_account_table(dir.path(), &requested);
		for dry_run in [true, false] {
			let (code, out) = init(answers(dir.path(), &clash), dry_run);
			assert_eq!(
				code,
				ExitCode::from(EXIT_INVALID),
				"{owner}, dry_run {dry_run}: {out}"
			);
		}
		assert_eq!(
			listing(dir.path()),
			before,
			"{owner} left the tree as it was"
		);
	}
}

#[test]
fn an_alias_is_found_when_the_existing_config_does_not_load() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "alice@example.org");
	assert_eq!(
		init(answers(dir.path(), &table), false).0,
		ExitCode::from(EXIT_OK)
	);
	let config = dir.path().join("etc").join("mail.toml");
	std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664)).expect("chmod");
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "Postmaster@Example.ORG");
	for dry_run in [true, false] {
		let (code, out) = init(answers(dir.path(), &clash), dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(listing(dir.path()), before, "nothing was written");
}
