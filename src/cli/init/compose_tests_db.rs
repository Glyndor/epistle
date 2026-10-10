//! The `db` service inside the rendered compose file: its
//! `network_mode == "none"` lock-down, the long-syntax secrets
//! mount with the explicit `uid`/`gid`/`mode` pin, the healthcheck
//! command that probes the real database over the unix socket,
//! the read-only root with `/tmp` as the only tmpfs, the top-level
//! `secrets` and `volumes` blocks when `services.database = true`,
//! the absence of those blocks when the database is off, the
//! digest-pinned `db` image, and the top-level secret file path.

use serde_json::Value;

use super::render;
use super::*;

#[test]
fn db_image_is_the_pinned_postgres_18_digest() {
	let value = render(&stack_answers(), true);
	let db_image = value["services"]["db"]["image"]
		.as_str()
		.expect("db image is a string");
	// The literal the test pins against is the full
	// digest-pinned reference, NOT the production code's
	// `POSTGRES_18_IMAGE` constant. A change to the constant
	// that drops the digest (`docker.io/library/postgres`
	// instead of `docker.io/library/postgres:18@sha256:...`)
	// would change the rendered image away from this
	// literal, and the test would fail.
	assert_eq!(
		db_image,
		"docker.io/library/postgres:18@sha256:06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941",
		"the rendered db image must be the digest-pinned postgres:18 reference; \
		 the production code's POSTGRES_18_IMAGE constant was changed and the pin was dropped"
	);
}

#[test]
fn db_uses_network_mode_none_and_has_no_ports() {
	let value = render(&stack_answers(), true);
	let db = &value["services"]["db"];
	assert_eq!(db["network_mode"], "none");
	assert!(db.get("ports").is_none(), "db must not publish any port");
	assert!(db.get("networks").is_none(), "db must not declare networks");
}

#[test]
fn db_secrets_uses_long_syntax_with_uid_999_and_octal_mode() {
	let value = render(&stack_answers(), true);
	let secrets = value["services"]["db"]["secrets"]
		.as_array()
		.expect("secrets is an array");
	assert_eq!(secrets.len(), 1);
	let mount = &secrets[0];
	assert_eq!(mount["source"], "epistle_db_password");
	assert_eq!(mount["target"], "epistle_db_password");
	assert_eq!(mount["uid"], "999");
	assert_eq!(mount["gid"], "999");
	// The mode is a JSON number; podup reads the value as octal.
	// The number `400` in the rendered file is `0o400` after
	// podup parses it: owner read-only. Writing `256` (which
	// is `0o400` in decimal interpretation) would be parsed by
	// podup as `0o256` and rejected for the owner-execute bit.
	assert_eq!(mount["mode"], 400);
}

#[test]
fn db_healthcheck_queries_the_real_database() {
	let value = render(&stack_answers(), true);
	let healthcheck = &value["services"]["db"]["healthcheck"];
	let test = healthcheck["test"]
		.as_array()
		.expect("healthcheck.test is an array");
	assert_eq!(test[0], "CMD-SHELL");
	let cmd = test[1].as_str().expect("cmd is a string");
	assert!(cmd.contains("psql"), "got {cmd}");
	assert!(cmd.contains("-U epistle"), "got {cmd}");
	assert!(cmd.contains("-d epistle"), "got {cmd}");
	assert!(cmd.contains("select 1"), "got {cmd}");
	assert!(
		cmd.contains("/var/run/postgresql"),
		"the healthcheck must connect over the socket, got {cmd}"
	);
	assert_eq!(healthcheck["interval"], "5s");
	assert_eq!(healthcheck["timeout"], "5s");
	assert_eq!(healthcheck["retries"], 30);
}

#[test]
fn db_is_read_only_with_a_tmpfs_for_tmp() {
	let value = render(&stack_answers(), true);
	let db = &value["services"]["db"];
	assert_eq!(db["read_only"], true);
	let tmpfs = db["tmpfs"].as_array().expect("tmpfs is an array");
	assert_eq!(tmpfs, &vec![Value::String("/tmp".to_string())]);
}

#[test]
fn top_level_secrets_and_volumes_present_when_database_is_on() {
	let value = render(&stack_answers(), true);
	let secrets = &value["secrets"];
	assert!(
		secrets["epistle_db_password"]["file"]
			.as_str()
			.is_some_and(|s| s.ends_with("epistle_db_password")),
		"the top-level secret must point at the on-host password file"
	);
	let volumes = &value["volumes"];
	assert!(volumes.get("epistle-pgdata").is_some());
	assert!(volumes.get("epistle-pgsock").is_some());
}

#[test]
fn database_off_has_no_db_no_secrets_no_volumes() {
	let value = render(&minimal_answers(), false);
	assert!(
		value["services"].get("db").is_none(),
		"with database off there must be no `db` service"
	);
	assert_eq!(
		value["secrets"]
			.as_object()
			.expect("secrets is an object")
			.len(),
		0,
		"with database off the top-level secrets block must be empty"
	);
	assert!(
		value["volumes"].is_null() || value["volumes"].as_object().is_some_and(|o| o.is_empty()),
		"with database off the top-level volumes block must be absent or empty"
	);
}

#[test]
fn db_top_level_secret_path_points_at_the_data_dir() {
	let value = render(&stack_answers(), true);
	let file = value["secrets"]["epistle_db_password"]["file"]
		.as_str()
		.expect("file is a string");
	assert!(file.contains("/var/lib/epistle"), "got {file}");
	assert!(file.ends_with("epistle_db_password"));
}
