//! The database roles: PostgreSQL's bootstrap superuser is a separate
//! admin role with its own secret, and `epistle` is created without any
//! superuser attribute, as the owner of its database only.

use super::render;
use super::*;
use serde_json::json;

#[test]
fn the_image_bootstraps_an_admin_role_with_its_own_secret() {
	let value = render(&stack_answers(), true);
	let env = &value["services"]["db"]["environment"];
	assert_eq!(env["POSTGRES_USER"], "epistle_admin");
	assert_eq!(
		env["POSTGRES_PASSWORD_FILE"],
		"/run/secrets/epistle_db_admin_password"
	);
	assert_eq!(env["POSTGRES_DB"], "epistle");
	assert_eq!(
		value["secrets"]["epistle_db_admin_password"],
		json!({"file": "/var/lib/secrets/epistle_db_admin_password"}),
		"beside data_dir, so mail cannot read it through its data_dir mount"
	);
}

#[test]
fn only_db_mounts_the_admin_secret() {
	let value = render(&stack_answers(), true);
	let mounts = value["services"]["db"]["secrets"].as_array().unwrap();
	assert!(mounts.contains(&json!({
		"source": "epistle_db_admin_password",
		"target": "epistle_db_admin_password",
		"uid": "999",
		"gid": "999",
		"mode": 400
	})));
	for name in ["mail", "clamav", "freshclam"] {
		assert!(
			!value["services"][name]
				.to_string()
				.contains("admin_password"),
			"{name}"
		);
	}
}

#[test]
fn a_first_start_creates_epistle_without_superuser() {
	let value = render(&stack_answers(), true);
	assert_eq!(
		value["services"]["db"]["configs"],
		json!([{
			"source": "epistle_db_roles",
			"target": "/docker-entrypoint-initdb.d/10-epistle-roles.sh",
			"mode": 444
		}])
	);
	let script = value["configs"]["epistle_db_roles"]["content"]
		.as_str()
		.expect("the script is inline");
	for needle in [
		"NOSUPERUSER",
		"NOCREATEDB",
		"NOCREATEROLE",
		"NOREPLICATION",
		"NOBYPASSRLS",
		"ALTER DATABASE epistle OWNER TO epistle",
		"REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC",
		"/run/secrets/epistle_db_password",
		"ON_ERROR_STOP=1",
	] {
		assert!(script.contains(needle), "{needle} missing from:\n{script}");
	}
	assert!(
		!script.contains('$'),
		"compose interpolates `$NAME` in values, so the script names no variable"
	);
}

#[test]
fn without_the_database_there_is_no_admin_secret_and_no_script() {
	let value = render(&minimal_answers(), false);
	assert!(value["secrets"].get("epistle_db_admin_password").is_none());
	assert!(value.get("configs").is_none());
}
