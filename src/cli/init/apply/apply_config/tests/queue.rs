//! `init` limits the receiver groups of a new configuration only.

use std::os::unix::fs::PermissionsExt;

use super::*;

fn desired_toml() -> String {
	let answers = crate::cli::init::compose::minimal_answers();
	let desired = build_config(
		&answers,
		"::".parse().unwrap(),
		Some(Path::new("/key")),
		None,
		Path::new("/cert"),
		Path::new("/tls-key"),
	)
	.unwrap();
	toml::to_string(&desired).unwrap()
}

fn group_limits(config: &toml::Value) -> Option<&toml::value::Table> {
	config
		.get("queue")?
		.get("per_group_concurrency")?
		.as_table()
}

#[test]
fn a_new_configuration_limits_the_receiver_groups() {
	let config: toml::Value = toml::from_str(&desired_toml()).unwrap();
	let limits = group_limits(&config).expect("[queue.per_group_concurrency] written");
	let mut written: Vec<(&str, i64)> = limits
		.iter()
		.map(|(group, value)| (group.as_str(), value.as_integer().expect("a number")))
		.collect();
	written.sort_unstable();
	assert_eq!(
		written,
		[
			("gmail", 2),
			("gmx", 2),
			("icloud", 2),
			("mailru", 2),
			("outlook", 2),
			("yahoo", 2),
		]
	);
	assert!(!limits.contains_key("other"));
}

#[test]
fn what_init_writes_loads_and_validates() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("mail.toml");
	std::fs::write(&path, desired_toml()).expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
	let config = crate::config::Config::load(&path).expect("loads and validates");
	assert_eq!(config.queue.per_group_concurrency.len(), 6);
}

#[test]
fn an_existing_configuration_keeps_its_own_queue_limits() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	for (existing, expected) in [
		("hostname = \"old.example.org\"\n", None),
		(
			"hostname = \"old.example.org\"\n[queue]\nconcurrency = 4\n",
			None,
		),
		(
			"hostname = \"old.example.org\"\n[queue.per_group_concurrency]\ngmail = 1\n",
			Some(vec![("gmail", 1)]),
		),
	] {
		let path = dir.path().join("mail.toml");
		std::fs::write(&path, existing).expect("write config");
		let _ = merge_with_existing(&path, &desired_toml(), false);
		let merged: toml::Value =
			toml::from_str(&std::fs::read_to_string(&path).expect("read back")).expect("toml");
		let got = group_limits(&merged).map(|limits| {
			limits
				.iter()
				.map(|(group, value)| (group.as_str(), value.as_integer().expect("a number")))
				.collect::<Vec<_>>()
		});
		assert_eq!(got, expected, "merged into {existing:?}");
		assert_eq!(
			merged.get("hostname").and_then(toml::Value::as_str),
			Some("mail.example.org"),
			"the merge itself ran"
		);
	}
}
