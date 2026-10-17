//! Settings that cannot be trusted never make verification looser: they are
//! refused, and the caller keeps what it had or stops.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::Entry;

fn write_raw(dir: &Path, text: &str) {
	std::fs::write(dir.join(FILE), text).expect("write");
	std::fs::set_permissions(dir.join(FILE), std::fs::Permissions::from_mode(0o600))
		.expect("chmod");
}

fn error_of(dir: &Path) -> std::io::Error {
	load(dir).expect_err("the settings must be refused")
}

fn valid() -> Settings {
	Settings::default()
}

#[test]
fn a_settings_file_others_can_write_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	save(dir.path(), &valid()).expect("save");
	std::fs::set_permissions(
		dir.path().join(FILE),
		std::fs::Permissions::from_mode(0o666),
	)
	.expect("chmod");
	let error = error_of(dir.path());
	assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
	assert_eq!(
		error.to_string(),
		"timestamp settings are writable by other users: refused"
	);
}

#[test]
fn a_symlinked_settings_file_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let elsewhere = tempfile::tempdir().expect("tempdir");
	save(elsewhere.path(), &valid()).expect("save");
	std::os::unix::fs::symlink(elsewhere.path().join(FILE), dir.path().join(FILE)).expect("link");
	assert_eq!(
		error_of(dir.path()).kind(),
		std::io::ErrorKind::PermissionDenied
	);
}

#[test]
fn a_corrupt_file_is_refused_not_defaulted() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_raw(dir.path(), "{\"enabled\": tru");
	assert_eq!(error_of(dir.path()).kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn an_empty_or_unparsable_anchor_list_is_refused_on_load() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_raw(
		dir.path(),
		r#"{"enabled":true,"authorities":[{"url":"https://tsa.example.org","anchors":[]}]}"#,
	);
	assert_eq!(
		error_of(dir.path()).to_string(),
		"each authority needs 1 to 8 anchors"
	);
	write_raw(
		dir.path(),
		r#"{"enabled":true,"authorities":[{"url":"https://tsa.example.org","anchors":["not-a-hash"]}]}"#,
	);
	assert!(error_of(dir.path()).to_string().starts_with("an anchor is"));
}

#[test]
fn an_unknown_policy_format_is_refused_on_load() {
	let dir = tempfile::tempdir().expect("tempdir");
	let anchor = DEFAULT_TSA_ANCHOR;
	write_raw(
		dir.path(),
		&format!(
			r#"{{"enabled":true,"authorities":[{{"url":"https://tsa.example.org","anchors":["{anchor}"],"policy":"policy-one"}}]}}"#
		),
	);
	assert_eq!(
		error_of(dir.path()).to_string(),
		"a policy is a dotted object identifier"
	);
}

#[test]
fn plain_http_is_refused_unless_marked_as_a_local_test_authority() {
	let mut settings = valid();
	settings.authorities[0].url = "http://127.0.0.1:3180/tsr".into();
	assert_eq!(
		settings.validate().map_err(|error| error.0),
		Err(
			"a timestamp authority URL must be https (plain http only for a local test authority)"
				.into()
		)
	);
	settings.authorities[0].local_test = true;
	assert_eq!(settings.validate(), Ok(()));
	settings.authorities[0].url = "http://tsa.example.org/tsr".into();
	assert!(
		settings.validate().is_err(),
		"a local test authority must be on loopback"
	);
}

#[test]
fn disabling_timestamps_is_recorded_in_the_chain_with_its_operator() {
	let dir = tempfile::tempdir().expect("tempdir");
	let disabled = Settings {
		enabled: false,
		..valid()
	};
	record_change(dir.path(), &disabled, "uid=1001 (operator)").expect("record");
	assert_eq!(load(dir.path()).expect("load"), disabled);
	let chain = Chain::open(dir.path()).expect("open");
	let day = *chain.days().expect("days").last().expect("a day");
	let mut settings = Vec::new();
	crate::evidence::verify::walk_day(dir.path(), day, None, |_, record, _| {
		if let Entry::Setting(setting) = &record.entry {
			settings.push((setting.name.clone(), setting.value.clone()));
		}
	})
	.expect("walk");
	assert_eq!(
		settings,
		vec![(
			"timestamp".to_string(),
			"disabled by uid=1001 (operator)".to_string()
		)]
	);
}
