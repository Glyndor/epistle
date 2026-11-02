//! Every way a `disable` can fail after it starts: the copy of the account
//! key it places under data_dir, where `mail` reads, never outlives a split
//! that stays, and when it cannot be removed safely the message names it.

use super::*;

fn disable_failing(steps: Vec<&'static str>) -> (Recorder, String) {
	let mut host = Recorder::with_certs(true);
	host.fail = steps;
	let error = switch(&mut host, false).expect_err("the disable fails");
	(host, error)
}

#[test]
fn a_render_that_fails_places_no_key() {
	let (host, error) = disable_failing(vec!["render"]);
	assert!(error.contains("render false failed"), "{error}");
	assert_eq!(host.steps, ["render false"]);
}

#[test]
fn a_compose_write_that_fails_removes_the_placed_copy() {
	let (host, error) = disable_failing(vec!["write certs=false"]);
	assert_eq!(
		host.steps,
		[
			"render false",
			"place false",
			"write certs=false",
			"write certs=true",
			"podup up -d --remove-orphans",
			"retire",
		]
	);
	assert!(error.contains("removed again"), "{error}");
}

#[test]
fn a_failed_up_removes_the_placed_copy() {
	let (host, error) = disable_failing(vec!["podup"]);
	assert_eq!(host.steps.last().map(String::as_str), Some("retire"));
	assert!(error.contains("/data/acme/account.key"), "{error}");
}

#[test]
fn a_failed_restore_before_the_new_layout_ran_still_removes_the_copy() {
	let (host, error) = disable_failing(vec!["write certs=false", "write certs=true"]);
	assert_eq!(host.steps.last().map(String::as_str), Some("retire"));
	assert!(error.contains("failed as well"), "{error}");
	assert!(error.contains("removed again"), "{error}");
}

/// The layout without `certs` started and could not be replaced: `mail`
/// may be renewing with that copy, so it stays, and the message says where
/// it is and that `mail` can read it.
#[test]
fn a_failed_restore_after_the_new_layout_ran_names_the_copy_to_delete() {
	let (host, error) = disable_failing(vec!["ready mail", "write certs=true"]);
	assert!(
		!host.steps.contains(&"retire".to_string()),
		"{:?}",
		host.steps
	);
	assert!(error.contains("/data/acme/account.key"), "{error}");
	assert!(error.contains("mail can read it"), "{error}");
}

/// `stack up` of a split stack removes a copy left under data_dir, and only
/// on a split stack.
#[test]
fn stack_up_removes_a_leftover_copy_only_when_certs_runs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let compose = dir.path().join("compose.yaml");
	crate::acme::renew::load_or_create_account_key(&data_dir).expect("key");
	crate::cli::init::host_secrets::acme::place(&data_dir, true).expect("copy");
	let copy = crate::acme::renew::account_key_path(&data_dir);

	std::fs::write(&compose, Recorder::with_certs(false).compose).expect("whole");
	retire_before_up(&data_dir, &compose).expect("up");
	assert!(copy.exists(), "mail renews with it without the split");

	std::fs::write(&compose, Recorder::with_certs(true).compose).expect("split");
	retire_before_up(&data_dir, &compose).expect("up");
	assert!(!copy.exists());

	std::fs::write(&compose, "not json").expect("garbage");
	assert!(retire_before_up(&data_dir, &compose).is_err());
}

#[test]
fn a_copy_that_cannot_be_removed_is_named() {
	let (_, error) = disable_failing(vec!["ready mail", "retire"]);
	assert!(error.contains("could not be removed"), "{error}");
	assert!(error.contains("/data/acme/account.key"), "{error}");
}
