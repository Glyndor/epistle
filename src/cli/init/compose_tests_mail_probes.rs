//! The `mail` service healthcheck shape that the generated compose
//! file must carry. Every test here asserts against the rendered JSON
//! the apply phase would write, so a regression in `new_mail` shows up
//! as a missing / wrong `healthcheck` field rather than a failed
//! runtime healthcheck.

use super::local_image_answers;
use super::minimal_answers;
use super::render;
use super::stack_answers;

/// The `[CMD, /usr/bin/epistle, probe, --config, <path>]` healthcheck
/// test, as the exec form Compose and Compose-derived orchestrators
/// (podman, podup) require. The `["CMD", ...]` wrapper is the form
/// that bypasses a shell, which the distroless image does not have.
const EXPECTED_TEST: &[&str] = &[
	"CMD",
	"/usr/bin/epistle",
	"probe",
	"--config",
	"/etc/epistle/mail.toml",
];

#[test]
fn mail_healthcheck_is_present_in_default_image_mode() {
	// Default mode (answers leave `image` unset, bind-mount the host
	// binary into distroless) is the path an operator reaches by
	// running `epistle init` without `-i`. The container's only
	// binary is the bind-mounted host `/usr/bin/epistle`, so the
	// healthcheck cannot use a shell or curl and must call that
	// binary's `probe` subcommand directly.
	let value = render(&minimal_answers(), false);
	let mail = &value["services"]["mail"];
	let healthcheck = mail
		.get("healthcheck")
		.unwrap_or_else(|| panic!("mail service must declare a healthcheck; got {mail}"));
	assert!(
		!healthcheck.is_null(),
		"mail healthcheck must be an object, got {healthcheck:?}"
	);
}

#[test]
fn mail_healthcheck_uses_the_probe_subcommand_with_the_configured_path() {
	// The shape of the `test` field is the only thing an orchestrator
	// uses to decide what command to run inside the container: a
	// mismatched CMD array (or a typo on `probe`) would silently
	// healthcheck something else and report green when nothing is
	// listening. The path argument is bound to the operator's
	// chosen `config_path`, so the test pins the exact string.
	let value = render(&minimal_answers(), false);
	let mail = &value["services"]["mail"];
	let healthcheck = &mail["healthcheck"];
	let test = healthcheck["test"]
		.as_array()
		.unwrap_or_else(|| panic!("healthcheck.test must be an array; got {healthcheck:?}"));
	let test_strs: Vec<&str> = test
		.iter()
		.map(|v| v.as_str().expect("test entry is a string"))
		.collect();
	assert_eq!(
		test_strs,
		Vec::from(EXPECTED_TEST),
		"healthcheck must invoke `/usr/bin/epistle probe --config <path>`; got {test_strs:?}"
	);
}

#[test]
fn mail_healthcheck_timing_matches_the_distroless_first_byte_window() {
	// interval/timeout/retries/start_period are a deliberate
	// fixed set. They are not arbitrary: `timeout` has to be longer
	// than the probe's own 2-second per-listener budget so a slow
	// listener surface does not leak as a timeout from `timeout`,
	// `interval` is short enough that a stuck listener is noticed
	// but long enough that a healthy restart does not flap.
	let value = render(&minimal_answers(), false);
	let healthcheck = &value["services"]["mail"]["healthcheck"];
	assert_eq!(
		healthcheck["interval"], "30s",
		"healthcheck interval must be 30s"
	);
	assert_eq!(
		healthcheck["timeout"], "10s",
		"healthcheck timeout must be 10s"
	);
	assert_eq!(
		healthcheck["retries"].as_u64(),
		Some(3),
		"healthcheck retries must be 3"
	);
	assert_eq!(
		healthcheck["start_period"], "30s",
		"healthcheck start_period must be 30s"
	);
}

#[test]
fn mail_healthcheck_uses_epistle_probe_against_a_known_config_path() {
	// The on-disk config the probe is told to read must be the same
	// one `serve` was started with. The container's `command:` is
	// `serve --config <path>`; a healthcheck against a different
	// path would either probe the wrong listeners or fail to parse
	// a file the serve did not write.
	let value = render(&minimal_answers(), false);
	let mail_cmd = value["services"]["mail"]["command"]
		.as_array()
		.expect("mail.command is an array");
	let serve_config_path = mail_cmd
		.iter()
		.position(|v| v == "--config")
		.and_then(|idx| mail_cmd.get(idx + 1))
		.and_then(|v| v.as_str())
		.expect("mail.command carries a --config argument");
	let healthcheck_test = value["services"]["mail"]["healthcheck"]["test"]
		.as_array()
		.expect("healthcheck.test is an array");
	let probe_config_arg = healthcheck_test
		.iter()
		.position(|v| v == "--config")
		.and_then(|idx| healthcheck_test.get(idx + 1))
		.and_then(|v| v.as_str())
		.expect("healthcheck.test carries a --config argument");
	assert_eq!(
		probe_config_arg, serve_config_path,
		"probe must read the same config serve was started with"
	);
}

#[test]
fn mail_healthcheck_is_present_in_custom_image_mode() {
	// Custom-image mode (operator passes `image = ...`) keeps the
	// same healthcheck command: the operator's image is expected to
	// contain `/usr/bin/epistle` (documented in docs/cli.md), so
	// the same exec form applies. The test pins the contract that a
	// future change to the custom-image branch did not silently drop
	// the healthcheck while preserving the bind-mount branch.
	let value = render(&local_image_answers(), true);
	let mail = &value["services"]["mail"];
	let healthcheck = mail.get("healthcheck").unwrap_or_else(|| {
		panic!("custom-image mail service must declare a healthcheck; got {mail}")
	});
	let test = healthcheck["test"]
		.as_array()
		.expect("custom-image healthcheck.test must be an array");
	let test_strs: Vec<&str> = test
		.iter()
		.map(|v| v.as_str().expect("test entry is a string"))
		.collect();
	assert_eq!(
		test_strs,
		Vec::from(EXPECTED_TEST),
		"custom-image mail healthcheck must use the same probe command; got {test_strs:?}"
	);
}

#[test]
fn mail_healthcheck_uses_the_custom_image_config_path() {
	// The probe must read whatever path the operator's answers
	// declared for the config (their `mail.toml`), not the path the
	// default mode happens to use. A regression that hard-codes the
	// packaged path would surface here as a string mismatch.
	let mut answers = local_image_answers();
	answers.config_path = std::path::PathBuf::from("/srv/epistle/mail.toml");
	let value = render(&answers, false);
	let healthcheck_test = value["services"]["mail"]["healthcheck"]["test"]
		.as_array()
		.expect("healthcheck.test is an array");
	let probe_config_arg = healthcheck_test
		.iter()
		.position(|v| v == "--config")
		.and_then(|idx| healthcheck_test.get(idx + 1))
		.and_then(|v| v.as_str())
		.expect("healthcheck.test carries --config");
	assert_eq!(
		probe_config_arg, "/srv/epistle/mail.toml",
		"custom-image probe must read the operator's chosen config path"
	);
}

#[test]
fn mail_healthcheck_stays_the_same_with_a_database_dependency() {
	// The `db` dependency adds `services.db` and gates `mail` on
	// `service_healthy`, but the healthcheck on `mail` itself must
	// not change shape under the database-on branch. This is a
	// shape regression test: a future refactor that keyed the
	// healthcheck off the database toggle would surface here.
	let value = render(&stack_answers(), true);
	let healthcheck = &value["services"]["mail"]["healthcheck"];
	assert_eq!(
		healthcheck["interval"], "30s",
		"healthcheck interval must be 30s regardless of database"
	);
	let test = healthcheck["test"]
		.as_array()
		.expect("healthcheck.test is an array");
	let test_strs: Vec<&str> = test
		.iter()
		.map(|v| v.as_str().expect("test entry is a string"))
		.collect();
	assert_eq!(
		test_strs,
		Vec::from(EXPECTED_TEST),
		"healthcheck command must not depend on the database toggle"
	);
}
