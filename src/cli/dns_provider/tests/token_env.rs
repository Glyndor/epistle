//! The variable the token lives in has to be visible where the container
//! reads it.
//!
//! `dns provider set` knows the name of the variable the operator gave, so
//! it can say that the variable is not set here, where the operator is
//! watching, instead of leaving the failure to `dns provider test` ("the
//! provider credentials could not be resolved"). The configuration is still
/// written: the operator may set the variable afterwards.
use super::base::EnvVar;
use super::write::{action, stack};
use super::*;

/// A variable name no other test uses, so the environment this test reads is
/// the one it sets: the environment is process-global, and a name two tests
/// share is a name one of them removes while the other still runs.
const UNSET_A: &str = "EPISTLE_TEST_1592_UNSET_A";
const UNSET_B: &str = "EPISTLE_TEST_1592_UNSET_B";
const SET_A: &str = "EPISTLE_TEST_1592_SET_A";
const SET_B: &str = "EPISTLE_TEST_1592_SET_B";

/// A value no other test uses, so finding it in the output means the
/// command printed the secret.
const MARKER: &str = "epistle-1592-marker-value";

/// What one run of the command left behind: the two streams, the exit
/// code, and the files it wrote.
struct Ran {
	out: String,
	status: String,
	code: ExitCode,
	config: String,
	compose: String,
}

/// The `set` command with a token variable, run against a stack install.
fn set_token_env(name: &str, dry_run: bool) -> Ran {
	let (_dir, path, compose) = stack();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-env", name]),
		dry_run,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	Ran {
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		code: result.unwrap_or(ExitCode::FAILURE),
		config: std::fs::read_to_string(&path).unwrap(),
		compose: std::fs::read_to_string(&compose).unwrap(),
	}
}

/// A variable the environment does not hold is reported where the operator
/// is watching, and the provider is saved anyway: the operator may set the
/// variable afterwards.
#[test]
fn an_unset_token_variable_warns_and_still_saves_the_provider() {
	let _env = EnvVar::unset(UNSET_A);
	let ran = set_token_env(UNSET_A, false);
	assert_eq!(
		ran.code,
		ExitCode::SUCCESS,
		"the warning is not a failure: {}",
		ran.status
	);
	assert!(
		ran.status.contains("warning:") && ran.status.contains(UNSET_A),
		"the warning has to name the variable: {}",
		ran.status
	);
	assert!(
		ran.status.contains("service account"),
		"the warning has to say where the variable has to be visible: {}",
		ran.status
	);
	assert!(
		ran.config.contains(&format!("token_env = \"{UNSET_A}\"")),
		"the configuration has to name the variable: {}",
		ran.config
	);
	let document: serde_json::Value = serde_json::from_str(&ran.compose).unwrap();
	assert_eq!(
		document["services"]["mail"]["environment"][UNSET_A],
		format!("${{{UNSET_A}}}"),
		"the variable has to reach the container"
	);
}

/// The dry run says the same thing: the operator sees the warning before
/// the change, not after it.
#[test]
fn a_dry_run_warns_about_the_unset_variable_and_writes_nothing() {
	let _env = EnvVar::unset(UNSET_B);
	let (_dir, path, compose) = stack();
	let before = std::fs::read_to_string(&path).unwrap();
	let compose_before = std::fs::read_to_string(&compose).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-env", UNSET_B]),
		true,
		false,
		&mut out,
		&mut status,
		|_, _| panic!("a dry run must not reach the stack"),
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let printed = String::from_utf8(status).unwrap();
	assert!(
		printed.contains("warning:") && printed.contains(UNSET_B),
		"the dry run has to warn about the variable: {printed}"
	);
	assert_eq!(
		std::fs::read_to_string(&path).unwrap(),
		before,
		"a dry run must not write the configuration"
	);
	assert_eq!(
		std::fs::read_to_string(&compose).unwrap(),
		compose_before,
		"a dry run must not write the compose file"
	);
}

/// A variable the environment holds is not reported: the operator set it.
#[test]
fn a_set_token_variable_does_not_warn() {
	let _env = EnvVar::set(SET_A, MARKER);
	let ran = set_token_env(SET_A, false);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert!(
		!ran.status.contains("warning:"),
		"a variable that is set must not be reported: {}",
		ran.status
	);
	assert!(
		ran.config.contains(&format!("token_env = \"{SET_A}\"")),
		"the configuration has to name the variable: {}",
		ran.config
	);
}

/// The value of the variable never reaches the terminal: the command names
/// the variable, never what it holds.
#[test]
fn the_value_of_the_token_variable_is_never_printed() {
	let _env = EnvVar::set(SET_B, MARKER);
	let ran = set_token_env(SET_B, false);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert!(
		!ran.out.contains(MARKER),
		"the value reached stdout: {}",
		ran.out
	);
	assert!(
		!ran.status.contains(MARKER),
		"the value reached stderr: {}",
		ran.status
	);
}
