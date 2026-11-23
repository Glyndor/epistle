//! The class a credential or an account sends under decides what evidence is
//! kept and what a marketing send must carry, so a class that is not one is
//! refused before anything is bound, and a good one reaches the bindings file
//! the server reads: `account set --default-class`, `app-password create
//! --class` and `api-key create --class`.

use epistle::evidence::{MailClass, bindings};

use crate::harness::{Env, add_account, env, epistle};

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

fn bound(env: &Env) -> bindings::Bindings {
	bindings::load(&env.data_dir()).expect("bindings")
}

fn listed(env: &Env, resource: &str) -> String {
	let output = epistle(&[resource, "list", "--config", &env.config, "--json"], b"");
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn an_account_default_class_is_checked_bound_and_cleared() {
	let env = env("");
	add_account(&env, "alice");
	let set = |class: &str| {
		epistle(
			&[
				"account",
				"set",
				"alice",
				"--default-class",
				class,
				"--config",
				&env.config,
			],
			b"",
		)
	};
	for bogus in ["bulk", "Spam", "", "marketing,personal"] {
		let output = set(bogus);
		assert_eq!(output.status.code(), Some(2), "{bogus:?}");
		assert!(output.stdout.is_empty(), "{bogus:?}");
		assert!(
			stderr(&output).contains("unknown class"),
			"{bogus:?}: {}",
			stderr(&output)
		);
		assert!(bound(&env).accounts.is_empty(), "{bogus:?}");
	}
	assert_eq!(set("marketing").status.code(), Some(0));
	assert_eq!(
		bound(&env).accounts.get("alice"),
		Some(&MailClass::Marketing)
	);
	assert_eq!(set("personal").status.code(), Some(0));
	assert_eq!(
		bound(&env).accounts.get("alice"),
		Some(&MailClass::Personal)
	);
	assert_eq!(set("none").status.code(), Some(0));
	assert!(bound(&env).accounts.is_empty());
}

#[test]
fn a_default_class_for_an_account_that_is_not_there_binds_nothing() {
	let env = env("");
	let output = epistle(
		&[
			"account",
			"set",
			"ghost",
			"--default-class",
			"marketing",
			"--config",
			&env.config,
		],
		b"",
	);
	assert_ne!(output.status.code(), Some(0));
	assert!(output.stdout.is_empty());
	assert!(bound(&env).accounts.is_empty());
}

#[test]
fn an_app_password_class_is_checked_and_bound_to_the_credential() {
	let env = env("");
	add_account(&env, "alice");
	let create = |label: &str, class: &str| {
		epistle(
			&[
				"app-password",
				"create",
				"alice",
				label,
				"--class",
				class,
				"--config",
				&env.config,
			],
			b"",
		)
	};
	for bogus in ["bulk", "Spam", ""] {
		let output = create("phone", bogus);
		assert_eq!(output.status.code(), Some(2), "{bogus:?}");
		assert!(output.stdout.is_empty(), "{bogus:?}");
		assert!(
			stderr(&output).contains("unknown class"),
			"{bogus:?}: {}",
			stderr(&output)
		);
	}
	assert!(!listed(&env, "app-password").contains("phone"));
	assert!(bound(&env).credentials.is_empty());

	assert_eq!(create("phone", "marketing").status.code(), Some(0));
	let credentials = bound(&env).credentials;
	assert_eq!(credentials.len(), 1);
	assert_eq!(credentials.values().next(), Some(&MailClass::Marketing));
	// A second credential without a class binds nothing for itself.
	let plain = epistle(
		&[
			"app-password",
			"create",
			"alice",
			"tablet",
			"--config",
			&env.config,
		],
		b"",
	);
	assert_eq!(plain.status.code(), Some(0), "{}", stderr(&plain));
	assert_eq!(bound(&env).credentials.len(), 1);
}

#[test]
fn an_api_key_class_is_checked_and_bound_to_the_key() {
	let env = env("");
	let create = |label: &str, class: &str| {
		epistle(
			&[
				"api-key",
				"create",
				label,
				"--scope",
				"send",
				"--class",
				class,
				"--config",
				&env.config,
			],
			b"",
		)
	};
	for bogus in ["bulk", "Spam", ""] {
		let output = create("mailer", bogus);
		assert_eq!(output.status.code(), Some(2), "{bogus:?}");
		assert!(output.stdout.is_empty(), "{bogus:?}");
		assert!(
			stderr(&output).contains("unknown class"),
			"{bogus:?}: {}",
			stderr(&output)
		);
	}
	assert!(!listed(&env, "api-key").contains("mailer"));
	assert!(bound(&env).credentials.is_empty());

	assert_eq!(create("mailer", "transactional").status.code(), Some(0));
	let credentials = bound(&env).credentials;
	assert_eq!(credentials.len(), 1);
	assert_eq!(credentials.values().next(), Some(&MailClass::Transactional));
}
