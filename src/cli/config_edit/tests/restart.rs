use super::*;
use std::process::ExitCode;

#[test]
fn restart_policy_observes_changes_and_compose_presence() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let config = Config::parse_text(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}",
			dir.path().canonicalize().unwrap()
		),
		Path::new("mail.toml"),
	)
	.unwrap();
	let mut output = Vec::new();
	for (outcome, needs_restart) in [(Outcome::Unchanged, true), (Outcome::Changed, false)] {
		let code = after_change_with(&config, outcome, needs_restart, &mut output, |_, _| {
			panic!("no restart expected")
		})
		.unwrap();
		assert_eq!(code, ExitCode::SUCCESS);
		assert!(
			output.is_empty(),
			"no-op or reload-free changes must not print a restart notice"
		);
	}
	let code = after_change_with(&config, Outcome::Changed, true, &mut output, |_, _| {
		panic!("host install must not invoke stack")
	})
	.unwrap();
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		String::from_utf8(output).unwrap(),
		"The server must be restarted.\n"
	);
	let compose = crate::cli::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(compose, "{}").unwrap();
	let code = after_change_with(&config, Outcome::Changed, true, &mut Vec::new(), |_, action| {
		assert!(matches!(action, crate::cli::stack::StackAction::Restart { service: Some(name) } if name == "mail"), "restart must target only mail");
		ExitCode::from(7)
	}).unwrap();
	assert_eq!(
		code,
		ExitCode::from(7),
		"restart failures must reach the caller"
	);
}

#[test]
fn deferred_restart_leaves_the_stack_alone_and_says_how_to_apply() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let config = Config::parse_text(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}",
			dir.path().canonicalize().unwrap()
		),
		Path::new("mail.toml"),
	)
	.unwrap();
	let compose = crate::cli::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(compose, "{}").unwrap();
	let action = || crate::cli::stack::StackAction::Restart {
		service: Some("mail".into()),
	};
	let mut ran = false;
	let mut output = Vec::new();
	let (code, reload) = super::super::restart::apply_deferring(
		true,
		&config,
		Outcome::Changed,
		true,
		&mut output,
		|_, _| {
			ran = true;
			ExitCode::SUCCESS
		},
		action(),
	)
	.unwrap();
	assert!(!ran, "--no-restart must not touch the stack");
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(reload, crate::cli::json_out::Reload::Deferred);
	let text = String::from_utf8(output).unwrap();
	assert!(
		text.contains("epistle stack apply"),
		"the notice names the command: {text}"
	);
	let (_, reload) = super::super::restart::apply_deferring(
		false,
		&config,
		Outcome::Changed,
		true,
		&mut Vec::new(),
		|_, _| ExitCode::SUCCESS,
		action(),
	)
	.unwrap();
	assert_eq!(reload, crate::cli::json_out::Reload::Restarted);
}
