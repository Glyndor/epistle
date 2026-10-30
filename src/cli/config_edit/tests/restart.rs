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
