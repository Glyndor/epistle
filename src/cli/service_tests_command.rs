use super::*;

fn fixture() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	std::fs::write(file.path(), format!("# deployment\nhostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n\n# public socket\n[[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n", dir.path().canonicalize().unwrap())).unwrap();
	(dir, file)
}

#[test]
fn service_command_dry_run_then_change_and_no_op() {
	let (_dir, file) = fixture();
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let action = || ServiceCli::Enable {
		name: ServiceName::Webdav,
	};
	let result = execute_with(
		file.path(),
		action(),
		true,
		&mut out,
		&mut status,
		|_, _| panic!("dry-run must not restart"),
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let expected =
		super::super::service_edit::listener_document(file.path(), ListenerKind::WebDav, true)
			.unwrap()
			.dry_run()
			.unwrap();
	assert_eq!(
		String::from_utf8(out.clone()).unwrap(),
		expected,
		"service dry-run must print the engine diff"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == before,
		"service dry-run must preserve config bytes"
	);
	assert!(status.is_empty());
	out.clear();
	assert_eq!(
		execute_with(
			file.path(),
			action(),
			false,
			&mut out,
			&mut status,
			|_, _| panic!("host install must not invoke stack")
		)
		.unwrap(),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(status.clone()).unwrap(),
		"webdav enabled.\nThe server must be restarted.\n"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap()
			== format!("{before}\n[[listeners]]\nkind = \"web-dav\"\naddr = \"0.0.0.0\"\n"),
		"service command must preserve exact commented text"
	);
	status.clear();
	let modified = std::fs::metadata(file.path()).unwrap().modified().unwrap();
	assert_eq!(
		execute_with(
			file.path(),
			action(),
			false,
			&mut out,
			&mut status,
			|_, _| panic!("no-op must not restart")
		)
		.unwrap(),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"webdav is already enabled; nothing changed.\n"
	);
	assert_eq!(
		std::fs::metadata(file.path()).unwrap().modified().unwrap(),
		modified
	);
}

#[test]
/// A published port only changes when the container is recreated: a plain
/// restart keeps the old port forwarding, so a disabled listener would stay
/// reachable. The stack is brought up again, which recreates mail.
fn service_command_updates_ports_and_recreates_mail() {
	let (_dir, file) = fixture();
	let config = Config::load(file.path()).unwrap();
	let compose = super::super::init::compose_file_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"ports":["25:25"],"image":"keep"}}}"#,
	)
	.unwrap();
	let code = execute_with(
		file.path(),
		ServiceCli::Enable {
			name: ServiceName::Webdav,
		},
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|config, action| {
			assert_eq!(config.listeners.len(), 2);
			assert!(
				matches!(&action, super::super::stack::StackAction::Recreate { service } if service == "mail"),
				"a port change must recreate mail, not restart it: {action:?}"
			);
			ExitCode::from(7)
		},
	)
	.unwrap();
	assert_eq!(
		code,
		ExitCode::from(7),
		"service command must propagate restart failure"
	);
	let compose: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(compose).unwrap()).unwrap();
	assert_eq!(
		compose["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "8090:8090"])
	);
	assert_eq!(compose["services"]["mail"]["image"], "keep");
}
