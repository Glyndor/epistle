use super::*;
use clap::Parser;

fn config_in(dir: &Path, socket: &Path) -> Config {
	let encoded = percent_encoding::utf8_percent_encode(
		&socket.to_string_lossy(),
		percent_encoding::NON_ALPHANUMERIC,
	)
	.to_string();
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n[database]\nurl = 'postgres://epistle@{encoded}/epistle'\n"
	)).expect("config")
}

fn compose_in(dir: &Path) -> std::path::PathBuf {
	let path = super::super::init::compose_file_path(dir);
	std::fs::create_dir_all(path.parent().unwrap()).expect("compose directory");
	std::fs::write(&path, r#"{"services":{"mail":{"command":["serve","--config","/mounted/config/mail.toml"],"volumes":["/host/config:/mounted/config:ro"]}}}"#).expect("compose");
	path
}

fn argv(command: &ProcessCommand) -> Vec<OsString> {
	std::iter::once(command.get_program().to_owned())
		.chain(command.get_args().map(OsString::from))
		.collect()
}

#[test]
fn absent_host_socket_delegates_with_the_mail_command_config() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), &dir.path().join("missing-socket"));
	let compose = compose_in(dir.path());
	let args = ["ban", "--config=/host/config/mail.toml", "list", "--json"].map(OsString::from);
	let command = exec_spec(&config, &args).expect("decision");
	assert!(
		command.is_some(),
		"a compose stack with an absent host socket must delegate to mail"
	);
	assert_eq!(
		argv(&command.unwrap()),
		vec![
			OsString::from("podup"),
			OsString::from("-f"),
			compose.into_os_string(),
			OsString::from("exec"),
			OsString::from("-T"),
			OsString::from("mail"),
			OsString::from("/usr/bin/epistle"),
			OsString::from("ban"),
			OsString::from("list"),
			OsString::from("--json"),
			OsString::from("--config"),
			OsString::from("/mounted/config/mail.toml"),
		]
	);
}

#[test]
fn available_socket_or_absent_compose_or_tcp_database_runs_locally() {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config_in(dir.path(), &dir.path().join("missing-socket"));
	assert!(exec_spec(&config, &[]).unwrap().is_none());
	compose_in(dir.path());
	config = config_in(dir.path(), dir.path());
	assert!(exec_spec(&config, &[]).unwrap().is_none());
	config.database.as_mut().unwrap().url = "postgres://epistle@127.0.0.1/epistle".into();
	assert!(exec_spec(&config, &[]).unwrap().is_none());
	config.database = None;
	assert!(exec_spec(&config, &[]).unwrap().is_none());
}

#[test]
fn only_operator_paths_that_open_a_pool_are_selected() {
	for (args, selected) in [
		(vec!["epistle", "ban", "list"], true),
		// status stays on the host, where the published ports are what it
		// checks; only its db area asks the container.
		(vec!["epistle", "status", "--json"], false),
		(vec!["epistle", "check", "db"], true),
		(
			vec![
				"epistle",
				"account-remove",
				"--name",
				"alice",
				"--queue",
				"discard",
			],
			true,
		),
		// The resource form of `account-remove` purges the same bayes rows.
		(
			vec![
				"epistle", "account", "remove", "alice", "--queue", "discard",
			],
			true,
		),
		(vec!["epistle", "account", "list"], false),
		(vec!["epistle", "check", "ports"], false),
		(vec!["epistle", "probe"], false),
		(vec!["epistle", "serve"], false),
		(vec!["epistle", "backup"], false),
	] {
		let cli = super::super::Cli::try_parse_from(args.clone()).expect("CLI");
		assert_eq!(
			database_config(&cli.command).is_some(),
			selected,
			"{args:?}"
		);
	}
}

#[test]
fn exec_arguments_preserve_flags_without_database_secrets() {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config_in(dir.path(), &dir.path().join("missing-socket"));
	compose_in(dir.path());
	let secret = "private-database-password";
	let db = config.database.as_mut().unwrap();
	db.url = db.url.replace("epistle@", &format!("epistle:{secret}@"));
	db.password_file = Some(dir.path().join("private-password-file"));
	for args in [
		vec![
			"ban",
			"allow",
			"list",
			"--json",
			"--config",
			"/host/mail.toml",
		],
		vec!["check", "db"],
		vec!["check", "db", "--config=/host/mail.toml", "--json"],
		vec!["account-remove", "--name", "alice", "--queue", "discard"],
	] {
		let original = args.iter().map(OsString::from).collect::<Vec<_>>();
		let command = exec_spec(&config, &original).unwrap().expect("delegate");
		let actual = argv(&command);
		assert!(
			!actual
				.iter()
				.any(|arg| arg.to_string_lossy().contains(secret)),
			"database passwords must stay out of argv"
		);
		assert!(
			!actual
				.iter()
				.any(|arg| arg.to_string_lossy().contains("private-password-file")),
			"database password file paths must stay out of argv"
		);
		let cli = super::super::Cli::try_parse_from(actual.into_iter().skip(6))
			.expect("delegated argv parses");
		assert_eq!(
			database_config(&cli.command),
			Some(Path::new("/mounted/config/mail.toml"))
		);
	}
}

#[test]
fn query_socket_urls_also_delegate() {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config_in(dir.path(), dir.path());
	compose_in(dir.path());
	config.database.as_mut().unwrap().url = format!(
		"postgres://epistle@localhost/epistle?host={}",
		dir.path().join("missing").display()
	);
	assert!(exec_spec(&config, &[]).unwrap().is_some());
}

#[test]
fn stopped_or_missing_mail_suggests_starting_the_stack() {
	let expected = Err("the mail container is not running; run `epistle stack up`".to_string());
	assert_eq!(require_running_mail("[]"), expected);
	assert_eq!(
		require_running_mail(r#"[{"Service":"mail","State":"exited"}]"#),
		expected
	);
	assert_eq!(
		require_running_mail(r#"[{"Service":"db","State":"running"}]"#),
		expected
	);
	assert_eq!(
		require_running_mail(r#"[{"Service":"mail","State":"running"}]"#),
		Ok(())
	);
}
