use super::*;

#[test]
fn mta_sts_cli_parses_options_and_default_listen() {
	let key_path = uuid::Uuid::now_v7().simple().to_string();
	let args = [
		"epistle",
		"mta-sts-serve",
		"--policy-dir",
		"/policy",
		"--cert",
		"/cert.pem",
		"--key",
		&key_path,
	];
	let parsed = Cli::try_parse_from(args).expect("CLI");
	let Command::MtaStsServe {
		policy_dir,
		cert,
		key,
		listen,
	} = parsed.command
	else {
		panic!("wrong command")
	};
	assert_eq!(policy_dir, PathBuf::from("/policy"));
	assert_eq!(cert, PathBuf::from("/cert.pem"));
	assert_eq!(key, PathBuf::from(&key_path));
	assert_eq!(listen, "0.0.0.0:8443".parse().expect("socket address"));
	let parsed = Cli::try_parse_from(args.into_iter().chain(["--listen", "127.0.0.1:0"]))
		.expect("explicit listen");
	assert!(
		matches!(parsed.command, Command::MtaStsServe { listen, .. } if listen == "127.0.0.1:0".parse().expect("address"))
	);
}

#[test]
fn dns_command_uses_policy_content_identifier() {
	let mut config: crate::config::Config = toml::from_str(
		"hostname = 'mail.example.org'\ndata_dir = '/unused'\ndomains = ['example.org']",
	)
	.expect("config");
	let mut ids = Vec::new();
	for mode in [
		crate::config::MtaStsMode::Testing,
		crate::config::MtaStsMode::Enforce,
	] {
		config.mta_sts.mode = mode;
		let publication = crate::mtasts::publish::publication(&config);
		let mut output = Vec::new();
		assert_eq!(dns_records::run(&config, &mut output), ExitCode::SUCCESS);
		let output = String::from_utf8(output).expect("DNS text");
		let record = output
			.lines()
			.find(|line| line.starts_with("_mta-sts.example.org "))
			.expect("MTA-STS TXT");
		assert_eq!(
			record,
			format!(
				"_mta-sts.example.org 3600 IN TXT \"v=STSv1; id={}\"",
				publication.id
			)
		);
		ids.push(publication.id);
	}
	assert_ne!(ids[0], ids[1]);
}
