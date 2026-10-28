	/// Load a minimal `mail.toml` with `extra` appended.
	fn load(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
		use std::os::unix::fs::PermissionsExt;
		let dir = tempfile::tempdir().expect("tempdir");
		let path = dir.path().join("mail.toml");
		std::fs::write(
			&path,
			format!(
				"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n{extra}",
				dir.path()
			),
		)
		.expect("write config");
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
		crate::config::Config::load(&path)
	}

	#[test]
	fn a_config_without_an_auth_section_keeps_scram_on() {
		assert!(
			load("").expect("load").auth.scram,
			"an absent [auth] section must keep SCRAM enabled"
		);
	}

	#[test]
	fn an_empty_auth_section_keeps_scram_on() {
		assert!(load("[auth]\n").expect("load").auth.scram);
	}

	#[test]
	fn scram_false_turns_it_off() {
		assert!(!load("[auth]\nscram = false\n").expect("load").auth.scram);
	}

	#[test]
	fn a_config_without_an_auth_section_keeps_unicode_passwords_off() {
		// The historical default must be preserved when the [auth] section
		// is absent: existing configs do not get a new flag turned on.
		assert!(
			!load("").expect("load").auth.unicode_passwords,
			"an absent [auth] section must keep the ASCII-only policy"
		);
	}

	#[test]
	fn unicode_passwords_true_opt_in_is_accepted() {
		assert!(
			load("[auth]\nunicode_passwords = true\n")
				.expect("load")
				.auth
				.unicode_passwords
		);
	}

	#[test]
	fn an_unknown_auth_key_fails_the_load() {
		let error = load("[auth]\nscram = true\nsrcam = false\n").expect_err("unknown key");
		assert!(
			error.to_string().contains("srcam"),
			"the error must name the unknown key, got: {error}"
		);
	}
