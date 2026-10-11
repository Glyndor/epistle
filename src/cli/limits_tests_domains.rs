use super::*;

#[test]
fn domain_maps_and_global_limits_preserve_exact_commented_text() {
	let (_dir, file) = super::tests_config::config_file();
	let original = std::fs::read_to_string(file.path()).unwrap();
	let original = format!(
		"# deployment\n{original}\n# quotas\n[domain_quotas]\n'example.org'  =  123 # cap\n'other.org' = 987\n\n# sending\n[domain_submission_limits]\n'example.org'  =  12 # rate\n"
	);
	std::fs::write(file.path(), &original).unwrap();
	for (key, input, expected) in [
		(
			Key::Quota,
			"10G",
			original.replace("=  123 # cap", "=  10737418240 # cap"),
		),
		(
			Key::SubmissionRate,
			"50",
			original
				.replace("=  123 # cap", "=  10737418240 # cap")
				.replace("=  12 # rate", "=  50 # rate"),
		),
	] {
		let doc = edit_document(file.path(), key, Some("example.org"), Some(input)).unwrap();
		assert_eq!(
			doc.commit().unwrap(),
			super::super::config_edit::Outcome::Changed
		);
		assert!(
			std::fs::read_to_string(file.path()).unwrap() == expected,
			"limits must preserve exact comments and unrelated formatting"
		);
	}
	let config = Config::load(file.path()).unwrap();
	assert_eq!(config.domain_quotas["example.org"], 10 * 1024_u64.pow(3));
	assert_eq!(config.domain_submission_limits["example.org"], 50);
	assert_eq!(config.domain_quotas["other.org"], 987);
	let before = std::fs::read_to_string(file.path()).unwrap();
	let modified = std::fs::metadata(file.path()).unwrap().modified().unwrap();
	assert_eq!(
		edit_document(file.path(), Key::Quota, Some("example.org"), Some("10G"))
			.unwrap()
			.commit()
			.unwrap(),
		super::super::config_edit::Outcome::Unchanged
	);
	assert_eq!(
		std::fs::metadata(file.path()).unwrap().modified().unwrap(),
		modified
	);
	edit_document(file.path(), Key::Quota, Some("example.org"), None)
		.unwrap()
		.commit()
		.unwrap();
	assert!(
		std::fs::read_to_string(file.path()).unwrap()
			== format!(
				"{}# cap\n",
				before.replace("'example.org'  =  10737418240 # cap\n", "")
			),
		"domain unset must preserve all comments and other entries"
	);
}

#[test]
fn limits_dry_run_returns_diff_without_writing_or_restarting() {
	let (_dir, file) = super::tests_config::config_file();
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	let code = run_with_restart(
		file.path(),
		Action::Set {
			key: Key::Quota,
			domain: None,
			value: "10G".into(),
		},
		true,
		&mut out,
		&mut status,
		|_, _| panic!("dry-run must not restart"),
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		String::from_utf8(out).unwrap(),
		edit_document(file.path(), Key::Quota, None, Some("10G"))
			.unwrap()
			.dry_run()
			.unwrap(),
		"limits dry-run must print the engine diff"
	);
	assert!(status.is_empty(), "dry-run must keep status output empty");
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == before,
		"dry-run must leave config byte-identical"
	);
}

#[test]
fn unsupported_domain_key_reports_exact_error_without_writing() {
	let (_dir, file) = super::tests_config::config_file();
	let before = std::fs::read(file.path()).unwrap();
	assert_eq!(
		edit_document(
			file.path(),
			Key::QueueGiveUp,
			Some("example.org"),
			Some("5d")
		)
		.err()
		.as_deref(),
		Some("--domain is supported only for quota and submission-rate")
	);
	assert!(
		std::fs::read(file.path()).unwrap() == before,
		"unsupported domain key must leave file untouched"
	);
}
