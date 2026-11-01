use super::*;

fn sample() -> Llm {
	Llm {
		endpoint: "https://api.example/v1/chat/completions".to_string(),
		api_key_env: "EPISTLE_LLM_API_KEY".to_string(),
		model: "gpt-4o-mini".to_string(),
		uncertain_low: 0.35,
		uncertain_high: 0.65,
		timeout_secs: 10,
		max_body_bytes: 16384,
	}
}

#[test]
fn parses_with_defaults() {
	let parsed: Llm = toml::from_str(
		r#"
endpoint = "https://api.example/v1/chat/completions"
api_key_env = "EPISTLE_LLM_API_KEY"
model = "gpt-4o-mini"
"#,
	)
	.expect("parse");
	assert_eq!(parsed.uncertain_low, 0.35);
	assert_eq!(parsed.uncertain_high, 0.65);
	assert_eq!(parsed.timeout_secs, 10);
	assert_eq!(parsed.max_body_bytes, 16384);
}

#[test]
fn parses_with_overrides() {
	let parsed: Llm = toml::from_str(
		r#"
endpoint = "https://api.example/v1/chat/completions"
api_key_env = "X"
model = "m"
uncertain_low = 0.2
uncertain_high = 0.8
timeout_secs = 5
max_body_bytes = 1024
"#,
	)
	.expect("parse");
	assert_eq!(parsed.uncertain_low, 0.2);
	assert_eq!(parsed.uncertain_high, 0.8);
	assert_eq!(parsed.timeout_secs, 5);
	assert_eq!(parsed.max_body_bytes, 1024);
}

#[test]
fn rejects_unknown_keys() {
	assert!(
		toml::from_str::<Llm>(
			r#"
endpoint = "https://x/y"
api_key_env = "X"
model = "m"
surprise = true
"#,
		)
		.is_err()
	);
}

#[test]
fn band_is_inclusive() {
	let llm = sample();
	assert!(llm.is_uncertain(0.35));
	assert!(llm.is_uncertain(0.65));
	assert!(llm.is_uncertain(0.5));
	assert!(!llm.is_uncertain(0.349));
	assert!(!llm.is_uncertain(0.651));
}

#[test]
fn validate_rejects_inverted_band() {
	let mut llm = sample();
	llm.uncertain_low = 0.7;
	llm.uncertain_high = 0.3;
	let error = llm.validate().expect_err("inverted band must fail");
	assert!(format!("{error}").contains("uncertain_low"), "{error}");
}

#[test]
fn validate_rejects_zero_timeout() {
	let mut llm = sample();
	llm.timeout_secs = 0;
	let error = llm.validate().expect_err("zero timeout must fail");
	assert!(format!("{error}").contains("timeout_secs"), "{error}");
}

#[test]
fn validate_rejects_out_of_range_score() {
	let mut llm = sample();
	llm.uncertain_low = 1.5;
	let error = llm.validate().expect_err("out-of-range low must fail");
	assert!(format!("{error}").contains("uncertain_low"), "{error}");

	let mut llm = sample();
	llm.uncertain_high = -0.1;
	let error = llm.validate().expect_err("out-of-range high must fail");
	assert!(format!("{error}").contains("uncertain_high"), "{error}");
}

#[test]
fn validate_rejects_zero_body() {
	let mut llm = sample();
	llm.max_body_bytes = 0;
	let error = llm.validate().expect_err("zero body must fail");
	assert!(format!("{error}").contains("max_body_bytes"), "{error}");
}

#[test]
fn validate_rejects_empty_strings() {
	let mut llm = sample();
	llm.endpoint = "".into();
	let error = llm.validate().expect_err("empty endpoint must fail");
	assert!(format!("{error}").contains("endpoint"), "{error}");

	let mut llm = sample();
	llm.api_key_env = "   ".into();
	let error = llm.validate().expect_err("blank env name must fail");
	assert!(format!("{error}").contains("api_key_env"), "{error}");

	let mut llm = sample();
	llm.model = "".into();
	let error = llm.validate().expect_err("empty model must fail");
	assert!(format!("{error}").contains("model"), "{error}");
}

#[test]
fn validation_errors_name_the_top_level_section() {
	// The section is `[antispam_llm]`, not a sub-table of `[antispam]`: an
	// operator searching the file for the name in the message must find it.
	let breakers: [fn(&mut Llm); 8] = [
		|llm| llm.uncertain_low = 1.5,
		|llm| llm.uncertain_high = -0.1,
		|llm| {
			llm.uncertain_low = 0.7;
			llm.uncertain_high = 0.3;
		},
		|llm| llm.timeout_secs = 0,
		|llm| llm.max_body_bytes = 0,
		|llm| llm.endpoint = String::new(),
		|llm| llm.api_key_env = String::new(),
		|llm| llm.model = String::new(),
	];
	for breaker in breakers {
		let mut llm = sample();
		breaker(&mut llm);
		let error = llm.validate().expect_err("the broken setting must fail");
		assert!(
			format!("{error}").contains("[antispam_llm] "),
			"wrong section in: {error}"
		);
		assert!(!format!("{error}").contains("[antispam.llm]"), "{error}");
	}
}

#[test]
fn debug_redacts_nothing_but_omits_key_value() {
	// The API key is read from the environment, not stored on the struct;
	// the only secret-ish field visible in Debug is `api_key_env` (the
	// variable *name*), and that is exactly what the operator configured.
	let llm = sample();
	let rendered = format!("{llm:?}");
	assert!(rendered.contains("EPISTLE_LLM_API_KEY"));
	assert!(!rendered.contains("sk-"), "{rendered}");
}
