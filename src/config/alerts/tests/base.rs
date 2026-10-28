	use super::*;

	#[test]
	fn parses_minimal_rule() {
		let alert: Alert = toml::from_str(
			r#"
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
cooldown_secs = 900
"#,
		)
		.expect("parse alert");
		assert_eq!(alert.name, "bounce-storm");
		assert_eq!(alert.metric, "bounced");
		assert_eq!(alert.op, AlertOp::Ge);
		assert_eq!(alert.threshold, 50);
		assert_eq!(alert.window_secs, 300);
		assert_eq!(alert.cooldown_secs, 900);
		assert!(!alert.webhook);
		assert!(alert.email.is_empty());
		assert!(alert.enabled, "a rule is on unless it says otherwise");
	}

	#[test]
	fn a_rule_can_be_switched_off() {
		let alert: Alert = toml::from_str(
			r#"
name = "x"
metric = "bounced"
op = ">="
threshold = 1
window_secs = 60
cooldown_secs = 60
webhook = true
enabled = false
"#,
		)
		.expect("parse alert");
		assert!(!alert.enabled);
		assert!(alert.validate().is_ok(), "a disabled rule is still checked");
	}

	#[test]
	fn parses_all_operators() {
		#[derive(Deserialize)]
		struct Wrap {
			op: AlertOp,
		}
		for (text, want) in [
			(r#"op = ">=""#, AlertOp::Ge),
			(r#"op = ">""#, AlertOp::Gt),
			(r#"op = "<=""#, AlertOp::Le),
			(r#"op = "<""#, AlertOp::Lt),
			(r#"op = "==""#, AlertOp::Eq),
		] {
			let parsed: Wrap = toml::from_str(text).expect("parse op");
			assert_eq!(parsed.op, want, "{text}");
		}
	}

	#[test]
	fn unknown_metric_lists_valid_names() {
		let alert = Alert {
			name: "broken".into(),
			metric: "not_a_counter".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			enabled: true,
			webhook: true,
			email: Vec::new(),
		};
		let error = alert.validate().expect_err("unknown metric rejected");
		assert!(error.contains("not_a_counter"), "{error}");
		assert!(error.contains("bounced"), "{error}");
	}

	#[test]
	fn zero_window_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 0,
			cooldown_secs: 60,
			enabled: true,
			webhook: true,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn zero_cooldown_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 0,
			enabled: true,
			webhook: true,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn silent_alert_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			enabled: true,
			webhook: false,
			email: Vec::new(),
		};
		assert!(alert.validate().is_err());
	}

	#[test]
	fn malformed_email_is_rejected() {
		let alert = Alert {
			name: "broken".into(),
			metric: "bounced".into(),
			op: AlertOp::Ge,
			threshold: 1,
			window_secs: 60,
			cooldown_secs: 60,
			enabled: true,
			webhook: false,
			email: vec!["no-at-sign".into()],
		};
		assert!(alert.validate().is_err());

		let crlf = Alert {
			email: vec!["a@b\r\nCc: x".into()],
			..alert.clone()
		};
		assert!(crlf.validate().is_err());
	}

	#[test]
	fn unknown_keys_are_rejected() {
		let parsed: Result<Alert, _> = toml::from_str(
			r#"
name = "x"
metric = "bounced"
op = ">="
threshold = 1
window_secs = 60
cooldown_secs = 60
webhook = true
surprise = 1
"#,
		);
		assert!(parsed.is_err());
	}
