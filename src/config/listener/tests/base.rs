use super::*;

#[test]
fn default_ports_match_iana() {
	assert_eq!(ListenerKind::Smtp.default_port(), 25);
	assert_eq!(ListenerKind::Submission.default_port(), 587);
	assert_eq!(ListenerKind::Submissions.default_port(), 465);
	assert_eq!(ListenerKind::Imaps.default_port(), 993);
	assert_eq!(ListenerKind::Pop3s.default_port(), 995);
}

#[test]
fn listener_defaults_to_loopback_and_service_port() {
	let listener: Listener = toml::from_str(r#"kind = "smtp""#).expect("parse listener");
	let addr = listener.socket_addr();
	assert!(addr.ip().is_loopback());
	assert_eq!(addr.port(), 25);
}

#[test]
fn listener_accepts_explicit_addr_and_port() {
	let listener: Listener = toml::from_str(
		r#"
kind = "submissions"
addr = "0.0.0.0"
port = 2465
"#,
	)
	.expect("parse listener");
	let addr = listener.socket_addr();
	assert!(!addr.ip().is_loopback());
	assert_eq!(addr.port(), 2465);
}

#[test]
fn autoconfigs_listener_defaults_to_https_port() {
	let parsed: Result<Listener, _> = toml::from_str(r#"kind = "autoconfigs""#);
	assert!(parsed.is_ok(), "{:?}", parsed.as_ref().err());
	let listener = parsed.expect("checked above");
	assert_eq!(listener.socket_addr().port(), 443);
	assert_eq!(listener.kind.as_str(), "autoconfigs");
}

#[test]
fn listener_rejects_unknown_keys() {
	let result: Result<Listener, _> = toml::from_str(
		r#"
kind = "smtp"
oops = 1
"#,
	);
	assert!(result.is_err());
}
