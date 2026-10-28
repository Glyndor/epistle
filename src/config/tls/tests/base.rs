use super::*;

#[test]
fn parses_tls_section() {
	let tls: Tls = toml::from_str(
		r#"
cert_file = "/etc/mail/cert.pem"
key_file = "/etc/mail/key.pem"
"#,
	)
	.expect("parse tls");
	assert_eq!(tls.cert_file, PathBuf::from("/etc/mail/cert.pem"));
	assert_eq!(tls.key_file, PathBuf::from("/etc/mail/key.pem"));
	assert_eq!(tls.client_ca, None);
}

#[test]
fn parses_client_ca() {
	let tls: Tls = toml::from_str(
		r#"
cert_file = "/c.pem"
key_file = "/k.pem"
client_ca = "/etc/mail/client-ca.pem"
"#,
	)
	.expect("parse tls");
	assert_eq!(
		tls.client_ca,
		Some(PathBuf::from("/etc/mail/client-ca.pem"))
	);
}

#[test]
fn rejects_missing_key_file() {
	let result: Result<Tls, _> = toml::from_str(r#"cert_file = "/etc/mail/cert.pem""#);
	assert!(result.is_err());
}

#[test]
fn rejects_unknown_keys() {
	let result: Result<Tls, _> = toml::from_str(
		r#"
cert_file = "/a.pem"
key_file = "/b.pem"
ciphers = "all"
"#,
	);
	assert!(result.is_err());
}
