//! A split stack: `mail` starts without the DNS credential and the ACME
//! account key the certificates container holds, and the certificates role
//! starts only with what it renews with.

use super::*;
use std::path::Path;
use std::time::Duration;

/// `[acme]` with dns-01 through a `[dns]` entry whose token file was never
/// written, as `mail` sees it once the token is mounted only in `certs`, plus
/// a bootstrap `[tls]` pair and one metrics listener on `port`.
fn split_config(dir: &Path, port: u16) -> Config {
	let mut config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\nchallenge = 'dns-01'\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{}'\n\
		 [[listeners]]\nkind = 'metrics'\naddr = '127.0.0.1'\nport = {port}\n",
		dir.join("data").display(),
		dir.join("not-mounted-here").display(),
	))
	.expect("config");
	let cert = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("cert");
	let tls = crate::config::Tls {
		cert_file: dir.join("cert.pem"),
		key_file: dir.join("key.pem"),
		client_ca: None,
	};
	std::fs::write(&tls.cert_file, cert.cert.pem()).expect("cert file");
	std::fs::write(&tls.key_file, cert.signing_key.serialize_pem()).expect("key file");
	config.tls = Some(tls);
	config
}

/// The control: one process that renews needs the credential, and its
/// absence stops the start.
#[tokio::test]
async fn the_whole_server_refuses_to_start_without_the_dns_credential() {
	let dir = tempfile::tempdir().expect("tempdir");
	let port = crate::test_fixtures::free_port();
	let error = super::super::serve(split_config(dir.path(), port), ServeRole::All)
		.await
		.expect_err("no credential to answer dns-01 with");
	assert!(error.to_string().contains("could not be built"), "{error}");
}

#[tokio::test]
async fn the_mail_role_serves_without_the_dns_credential() {
	let dir = tempfile::tempdir().expect("tempdir");
	let port = crate::test_fixtures::free_port();
	let server = tokio::spawn(super::super::serve(
		split_config(dir.path(), port),
		ServeRole::Mail,
	));
	let mut connected = false;
	for _ in 0..200 {
		if tokio::net::TcpStream::connect(("127.0.0.1", port))
			.await
			.is_ok()
		{
			connected = true;
			break;
		}
		if server.is_finished() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(40)).await;
	}
	assert!(!server.is_finished(), "{:?}", server.await);
	assert!(connected, "the listener came up");
	server.abort();
}

#[tokio::test]
async fn the_certificates_role_refuses_to_start_without_the_dns_credential() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = split_config(dir.path(), crate::test_fixtures::free_port());
	let error = super::super::certs::serve(config)
		.await
		.expect_err("no credential to answer dns-01 with");
	assert!(error.to_string().contains("could not be built"), "{error}");
}

#[tokio::test]
async fn the_certificates_role_refuses_to_start_without_acme() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut config = split_config(dir.path(), crate::test_fixtures::free_port());
	config.acme = None;
	let error = super::super::certs::serve(config)
		.await
		.expect_err("nothing to renew");
	assert!(error.to_string().contains("has no [acme]"), "{error}");
}
