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

/// The certificates container does not mount the database password; its
/// configuration loads without `[database]`, and the listeners' does not.
#[test]
fn the_certificates_role_loads_without_the_database_password_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
			 [database]\nurl = 'postgres://epistle@%2Frun%2Fpostgresql/epistle'\npassword_file = '{}'\n",
			dir.path().join("data").display(),
			dir.path().join("not-mounted-here").display(),
		),
	)
	.expect("config");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
	let config = super::super::load(&path, ServeRole::Certs).expect("certs loads");
	assert!(config.database.is_none());
	let error = super::super::load(&path, ServeRole::Mail).expect_err("mail needs it");
	assert!(error.to_string().contains("password_file"), "{error}");
}

/// The certificates container holds the DNS credential and the ACME account
/// key, and nothing else it does not use. The tables only the mail
/// container reads — the account password hashes, the API token hash, the
/// OAuth configuration, the storage key and the DKIM key paths — are not
/// read by the certificates role: the container mounts none of the files
/// they name, and its configuration loads without them.
#[test]
fn the_certificates_role_loads_without_the_tables_only_mail_reads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	let hash = crate::smtp::auth::hash_password("a-password").expect("hash");
	let token = "0".repeat(64);
	let data_dir = dir.path().join("data").display().to_string();
	let storage_key = dir.path().join("storage.key").display().to_string();
	let dkim_key = dir.path().join("dkim.pem").display().to_string();
	std::fs::write(
		&path,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = '{data_dir}'\ndomains = ['example.org']\n\
			 [[accounts]]\nname = 'alice'\naddresses = ['alice@example.org']\npassword_hash = '{hash}'\n\
			 [api]\ntoken_hash = 'sha256:{token}'\n\
			 [storage]\nencrypt_at_rest = true\nencryption_key_file = '{storage_key}'\n\
			 [oauth]\nissuer = 'https://idp.example.org'\naudience = 'mail.example.org'\n\
			 algorithm = 'RS256'\ndiscovery_url = 'https://idp.example.org/.well-known/openid-configuration'\n\
			 [dkim]\nselector = 'mail'\nkey_file = '{dkim_key}'\n"
		),
	)
	.expect("config");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
	let config = super::super::load(&path, ServeRole::Certs).expect("certs loads");
	assert!(config.accounts.is_empty(), "the accounts stay with mail");
	assert!(config.api.is_none(), "the API token hash stays with mail");
	assert!(config.storage.is_none(), "the storage key stays with mail");
	assert!(
		config.oauth.is_none(),
		"the OAuth configuration stays with mail"
	);
	assert!(config.dkim.is_none(), "the DKIM key paths stay with mail");
	// The same file read by the role that does use them.
	let mail = super::super::load(&path, ServeRole::Mail).expect("mail loads");
	assert_eq!(mail.accounts.len(), 1, "mail reads the accounts");
	assert!(mail.api.is_some(), "mail reads the API token hash");
	assert!(mail.storage.is_some(), "mail reads the storage key");
	assert!(mail.oauth.is_some(), "mail reads the OAuth configuration");
	assert!(mail.dkim.is_some(), "mail reads the DKIM key paths");
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
