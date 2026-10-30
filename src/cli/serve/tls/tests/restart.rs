use super::*;
use std::sync::Arc;
use tokio_rustls::{
	TlsConnector,
	rustls::{ClientConfig, RootCertStore},
};

#[tokio::test]
async fn restart_presents_persisted_acme_certificate() {
	crate::tls::ensure_crypto_provider();
	let dir = tempfile::tempdir().expect("directory");
	let original =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("bootstrap");
	let renewed =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("renewed");
	let mut config: Config =
		toml::from_str("hostname = 'mail.example.org'\ndata_dir = '.'").expect("config");
	config.data_dir = dir.path().to_path_buf();
	config.tls = Some(crate::config::Tls {
		cert_file: dir.path().join("bootstrap.pem"),
		key_file: dir.path().join("bootstrap.key"),
		client_ca: None,
	});
	let tls = config.tls.as_ref().unwrap();
	std::fs::write(&tls.cert_file, original.cert.pem()).expect("bootstrap cert");
	std::fs::write(&tls.key_file, original.signing_key.serialize_pem()).expect("bootstrap key");
	config.acme = Some(toml::from_str("directory_url = 'https://acme.invalid/directory'\ncontacts = ['admin@example.org']\ndomains = ['mail.example.org']").expect("ACME"));
	std::fs::create_dir(dir.path().join("acme")).expect("acme directory");
	std::fs::write(dir.path().join("acme/cert.pem"), renewed.cert.pem()).expect("renewed cert");
	std::fs::write(
		dir.path().join("acme/key.pem"),
		renewed.signing_key.serialize_pem(),
	)
	.expect("renewed key");
	let mut roots = RootCertStore::empty();
	roots
		.add(original.cert.der().clone())
		.expect("bootstrap trust");
	roots
		.add(renewed.cert.der().clone())
		.expect("renewed trust");
	let connector = TlsConnector::from(Arc::new(
		ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth(),
	));
	for _ in 0..2 {
		let stack = build_tls(&config, ChallengeStore::new()).expect("restart");
		let acceptor = stack.tls_acceptor.expect("acceptor");
		let (client, server) = tokio::io::duplex(65536);
		let task = tokio::spawn(async move { acceptor.accept(server).await });
		let connection = connector
			.connect("mail.example.org".try_into().unwrap(), client)
			.await
			.expect("handshake");
		assert!(
			connection.get_ref().1.peer_certificates().unwrap()[0] == *renewed.cert.der(),
			"restart must present the persisted ACME certificate"
		);
		task.abort();
	}
}
