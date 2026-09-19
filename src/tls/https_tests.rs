use super::*;
use tokio_rustls::rustls::{ClientConfig, ProtocolVersion, RootCertStore};

#[tokio::test]
async fn https_pins_tls12_minimum_and_accepts_both_supported_versions() {
	assert_eq!(
		VERSIONS
			.iter()
			.map(|version| version.version)
			.collect::<Vec<_>>(),
		[ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
	);
	let dir = tempfile::tempdir().expect("tempdir");
	let certified = rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()])
		.expect("certificate");
	let config = Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	fs::write(&config.cert_file, certified.cert.pem()).expect("certificate file");
	fs::write(&config.key_file, certified.signing_key.serialize_pem()).expect("key file");
	let server = acceptor(&config).expect("acceptor");
	let mut roots = RootCertStore::empty();
	roots.add(certified.cert.der().clone()).expect("trust");
	for version in [&version::TLS12, &version::TLS13] {
		let client = ClientConfig::builder_with_protocol_versions(&[version])
			.with_root_certificates(roots.clone())
			.with_no_client_auth();
		let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
		let (client_io, server_io) = tokio::io::duplex(16384);
		let (accepted, connected) = tokio::join!(
			server.accept(server_io),
			connector.connect("mta-sts.example.org".try_into().expect("name"), client_io)
		);
		assert_eq!(
			accepted
				.expect("server handshake")
				.get_ref()
				.1
				.protocol_version(),
			Some(version.version)
		);
		assert_eq!(
			connected
				.expect("client handshake")
				.get_ref()
				.1
				.protocol_version(),
			Some(version.version)
		);
	}
}

#[tokio::test]
async fn changed_certificate_reloads_and_invalid_replacement_retains_last_valid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let initial = rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()])
		.expect("initial certificate");
	let replacement = rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()])
		.expect("replacement certificate");
	let config = Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	fs::write(&config.cert_file, initial.cert.pem()).expect("certificate");
	fs::write(&config.key_file, initial.signing_key.serialize_pem()).expect("private PEM");
	let mut reload = FileAcceptor::new(config.clone()).expect("file acceptor");
	let mut roots = RootCertStore::empty();
	roots
		.add(initial.cert.der().clone())
		.expect("initial trust");
	roots
		.add(replacement.cert.der().clone())
		.expect("replacement trust");
	let client = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
	for stage in 0..3 {
		if stage == 1 {
			for (path, pem) in [
				(&config.cert_file, replacement.cert.pem()),
				(&config.key_file, replacement.signing_key.serialize_pem()),
			] {
				let temporary = path.with_extension("new");
				fs::write(&temporary, pem).expect("replacement PEM");
				fs::rename(temporary, path).expect("atomic replacement");
			}
		} else if stage == 2 {
			fs::write(&config.cert_file, "incomplete PEM").expect("invalid certificate");
		}
		let (client_io, server_io) = tokio::io::duplex(16384);
		let server = reload.current();
		let (accepted, connected) = tokio::join!(
			server.accept(server_io),
			connector.connect("mta-sts.example.org".try_into().expect("name"), client_io)
		);
		assert!(accepted.is_ok(), "server handshake stage {stage}");
		let connection = connected.expect("client handshake");
		let expected = if stage == 0 {
			initial.cert.der()
		} else {
			replacement.cert.der()
		};
		assert_eq!(
			&connection
				.get_ref()
				.1
				.peer_certificates()
				.expect("peer chain")[0],
			expected,
			"certificate at stage {stage}"
		);
	}
}
