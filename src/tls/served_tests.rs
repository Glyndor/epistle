use super::*;

fn config(dir: &std::path::Path, acme: bool) -> Config {
	let mut config: Config =
		toml::from_str("hostname = 'mail.example.org'\ndata_dir = '.'").expect("config");
	config.data_dir = dir.to_path_buf();
	config.tls = Some(Tls {
		cert_file: dir.join("bootstrap.pem"),
		key_file: dir.join("bootstrap.key"),
		client_ca: Some(dir.join("ca.pem")),
	});
	if acme {
		config.acme = Some(
			toml::from_str(
				"directory_url = 'https://acme.invalid/directory'\ndomains = ['mail.example.org']",
			)
			.expect("acme"),
		);
	}
	config
}

fn write_acme_pair(dir: &std::path::Path) {
	let pair = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("pair");
	std::fs::create_dir_all(dir.join("acme")).expect("acme dir");
	std::fs::write(dir.join("acme/cert.pem"), pair.cert.pem()).expect("cert");
	std::fs::write(dir.join("acme/key.pem"), pair.signing_key.serialize_pem()).expect("key");
}

#[test]
fn without_acme_the_static_pair_wins_even_if_an_acme_pair_exists() {
	let dir = tempfile::tempdir().expect("dir");
	write_acme_pair(dir.path());
	let served = served_tls(&config(dir.path(), false)).expect("served");
	assert_eq!(served.source, CertSource::Static);
	assert_eq!(served.tls.cert_file, dir.path().join("bootstrap.pem"));
}

#[test]
fn acme_pair_wins_and_keeps_the_client_ca() {
	let dir = tempfile::tempdir().expect("dir");
	write_acme_pair(dir.path());
	let served = served_tls(&config(dir.path(), true)).expect("served");
	assert_eq!(served.source, CertSource::Acme);
	assert_eq!(served.tls.cert_file, dir.path().join("acme/cert.pem"));
	assert_eq!(served.tls.key_file, dir.path().join("acme/key.pem"));
	assert_eq!(served.tls.client_ca, Some(dir.path().join("ca.pem")));
}

#[test]
fn missing_or_broken_acme_pair_falls_back_to_static() {
	let dir = tempfile::tempdir().expect("dir");
	let absent = served_tls(&config(dir.path(), true)).expect("served");
	assert_eq!(absent.source, CertSource::Static);
	write_acme_pair(dir.path());
	std::fs::write(dir.path().join("acme/key.pem"), "garbage").expect("break key");
	let broken = served_tls(&config(dir.path(), true)).expect("served");
	assert_eq!(broken.source, CertSource::Static);
}

#[test]
fn mismatched_acme_key_falls_back_to_static() {
	let dir = tempfile::tempdir().expect("dir");
	write_acme_pair(dir.path());
	let other = rcgen::generate_simple_self_signed(vec!["x.example.org".into()]).expect("other");
	std::fs::write(
		dir.path().join("acme/key.pem"),
		other.signing_key.serialize_pem(),
	)
	.expect("key");
	let served = served_tls(&config(dir.path(), true)).expect("served");
	assert_eq!(served.source, CertSource::Static);
}

#[test]
fn no_sections_and_no_pair_resolves_to_none() {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config(dir.path(), false);
	config.tls = None;
	assert!(served_tls(&config).is_none());
}
