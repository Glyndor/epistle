//! `mail` with the certificates container: the ACME pair appears on disk
//! some time after the start, and each refusal is reported once.

use super::*;

fn self_signed() -> (String, String) {
	let certified =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	(certified.cert.pem(), certified.signing_key.serialize_pem())
}

/// The process starts on the bootstrap pair while nothing is at the ACME
/// path yet, then the container writes its pair there.
#[test]
fn a_pair_written_after_the_start_is_put_in_service() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (bootstrap_cert, bootstrap_key) = self_signed();
	let acceptor =
		crate::tls::acceptor_from_pem(bootstrap_cert.as_bytes(), bootstrap_key.as_bytes())
			.expect("bootstrap acceptor");
	let acme = Tls {
		cert_file: dir.path().join("acme").join("cert.pem"),
		key_file: dir.path().join("acme").join("key.pem"),
		client_ca: None,
	};
	let mut watcher = CertWatcher::new(acme.clone(), ReloadableAcceptor::new(acceptor));
	let mut reported = None;

	let missing = followed(watcher.poll(), &mut reported);
	assert!(
		matches!(&missing, Some(Followed::Refused(reason)) if reason.contains("cannot read")),
		"{missing:?}"
	);
	assert_eq!(
		followed(watcher.poll(), &mut reported),
		None,
		"the same missing files are not reported on every look"
	);

	let (cert, key) = self_signed();
	std::fs::create_dir_all(dir.path().join("acme")).expect("acme directory");
	std::fs::write(&acme.cert_file, &cert).expect("certificate");
	std::fs::write(&acme.key_file, &key).expect("key");

	assert_eq!(
		followed(watcher.poll(), &mut reported),
		Some(Followed::Reloaded)
	);
	assert_eq!(watcher.served_chain(), Some(cert.as_str()));
	assert_eq!(reported, None);
}

/// A key written by a second rename lags its certificate by one look: the
/// half-written pair is refused once and the whole one replaces it.
#[test]
fn a_half_written_pair_is_refused_once_and_the_whole_one_follows() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (first_cert, first_key) = self_signed();
	let acme = Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	std::fs::write(&acme.cert_file, &first_cert).expect("certificate");
	std::fs::write(&acme.key_file, &first_key).expect("key");
	let acceptor = crate::tls::acceptor(&acme).expect("acceptor");
	let mut watcher = CertWatcher::new(acme.clone(), ReloadableAcceptor::new(acceptor));
	let mut reported = None;

	let (next_cert, next_key) = self_signed();
	std::fs::write(&acme.cert_file, &next_cert).expect("new certificate first");
	let refused = followed(watcher.poll(), &mut reported);
	assert!(matches!(refused, Some(Followed::Refused(_))), "{refused:?}");
	assert_eq!(watcher.served_chain(), Some(first_cert.as_str()));

	std::fs::write(&acme.key_file, &next_key).expect("then its key");
	assert_eq!(
		followed(watcher.poll(), &mut reported),
		Some(Followed::Reloaded)
	);
	assert_eq!(watcher.served_chain(), Some(next_cert.as_str()));
}

#[test]
fn a_different_refusal_is_reported_again() {
	let mut reported = Some("cannot read the certificate files: gone".to_string());
	assert_eq!(
		followed(
			Polled::Refused("invalid TLS material: x".into()),
			&mut reported
		),
		Some(Followed::Refused("invalid TLS material: x".into()))
	);
	assert_eq!(followed(Polled::Unchanged, &mut reported), None);
}
