//! An operator's own certificate replaced on disk: every listener clone
//! presents the new pair after one look at the files, and a half-written,
//! mismatched or unparsable pair is refused while the old one stays.

use super::*;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct Pair {
	cert: String,
	key: String,
	der: CertificateDer<'static>,
}

fn pair() -> Pair {
	let certified =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	Pair {
		cert: certified.cert.pem(),
		key: certified.signing_key.serialize_pem(),
		der: certified.cert.der().clone(),
	}
}

struct Lab {
	_dir: tempfile::TempDir,
	tls: Tls,
	/// What a listener cloned at start and keeps for its whole life.
	listener: tokio_rustls::TlsAcceptor,
	watcher: CertWatcher,
	end_point: EndPoint,
	roots: RootCertStore,
}

impl Lab {
	/// Serve `first` from files, as `serve` does with a static `[tls]`.
	fn new(first: &Pair) -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let tls = Tls {
			cert_file: dir.path().join("fullchain.pem"),
			key_file: dir.path().join("privkey.pem"),
			client_ca: None,
		};
		std::fs::write(&tls.cert_file, &first.cert).expect("certificate");
		std::fs::write(&tls.key_file, &first.key).expect("key");
		let reloadable =
			ReloadableAcceptor::new(super::super::super::acceptor(&tls).expect("acceptor"));
		let end_point = EndPoint::new(end_point_of(first.der.as_ref()));
		let watcher =
			CertWatcher::new(tls.clone(), reloadable.clone()).with_end_point(end_point.clone());
		let mut roots = RootCertStore::empty();
		roots.add(first.der.clone()).expect("trust");
		Lab {
			_dir: dir,
			tls,
			listener: reloadable.current(),
			watcher,
			end_point,
			roots,
		}
	}

	fn trust(&mut self, pair: &Pair) {
		self.roots.add(pair.der.clone()).expect("trust");
	}

	/// Replace a file the way certbot and most tools do: write beside it,
	/// then rename over it.
	fn replace(&self, cert: &str, key: &str) {
		for (path, pem) in [(&self.tls.cert_file, cert), (&self.tls.key_file, key)] {
			let staged = path.with_extension("new");
			std::fs::write(&staged, pem).expect("staged PEM");
			std::fs::rename(&staged, path).expect("rename");
		}
	}

	/// The certificate a client sees from the listener's clone.
	async fn served(&self) -> CertificateDer<'static> {
		let client = ClientConfig::builder()
			.with_root_certificates(self.roots.clone())
			.with_no_client_auth();
		let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
		let (client_io, server_io) = tokio::io::duplex(16384);
		let (accepted, connected) = tokio::join!(
			self.listener.accept(server_io),
			connector.connect("mail.example.org".try_into().expect("name"), client_io)
		);
		assert!(accepted.is_ok(), "server handshake");
		let connection = connected.unwrap_or_else(|_| panic!("client handshake"));
		connection.get_ref().1.peer_certificates().expect("chain")[0].clone()
	}
}

fn refused(polled: &Polled) -> bool {
	matches!(polled, Polled::Refused(_))
}

#[tokio::test]
async fn a_replaced_pair_is_served_without_a_restart() {
	let (first, second) = (pair(), pair());
	let mut lab = Lab::new(&first);
	lab.trust(&second);
	assert_eq!(lab.watcher.poll(), Polled::Unchanged, "nothing changed yet");
	assert!(lab.served().await == first.der, "the first pair is served");

	lab.replace(&second.cert, &second.key);
	assert!(
		lab.watcher.poll()
			== Polled::Reloaded {
				chain_pem: second.cert.clone()
			},
		"the new pair is reloaded with its chain"
	);
	assert!(
		lab.served().await == second.der,
		"a listener's clone taken at start presents the new certificate"
	);
	assert!(
		lab.end_point.current() == end_point_of(second.der.as_ref()),
		"SCRAM-PLUS binds to the certificate now presented"
	);
	assert_eq!(lab.watcher.poll(), Polled::Unchanged, "reloaded once");
}

#[tokio::test]
async fn a_half_written_certificate_is_refused_until_it_is_complete() {
	let (first, second) = (pair(), pair());
	let mut lab = Lab::new(&first);
	lab.trust(&second);
	let half = &second.cert[..second.cert.len() / 2];
	std::fs::write(&lab.tls.key_file, &second.key).expect("key");
	std::fs::write(&lab.tls.cert_file, half).expect("half a certificate");
	assert!(
		refused(&lab.watcher.poll()),
		"half a certificate is refused"
	);
	assert!(lab.served().await == first.der, "the old pair stays");
	assert_eq!(
		lab.watcher.poll(),
		Polled::Unchanged,
		"a refused pair is reported once, not every minute"
	);
	std::fs::write(&lab.tls.cert_file, &second.cert).expect("whole certificate");
	assert!(matches!(lab.watcher.poll(), Polled::Reloaded { .. }));
	assert!(
		lab.served().await == second.der,
		"the completed pair is served"
	);
}

#[tokio::test]
async fn a_certificate_with_another_key_is_refused() {
	let (first, second, third) = (pair(), pair(), pair());
	let mut lab = Lab::new(&first);
	lab.trust(&second);
	lab.replace(&second.cert, &third.key);
	assert!(refused(&lab.watcher.poll()), "a mismatched pair is refused");
	assert!(lab.served().await == first.der, "the old pair stays");
	assert!(
		lab.end_point.current() == end_point_of(first.der.as_ref()),
		"the binding stays with the certificate in service"
	);
	lab.replace(&second.cert, &second.key);
	assert!(matches!(lab.watcher.poll(), Polled::Reloaded { .. }));
	assert!(lab.served().await == second.der);
}

#[tokio::test]
async fn a_chain_with_a_certificate_that_does_not_parse_is_refused() {
	use base64::Engine;
	let (first, second) = (pair(), pair());
	let mut lab = Lab::new(&first);
	lab.trust(&second);
	let garbage = base64::engine::general_purpose::STANDARD.encode([0x30, 0x03, 0x02, 0x01]);
	let chain = format!(
		"{}-----BEGIN CERTIFICATE-----\n{garbage}\n-----END CERTIFICATE-----\n",
		second.cert
	);
	lab.replace(&chain, &second.key);
	assert!(
		refused(&lab.watcher.poll()),
		"an intermediate that is not a certificate is refused"
	);
	assert!(lab.served().await == first.der, "the old pair stays");
}

#[tokio::test]
async fn missing_files_keep_the_old_pair() {
	let first = pair();
	let mut lab = Lab::new(&first);
	std::fs::remove_file(&lab.tls.cert_file).expect("remove");
	assert!(refused(&lab.watcher.poll()), "a missing file is refused");
	assert!(lab.served().await == first.der, "the old pair stays");
}
