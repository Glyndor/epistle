//! The transport policy matrix: every combination of MTA-STS mode, TLSA
//! RRset, the DNSSEC state of the MX answer and what the MX offers,
//! driven through the worker against a real SMTP server, with the outcome
//! RFC 8461 and RFC 7672 call for.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::*;
use crate::config::OutboundTls;
use crate::dane::rrset::TlsaRrset;
use crate::dane::tlsa::TlsaRecord;
use crate::queue::resolver::{BoxedStream, ConnectFuture};
use crate::smtp::directory::Directory;
use crate::smtp::server::{Server, TlsMode};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::spf::{DnsFailure, DnsLookup};

const MX: &str = "mx.remote.example";

/// The MTA-STS policy the recipient domain publishes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Sts {
	None,
	Testing,
	Enforce,
}

/// The TLSA lookup for the MX.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Tlsa {
	Absent,
	Usable,
	Unusable,
	TempFail,
}

/// What the MX offers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Mx {
	/// STARTTLS with a certificate that passes PKIX and matches the TLSA.
	Good,
	/// STARTTLS with a self-signed certificate the TLSA RRset names.
	DaneOnly,
	/// STARTTLS with a self-signed certificate nothing vouches for.
	Bad,
	/// No STARTTLS.
	Plain,
}

/// The DNSSEC state of the MX answer that named the host, or for a
/// domain without MX (implicit MX) of the denial and the address answer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum MxDns {
	Secure,
	Insecure,
	Bogus,
	ImplicitSecure,
	ImplicitInsecure,
	ImplicitBogusDenial,
	ImplicitBogusAddress,
}

/// How one delivery attempt ended.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Seen {
	DeliveredTls,
	DeliveredPlain,
	Deferred,
	Dropped,
}

struct Certs {
	ca: CertificateDer<'static>,
	good: (CertificateDer<'static>, Vec<u8>),
	dane_only: (CertificateDer<'static>, Vec<u8>),
	bad: (CertificateDer<'static>, Vec<u8>),
}

fn certs() -> &'static Certs {
	static CERTS: OnceLock<Certs> = OnceLock::new();
	CERTS.get_or_init(|| {
		let ca_key = rcgen::KeyPair::generate().expect("ca key");
		let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca");
		ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
		let ca = ca_params.self_signed(&ca_key).expect("ca cert");
		let issuer = rcgen::Issuer::new(ca_params, ca_key);
		let leaf = |signed: bool| {
			let key = rcgen::KeyPair::generate().expect("leaf key");
			let params = rcgen::CertificateParams::new(vec![MX.to_string()]).expect("leaf");
			let cert = if signed {
				params.signed_by(&key, &issuer).expect("signed leaf")
			} else {
				params.self_signed(&key).expect("self-signed leaf")
			};
			(cert.der().clone(), key.serialize_der())
		};
		Certs {
			ca: ca.der().clone(),
			good: leaf(true),
			dane_only: leaf(false),
			bad: leaf(false),
		}
	})
}

/// DANE-EE SPKI SHA-256 record for a leaf.
fn tlsa_for(leaf: &CertificateDer<'_>) -> TlsaRecord {
	let spki = crate::dane::verify::spki_of(leaf).expect("spki");
	let hash = ring::digest::digest(&ring::digest::SHA256, &spki);
	TlsaRecord::from_parts(3, 1, 1, hash.as_ref().to_vec()).expect("record")
}

fn acceptor(leaf: &(CertificateDer<'static>, Vec<u8>)) -> TlsAcceptor {
	crate::tls::ensure_crypto_provider();
	let key = PrivateKeyDer::try_from(leaf.1.clone()).expect("key");
	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![leaf.0.clone()], key)
		.expect("server config");
	TlsAcceptor::from(Arc::new(config))
}

/// Hands out a pipe to an in-process SMTP server shaped by `mx`.
struct MxConnector {
	sink: Arc<MemorySink>,
	mx: Mx,
	mx_dns: MxDns,
}

impl Connector for MxConnector {
	fn connect(&self, _domain: &str, _policy: Option<&crate::mtasts::Policy>) -> ConnectFuture<'_> {
		Box::pin(async move {
			// What the real connector does with each answer.
			use hickory_resolver::proto::dnssec::Proof;
			let implicit = |denial, address| {
				crate::queue::resolver::implicit_mx_security(denial, address).map_err(|_| {
					DeliveryError::Transient("implicit MX failed DNSSEC validation".into())
				})
			};
			let security = match self.mx_dns {
				MxDns::Secure => crate::queue::resolver::MxSecurity::Secure,
				MxDns::Insecure => crate::queue::resolver::MxSecurity::Insecure,
				MxDns::Bogus => {
					return Err(DeliveryError::Transient(
						"MX answer failed DNSSEC validation".into(),
					));
				}
				MxDns::ImplicitSecure => implicit(Proof::Secure, Proof::Secure)?,
				MxDns::ImplicitInsecure => implicit(Proof::Insecure, Proof::Secure)?,
				MxDns::ImplicitBogusDenial => implicit(Proof::Bogus, Proof::Secure)?,
				MxDns::ImplicitBogusAddress => implicit(Proof::Secure, Proof::Bogus)?,
			};
			let directory = crate::directory_store::DirectoryHandle::new(Directory::new(
				["remote.example".to_string()],
				[("bob@remote.example".to_string(), "bob".to_string())],
			));
			let mut server = Server::new(MX, self.sink.clone() as Arc<dyn MessageSink>)
				.with_directory(directory);
			let leaf = match self.mx {
				Mx::Good => Some(&certs().good),
				Mx::DaneOnly => Some(&certs().dane_only),
				Mx::Bad => Some(&certs().bad),
				Mx::Plain => None,
			};
			if let Some(leaf) = leaf {
				server = server.with_tls(
					crate::tls::ReloadableAcceptor::new(acceptor(leaf)),
					TlsMode::Opportunistic,
				);
			}
			let (client, server_stream) = tokio::io::duplex(64 * 1024);
			tokio::spawn(async move { server.handle(server_stream, None).await });
			Ok(crate::queue::resolver::Connection::new(
				Box::new(client) as BoxedStream,
				MX.to_string(),
			)
			.with_mx(security))
		})
	}
}

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// MTA-STS discovery TXT and the MX's TLSA RRset.
struct Dns {
	sts: Sts,
	tlsa: Tlsa,
}

impl DnsLookup for Dns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let records = if name == "_mta-sts.remote.example" && self.sts != Sts::None {
			vec!["v=STSv1; id=1".to_string()]
		} else {
			Vec::new()
		};
		Box::pin(async move { Ok(records) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn tlsa(&self, name: &str) -> Lookup<'_, TlsaRrset> {
		assert_eq!(name, format!("_25._tcp.{MX}"));
		let result = match self.tlsa {
			Tlsa::Absent => Ok(TlsaRrset::Absent),
			Tlsa::Usable => Ok(TlsaRrset::Usable(vec![
				tlsa_for(&certs().good.0),
				tlsa_for(&certs().dane_only.0),
			])),
			Tlsa::Unusable => Ok(TlsaRrset::Unusable),
			Tlsa::TempFail => Err(DnsFailure::Temporary),
		};
		Box::pin(async move { result })
	}
}

/// Serves the policy document for the mode under test.
struct Fetcher(Sts);

impl crate::mtasts::PolicyFetcher for Fetcher {
	fn fetch(
		&self,
		_domain: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<String, crate::mtasts::PolicyError>> + Send + '_>,
	> {
		let mode = match self.0 {
			Sts::Testing => "testing",
			_ => "enforce",
		};
		let body = format!("version: STSv1\nmode: {mode}\nmx: {MX}\nmax_age: 86400\n");
		Box::pin(async move { Ok(body) })
	}
}

/// Run one delivery attempt for the cell and report how it ended.
pub(super) async fn attempt(
	sts: Sts,
	tlsa: Tlsa,
	mx: Mx,
	mode: OutboundTls,
	mx_dns: MxDns,
) -> Seen {
	let dns: Arc<dyn DnsLookup> = Arc::new(Dns { sts, tlsa });
	attempt_with(dns, Box::new(Fetcher(sts)), mx, mode, mx_dns).await
}

/// One delivery attempt with the given DNS (MTA-STS discovery and TLSA)
/// and policy fetcher.
pub(super) async fn attempt_with(
	dns: Arc<dyn DnsLookup>,
	fetcher: Box<dyn crate::mtasts::PolicyFetcher>,
	mx: Mx,
	mode: OutboundTls,
	mx_dns: MxDns,
) -> Seen {
	let message = AcceptedMessage {
		reverse_path: "alice@sender.example".into(),
		recipients: vec!["bob@remote.example".to_string()],
		data: b"From: alice@sender.example\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	};
	attempt_message(dns, fetcher, mx, mode, mx_dns, &message).await
}

/// One delivery attempt for the cell, of `message` (to bob@remote.example).
pub(super) async fn attempt_cell(
	(sts, tlsa, mx, mode, mx_dns): (Sts, Tlsa, Mx, OutboundTls, MxDns),
	message: &AcceptedMessage,
) -> Seen {
	let dns: Arc<dyn DnsLookup> = Arc::new(Dns { sts, tlsa });
	attempt_message(dns, Box::new(Fetcher(sts)), mx, mode, mx_dns, message).await
}

/// [`attempt_with`] for a given spooled `message`.
async fn attempt_message(
	dns: Arc<dyn DnsLookup>,
	fetcher: Box<dyn crate::mtasts::PolicyFetcher>,
	mx: Mx,
	mode: OutboundTls,
	mx_dns: MxDns,
	message: &AcceptedMessage,
) -> Seen {
	crate::queue::client::TEST_ROOTS.with(|roots| *roots.borrow_mut() = vec![certs().ca.clone()]);
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool.store(message, None, &BTreeMap::new()).expect("store");
	let sink = Arc::new(MemorySink::new());
	let store = Arc::new(crate::mtasts::PolicyStore::new(fetcher));
	let worker = Worker::new(
		spool,
		Arc::new(MxConnector {
			sink: sink.clone(),
			mx,
			mx_dns,
		}),
		"mail.sender.example",
	)
	.with_dane(Arc::clone(&dns))
	.with_mta_sts(store, dns)
	.with_outbound_tls(mode);
	let delivered = worker.pass().await.expect("pass");
	let left = worker.spool.list().expect("list").len();
	match (delivered, left) {
		(1, 0) => {
			let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
			if data.contains("with ESMTPS;") {
				Seen::DeliveredTls
			} else {
				Seen::DeliveredPlain
			}
		}
		(0, 1) => Seen::Deferred,
		_ => Seen::Dropped,
	}
}

/// One delivery attempt with TLS-RPT enabled. Returns the journal lines
/// recorded for the recipient domain on 2024-01-01 so the caller can
/// assert which result types were written.
pub(super) async fn attempt_with_tlsrpt(
	dns: Arc<dyn DnsLookup>,
	fetcher: Box<dyn crate::mtasts::PolicyFetcher>,
	mx: Mx,
	mx_dns: MxDns,
) -> Vec<serde_json::Value> {
	crate::queue::client::TEST_ROOTS.with(|roots| *roots.borrow_mut() = vec![certs().ca.clone()]);
	const NOW: u64 = 1_704_110_400;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["bob@remote.example".to_string()],
				data: b"From: alice@sender.example\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let sink = Arc::new(MemorySink::new());
	let store = Arc::new(crate::mtasts::PolicyStore::new(fetcher));
	let worker = Worker::new(
		spool,
		Arc::new(MxConnector {
			sink: sink.clone(),
			mx,
			mx_dns,
		}),
		"mail.sender.example",
	)
	.with_dane(Arc::clone(&dns))
	.with_mta_sts(store, dns)
	.with_tlsrpt(dir.path());
	worker.set_now(NOW);
	worker.pass().await.expect("pass");
	let path = dir
		.path()
		.join("reports/tlsrpt-outbound/20240101/remote.example.jsonl");
	std::fs::read_to_string(&path)
		.unwrap_or_default()
		.lines()
		.filter(|line| !line.is_empty())
		.map(|line| serde_json::from_str(line).expect("json line"))
		.collect()
}

/// What RFC 8461 and RFC 7672 call for in one cell.
fn expected(sts: Sts, tlsa: Tlsa, mx: Mx, mode: OutboundTls, mx_dns: MxDns) -> Seen {
	match mx_dns {
		// A forged or broken MX answer, denial or address answer: wait, as
		// for any lookup failure.
		MxDns::Bogus | MxDns::ImplicitBogusDenial | MxDns::ImplicitBogusAddress => {
			return Seen::Deferred;
		}
		// DANE needs a secure MX RRset (RFC 7672 section 2.2.1), or for an
		// implicit MX a secure denial and address answer (section 2.2.2):
		// otherwise the TLSA is never looked at.
		MxDns::Insecure | MxDns::ImplicitInsecure => {
			return expected(sts, Tlsa::Absent, mx, mode, MxDns::Secure);
		}
		MxDns::Secure | MxDns::ImplicitSecure => {}
	}
	let pkix_ok = mx == Mx::Good;
	let any_tls = mx != Mx::Plain;
	match tlsa {
		// A lookup that cannot finish might be hiding DANE: never guess.
		Tlsa::TempFail => Seen::Deferred,
		// DANE authenticates, and takes precedence over MTA-STS.
		Tlsa::Usable => match mx {
			Mx::Good | Mx::DaneOnly => Seen::DeliveredTls,
			Mx::Bad | Mx::Plain => Seen::Deferred,
		},
		Tlsa::Absent | Tlsa::Unusable => {
			// MTA-STS enforce requires PKIX; testing must not enforce.
			let pkix_required = sts == Sts::Enforce || mode == OutboundTls::Strict;
			// An unusable TLSA RRset still forbids cleartext.
			let tls_required = sts == Sts::Enforce || tlsa == Tlsa::Unusable;
			match (any_tls, pkix_required && !pkix_ok) {
				(false, _) if tls_required => Seen::Deferred,
				(false, _) => Seen::DeliveredPlain,
				(true, true) => Seen::Deferred,
				(true, false) => Seen::DeliveredTls,
			}
		}
	}
}

#[tokio::test]
async fn every_cell_of_the_transport_matrix() {
	let mut wrong = Vec::new();
	let mut cells = 0;
	for mode in [OutboundTls::Strict, OutboundTls::Opportunistic] {
		for sts in [Sts::None, Sts::Testing, Sts::Enforce] {
			for tlsa in [Tlsa::Absent, Tlsa::Usable, Tlsa::Unusable, Tlsa::TempFail] {
				for mx in [Mx::Good, Mx::DaneOnly, Mx::Bad, Mx::Plain] {
					for mx_dns in [
						MxDns::Secure,
						MxDns::Insecure,
						MxDns::Bogus,
						MxDns::ImplicitSecure,
						MxDns::ImplicitInsecure,
						MxDns::ImplicitBogusDenial,
						MxDns::ImplicitBogusAddress,
					] {
						cells += 1;
						let want = expected(sts, tlsa, mx, mode, mx_dns);
						let got = attempt(sts, tlsa, mx, mode, mx_dns).await;
						if got != want {
							wrong.push(format!(
								"{mode:?} {sts:?} {tlsa:?} {mx:?} {mx_dns:?}: want {want:?}, got {got:?}"
							));
						}
					}
				}
			}
		}
	}
	assert_eq!(cells, 672);
	assert!(wrong.is_empty(), "wrong cells:\n{}", wrong.join("\n"));
}
