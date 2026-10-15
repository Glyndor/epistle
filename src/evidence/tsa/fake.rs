//! A timestamp authority for tests: real certificates (an ECDSA P-256 root
//! and a signer with the critical `timeStamping` usage, both minted per
//! test), real CMS signatures, and switches to break one property at a
//! time. It also serves RFC 3161 over HTTP on loopback and keeps the bodies
//! it received, so a test can see exactly what left the server.

use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::der::{encode, encode_all, parse_one, tag, unsigned_content};
use super::oid;
use crate::evidence::record::sha256;

/// What to get wrong in a response.
#[derive(Debug, Clone, Default)]
pub(crate) struct Faults {
	/// Stamp this digest instead of the requested one.
	pub(crate) imprint: Option<[u8; 32]>,
	/// Answer with this nonce instead of the requested one.
	pub(crate) nonce: Option<u64>,
	/// Leave out the timeStamping usage of the signer.
	pub(crate) no_timestamping: bool,
	/// Give the signer the timeStamping usage, not marked critical.
	pub(crate) noncritical_timestamping: bool,
	/// Flip a bit of the signature.
	pub(crate) bad_signature: bool,
	/// Sign a messageDigest that is not that of the TSTInfo.
	pub(crate) wrong_message_digest: bool,
	/// Refuse with this PKIStatus.
	pub(crate) refuse: Option<u64>,
}

/// A test TSA.
pub(crate) struct FakeTsa {
	signer_key: KeyPair,
	signer_der: Vec<u8>,
	plain_signer_der: Vec<u8>,
	noncritical_signer_der: Vec<u8>,
	root_der: Vec<u8>,
	/// Hex-free SHA-256 of the root's SubjectPublicKeyInfo: the pin.
	pub(crate) anchor: [u8; 32],
	/// The time stamped into every token, epoch seconds.
	pub(crate) gen_time: u64,
	/// What to get wrong.
	pub(crate) faults: Faults,
	/// Every request body received over HTTP.
	pub(crate) received: Mutex<Vec<Vec<u8>>>,
}

fn timestamping_usage(critical: bool) -> CustomExtension {
	// ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId; id-kp-timeStamping.
	let content = encode_all(
		tag::SEQUENCE,
		&[&encode(
			tag::OID,
			&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
		)],
	);
	let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 37], content);
	extension.set_criticality(critical);
	extension
}

impl FakeTsa {
	/// A TSA whose tokens are stamped at `gen_time`.
	pub(crate) fn new(gen_time: u64) -> Self {
		let root_key = KeyPair::generate().expect("root key");
		let mut root = CertificateParams::new(Vec::<String>::new()).expect("root params");
		root.distinguished_name
			.push(DnType::CommonName, "Fake TSA Root");
		root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let root_der = root.self_signed(&root_key).expect("root").der().to_vec();
		let issuer = Issuer::from_params(&root, &root_key);
		let signer_key = KeyPair::generate().expect("signer key");
		let mut signer = CertificateParams::new(Vec::<String>::new()).expect("signer params");
		signer
			.distinguished_name
			.push(DnType::CommonName, "Fake TSA Signer");
		let plain_signer_der = signer
			.signed_by(&signer_key, &issuer)
			.expect("plain signer")
			.der()
			.to_vec();
		signer.custom_extensions.push(timestamping_usage(false));
		let noncritical_signer_der = signer
			.signed_by(&signer_key, &issuer)
			.expect("noncritical signer")
			.der()
			.to_vec();
		signer.custom_extensions = vec![timestamping_usage(true)];
		let signer_der = signer
			.signed_by(&signer_key, &issuer)
			.expect("signer")
			.der()
			.to_vec();
		let anchor = {
			let (_, parsed) = X509Certificate::from_der(&root_der).expect("parse root");
			sha256(parsed.public_key().raw)
		};
		FakeTsa {
			signer_key,
			signer_der,
			plain_signer_der,
			noncritical_signer_der,
			root_der,
			anchor,
			gen_time,
			faults: Faults::default(),
			received: Mutex::new(Vec::new()),
		}
	}

	/// The root certificate, PEM, as a bundle would carry it.
	pub(crate) fn root_pem(&self) -> String {
		use base64::Engine;
		let body = base64::engine::general_purpose::STANDARD.encode(&self.root_der);
		format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
	}

	/// The TimeStampResp for the TimeStampReq `request`.
	pub(crate) fn respond(&self, request: &[u8]) -> Vec<u8> {
		if let Some(status) = self.faults.refuse {
			return encode_all(
				tag::SEQUENCE,
				&[&encode_all(
					tag::SEQUENCE,
					&[&encode(tag::INTEGER, &unsigned_content(status))],
				)],
			);
		}
		let request = parse_one(request, tag::SEQUENCE).expect("request");
		let mut fields = request.reader();
		fields.expect(tag::INTEGER).expect("version");
		let imprint = fields.expect(tag::SEQUENCE).expect("imprint");
		let nonce = fields
			.optional(tag::INTEGER)
			.expect("nonce")
			.map(|tlv| tlv.value.to_vec());
		let imprint = match self.faults.imprint {
			Some(digest) => encode_all(
				tag::SEQUENCE,
				&[
					&encode_all(
						tag::SEQUENCE,
						&[&encode(tag::OID, oid::SHA256), &encode(tag::NULL, &[])],
					),
					&encode(tag::OCTET_STRING, &digest),
				],
			),
			None => imprint.raw.to_vec(),
		};
		let nonce = match self.faults.nonce {
			Some(nonce) => Some(unsigned_content(nonce)),
			None => nonce,
		};
		let tst = self.tst_info(&imprint, nonce.as_deref());
		self.wrap(&tst)
	}

	fn tst_info(&self, imprint: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
		let time = generalized(self.gen_time);
		let mut parts = vec![
			encode(tag::INTEGER, &[1]),
			encode(tag::OID, &[0x2a, 0x03, 0x04]),
			imprint.to_vec(),
			encode(tag::INTEGER, &unsigned_content(self.gen_time)),
			encode(tag::GENERALIZED_TIME, time.as_bytes()),
		];
		if let Some(nonce) = nonce {
			parts.push(encode(tag::INTEGER, nonce));
		}
		let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
		encode_all(tag::SEQUENCE, &refs)
	}

	fn wrap(&self, tst: &[u8]) -> Vec<u8> {
		let signer_der = if self.faults.no_timestamping {
			&self.plain_signer_der
		} else if self.faults.noncritical_timestamping {
			&self.noncritical_signer_der
		} else {
			&self.signer_der
		};
		let digest = if self.faults.wrong_message_digest {
			sha256(b"something else")
		} else {
			sha256(tst)
		};
		let attribute = |kind: &[u8], value: &[u8]| {
			encode_all(
				tag::SEQUENCE,
				&[&encode(tag::OID, kind), &encode(tag::SET, value)],
			)
		};
		let ess = encode_all(
			tag::SEQUENCE,
			&[&encode_all(
				tag::SEQUENCE,
				&[&encode_all(
					tag::SEQUENCE,
					&[&encode(tag::OCTET_STRING, &sha256(signer_der))],
				)],
			)],
		);
		let mut attributes = vec![
			attribute(oid::CONTENT_TYPE, &encode(tag::OID, oid::TST_INFO)),
			attribute(oid::MESSAGE_DIGEST, &encode(tag::OCTET_STRING, &digest)),
			attribute(oid::SIGNING_CERTIFICATE_V2, &ess),
		];
		// DER orders the members of a SET OF by their encodings.
		attributes.sort();
		let content: Vec<u8> = attributes.concat();
		let mut signature = self.sign(&encode(tag::SET, &content));
		if self.faults.bad_signature {
			let last = signature.len() - 1;
			signature[last] ^= 1;
		}
		let (issuer, serial) = {
			let (_, parsed) = X509Certificate::from_der(signer_der).expect("parse signer");
			(
				parsed.issuer().as_raw().to_vec(),
				parsed.raw_serial().to_vec(),
			)
		};
		let algorithm = |kind: &[u8]| encode_all(tag::SEQUENCE, &[&encode(tag::OID, kind)]);
		let signer_info = encode_all(
			tag::SEQUENCE,
			&[
				&encode(tag::INTEGER, &[1]),
				&encode_all(tag::SEQUENCE, &[&issuer, &encode(tag::INTEGER, &serial)]),
				&algorithm(oid::SHA256),
				&encode(tag::CONTEXT_0, &content),
				&algorithm(oid::ECDSA_SHA256),
				&encode(tag::OCTET_STRING, &signature),
			],
		);
		let signed_data = encode_all(
			tag::SEQUENCE,
			&[
				&encode(tag::INTEGER, &[3]),
				&encode(tag::SET, &algorithm(oid::SHA256)),
				&encode_all(
					tag::SEQUENCE,
					&[
						&encode(tag::OID, oid::TST_INFO),
						&encode(tag::CONTEXT_0, &encode(tag::OCTET_STRING, tst)),
					],
				),
				&encode_all(tag::CONTEXT_0, &[signer_der, &self.root_der]),
				&encode(tag::SET, &signer_info),
			],
		);
		let content_info = encode_all(
			tag::SEQUENCE,
			&[
				&encode(tag::OID, oid::SIGNED_DATA),
				&encode(tag::CONTEXT_0, &signed_data),
			],
		);
		encode_all(
			tag::SEQUENCE,
			&[
				&encode_all(tag::SEQUENCE, &[&encode(tag::INTEGER, &[0])]),
				&content_info,
			],
		)
	}

	fn sign(&self, message: &[u8]) -> Vec<u8> {
		let rng = ring::rand::SystemRandom::new();
		let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
			&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
			&self.signer_key.serialize_der(),
			&rng,
		)
		.expect("signer pkcs8");
		pair.sign(&rng, message).expect("sign").as_ref().to_vec()
	}

	/// Serve RFC 3161 over HTTP on loopback; returns the URL to POST to.
	pub(crate) async fn serve(self: Arc<Self>) -> String {
		use axum::routing::post;
		let tsa = Arc::clone(&self);
		let app = axum::Router::new().route(
			"/tsr",
			post(move |body: axum::body::Bytes| {
				let tsa = Arc::clone(&tsa);
				async move {
					tsa.received.lock().expect("lock").push(body.to_vec());
					(
						[(
							axum::http::header::CONTENT_TYPE,
							"application/timestamp-reply",
						)],
						tsa.respond(&body),
					)
				}
			}),
		);
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind");
		let address = listener.local_addr().expect("address");
		tokio::spawn(async move {
			let _ = axum::serve(listener, app).await;
		});
		format!("http://{address}/tsr")
	}
}

/// `YYYYMMDDHHMMSSZ` for epoch seconds.
fn generalized(epoch: u64) -> String {
	let day = crate::evidence::day::Day::of_epoch(epoch);
	let seconds = epoch - day.start_epoch();
	let date = day.name().replace('-', "");
	format!(
		"{date}{:02}{:02}{:02}Z",
		seconds / 3600,
		seconds % 3600 / 60,
		seconds % 60
	)
}
