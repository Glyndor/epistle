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
	/// Give the signer serverAuth as well as timeStamping.
	pub(crate) extra_usage: bool,
	/// Sign with a certificate that expired before the stamped time.
	pub(crate) expired_signer: bool,
	/// Leave the ESSCertIDv2 out of the signed attributes.
	pub(crate) no_signing_certificate: bool,
	/// Sign a content type other than TSTInfo.
	pub(crate) wrong_content_type: bool,
	/// Issue under this policy OID instead of 1.2.3.4.
	pub(crate) policy: Option<Vec<u8>>,
	/// Flip a bit of the signature.
	pub(crate) bad_signature: bool,
	/// Sign a messageDigest that is not that of the TSTInfo.
	pub(crate) wrong_message_digest: bool,
	/// Refuse with this PKIStatus.
	pub(crate) refuse: Option<u64>,
	/// Sign through an intermediate that is what this says.
	pub(crate) intermediate: Option<Intermediate>,
}

/// An intermediate certificate between the root and the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Intermediate {
	/// A certificate authority that may sign certificates.
	Proper,
	/// Not a certificate authority at all.
	NotAnAuthority,
	/// An authority whose key usage leaves out certificate signing.
	CannotSignCertificates,
	/// An authority that allows no intermediate below it, with one below.
	TooLong,
}

/// A test TSA.
pub(crate) struct FakeTsa {
	signer_key: KeyPair,
	signer_der: Vec<u8>,
	plain_signer_der: Vec<u8>,
	noncritical_signer_der: Vec<u8>,
	extra_usage_signer_der: Vec<u8>,
	expired_signer_der: Vec<u8>,
	/// The signer issued by each kind of intermediate, with the intermediate(s)
	/// it needs, nearest first.
	through: Vec<(Intermediate, Vec<u8>, Vec<Vec<u8>>)>,
	root_der: Vec<u8>,
	/// Hex-free SHA-256 of the root's SubjectPublicKeyInfo: the pin.
	pub(crate) anchor: [u8; 32],
	/// The time stamped into every token, epoch seconds.
	pub(crate) gen_time: u64,
	/// What to get wrong.
	pub(crate) faults: Faults,
	/// Every request body received over HTTP.
	pub(crate) received: Mutex<Vec<Vec<u8>>>,
	/// The Authorization header of every request that carried one.
	pub(crate) authorization: Mutex<Vec<String>>,
}

/// The policy OID the fake issues under: 1.2.3.4.
pub(crate) const POLICY: &[u8] = &[0x2a, 0x03, 0x04];

fn timestamping_usage(critical: bool) -> CustomExtension {
	usages(
		critical,
		&[&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]],
	)
}

fn usages(critical: bool, purposes: &[&[u8]]) -> CustomExtension {
	// ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId.
	let oids: Vec<Vec<u8>> = purposes
		.iter()
		.map(|purpose| encode(tag::OID, purpose))
		.collect();
	let refs: Vec<&[u8]> = oids.iter().map(Vec::as_slice).collect();
	let content = encode_all(tag::SEQUENCE, &refs);
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
		// id-kp-timeStamping and id-kp-serverAuth.
		signer.custom_extensions = vec![usages(
			true,
			&[
				&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
				&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
			],
		)];
		let extra_usage_signer_der = signer
			.signed_by(&signer_key, &issuer)
			.expect("extra usage signer")
			.der()
			.to_vec();
		signer.custom_extensions = vec![timestamping_usage(true)];
		let mut expired = signer.clone();
		expired.not_after = rcgen::date_time_ymd(1980, 1, 1);
		let expired_signer_der = expired
			.signed_by(&signer_key, &issuer)
			.expect("expired signer")
			.der()
			.to_vec();
		let signer_der = signer
			.signed_by(&signer_key, &issuer)
			.expect("signer")
			.der()
			.to_vec();
		let through = [
			Intermediate::Proper,
			Intermediate::NotAnAuthority,
			Intermediate::CannotSignCertificates,
			Intermediate::TooLong,
		]
		.into_iter()
		.map(|kind| {
			let levels = if kind == Intermediate::TooLong { 2 } else { 1 };
			let parts: Vec<(CertificateParams, KeyPair)> = (0..levels)
				.map(|level| {
					let key = KeyPair::generate().expect("intermediate key");
					let mut params =
						CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
					params
						.distinguished_name
						.push(DnType::CommonName, format!("Fake TSA Intermediate {level}"));
					params.is_ca = match kind {
						Intermediate::NotAnAuthority => IsCa::ExplicitNoCa,
						// The first level allows no intermediate below it.
						Intermediate::TooLong if level == 0 => {
							IsCa::Ca(BasicConstraints::Constrained(0))
						}
						_ => IsCa::Ca(BasicConstraints::Unconstrained),
					};
					params.key_usages = match kind {
						Intermediate::CannotSignCertificates => {
							vec![rcgen::KeyUsagePurpose::DigitalSignature]
						}
						_ => vec![
							rcgen::KeyUsagePurpose::KeyCertSign,
							rcgen::KeyUsagePurpose::CrlSign,
						],
					};
					(params, key)
				})
				.collect();
			let mut chain = Vec::new();
			for (index, (params, key)) in parts.iter().enumerate() {
				let above = match index {
					0 => Issuer::from_params(&root, &root_key),
					_ => Issuer::from_params(&parts[index - 1].0, &parts[index - 1].1),
				};
				let certificate = params.signed_by(key, &above).expect("intermediate");
				chain.insert(0, certificate.der().to_vec());
			}
			let last = parts.last().expect("an intermediate");
			let signer_der = signer
				.signed_by(&signer_key, &Issuer::from_params(&last.0, &last.1))
				.expect("signer through an intermediate")
				.der()
				.to_vec();
			(kind, signer_der, chain)
		})
		.collect();
		let anchor = {
			let (_, parsed) = X509Certificate::from_der(&root_der).expect("parse root");
			sha256(parsed.public_key().raw)
		};
		FakeTsa {
			signer_key,
			signer_der,
			plain_signer_der,
			noncritical_signer_der,
			extra_usage_signer_der,
			expired_signer_der,
			through,
			root_der,
			anchor,
			gen_time,
			faults: Faults::default(),
			received: Mutex::new(Vec::new()),
			authorization: Mutex::new(Vec::new()),
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
			encode(tag::OID, self.faults.policy.as_deref().unwrap_or(POLICY)),
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
		let via = self.faults.intermediate.and_then(|kind| {
			self.through
				.iter()
				.find(|(candidate, _, _)| *candidate == kind)
		});
		let signer_der = if let Some((_, signer_der, _)) = via {
			signer_der
		} else if self.faults.no_timestamping {
			&self.plain_signer_der
		} else if self.faults.noncritical_timestamping {
			&self.noncritical_signer_der
		} else if self.faults.extra_usage {
			&self.extra_usage_signer_der
		} else if self.faults.expired_signer {
			&self.expired_signer_der
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
		let content_type = if self.faults.wrong_content_type {
			oid::SIGNED_DATA
		} else {
			oid::TST_INFO
		};
		let mut attributes = vec![
			attribute(oid::CONTENT_TYPE, &encode(tag::OID, content_type)),
			attribute(oid::MESSAGE_DIGEST, &encode(tag::OCTET_STRING, &digest)),
		];
		if !self.faults.no_signing_certificate {
			attributes.push(attribute(oid::SIGNING_CERTIFICATE_V2, &ess));
		}
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
				&encode_all(tag::CONTEXT_0, &{
					let mut certificates: Vec<&[u8]> = vec![signer_der];
					if let Some((_, _, chain)) = via {
						certificates.extend(chain.iter().map(Vec::as_slice));
					}
					certificates.push(&self.root_der);
					certificates
				}),
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
			post(
				move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
					let tsa = Arc::clone(&tsa);
					async move {
						tsa.received.lock().expect("lock").push(body.to_vec());
						if let Some(value) = headers
							.get(axum::http::header::AUTHORIZATION)
							.and_then(|value| value.to_str().ok())
						{
							tsa.authorization
								.lock()
								.expect("lock")
								.push(value.to_string());
						}
						(
							[(
								axum::http::header::CONTENT_TYPE,
								"application/timestamp-reply",
							)],
							tsa.respond(&body),
						)
					}
				},
			),
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
