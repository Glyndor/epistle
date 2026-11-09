use super::*;

#[test]
fn generates_der_csr_and_key() {
	let csr =
		generate(&["mail.example.org".to_string(), "example.org".to_string()]).expect("generate");
	// base64url decodes to a DER SEQUENCE (0x30).
	let der = B64.decode(&csr.der_b64url).expect("b64url");
	assert_eq!(der.first(), Some(&0x30));
	// A private key PEM is returned.
	assert!(csr.key_pem.contains("PRIVATE KEY"));
}

#[test]
fn rejects_empty_domains() {
	assert!(generate(&[]).is_err());
}

/// The CA validates the names in the request. The subject must not carry the
/// default common name of the library (`rcgen self signed cert`), which Let's
/// Encrypt rejects, and every domain must be a SAN.
#[test]
fn subject_is_empty_and_every_domain_is_a_san() {
	use x509_parser::prelude::{FromDer, GeneralName, X509CertificationRequest};
	let domains = ["mail.example.org".to_string(), "example.org".to_string()];
	let csr = generate(&domains).expect("generate");
	let der = B64.decode(&csr.der_b64url).expect("b64url");
	let (_, request) = X509CertificationRequest::from_der(&der).expect("a valid PKCS#10 request");
	let info = &request.certification_request_info;
	assert_eq!(info.subject.iter_attributes().count(), 0, "no subject name");
	let names: Vec<String> = request
		.requested_extensions()
		.expect("extensions")
		.flat_map(|ext| match ext {
			x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => san
				.general_names
				.iter()
				.filter_map(|name| match name {
					GeneralName::DNSName(dns) => Some((*dns).to_string()),
					_ => None,
				})
				.collect::<Vec<_>>(),
			_ => Vec::new(),
		})
		.collect();
	assert_eq!(names, domains);
}
