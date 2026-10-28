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
