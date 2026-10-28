use super::*;
use ring::signature::KeyPair;

fn pair() -> (String, String) {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key");
	let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
		.expect("pair");
	(
		BASE64.encode(pkcs8.as_ref()),
		BASE64.encode(key.public_key().as_ref()),
	)
}

fn oauth(public: &str, extra: &str) -> Oauth {
	toml::from_str(&format!(
		"issuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"{public}\"\n{extra}"
	))
	.expect("parse")
}

#[test]
fn the_private_half_of_the_public_key_is_accepted() {
	let (private, public) = pair();
	let section = oauth(&public, &format!("signing_key = \"{private}\"\n"));
	assert_eq!(section.check_signing_pair(), Ok(()));
}

#[test]
fn another_providers_public_key_is_refused() {
	let (private, _) = pair();
	let (_, foreign) = pair();
	let section = oauth(&foreign, &format!("signing_key = \"{private}\"\n"));
	let error = section.check_signing_pair().unwrap_err();
	assert!(error.contains("not the private half"), "{error}");
}

#[test]
fn a_key_that_is_not_a_key_is_refused_and_no_signing_key_is_fine() {
	let (_, public) = pair();
	let error = oauth(&public, "signing_key = \"S\"\n")
		.check_signing_pair()
		.unwrap_err();
	assert!(error.contains("PKCS#8"), "{error}");
	assert_eq!(oauth(&public, "").check_signing_pair(), Ok(()));
}

#[test]
fn a_key_in_a_file_is_checked_too() {
	let (private, _) = pair();
	let (_, foreign) = pair();
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("oauth_signing.key");
	std::fs::write(&path, format!("{private}\n")).expect("write");
	let section = oauth(
		&foreign,
		&format!("signing_key_file = {:?}\n", path.display().to_string()),
	);
	assert!(section.check_signing_pair().is_err());
}

#[test]
fn a_signing_key_needs_the_es256_algorithm() {
	let (private, public) = pair();
	let section = oauth(&public, &format!("signing_key = \"{private}\"\n"));
	let rs256: Oauth = toml::from_str(&format!(
		"issuer = \"i\"\naudience = \"a\"\nalgorithm = \"RS256\"\npublic_key = \"{public}\"\nsigning_key = \"{private}\"\n"
	))
	.expect("parse");
	assert_eq!(section.check_signing_pair(), Ok(()));
	let error = rs256.check_signing_pair().unwrap_err();
	assert!(error.contains("ES256"), "{error}");
}
