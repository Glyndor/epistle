//! A token that does not validate says why, and the reasons differ.

use super::*;

fn reason(error: &Invalid) -> &'static str {
	invalid_reason(error)
}

fn jwk(kid: &str) -> Jwk {
	Jwk {
		kid: kid.to_string(),
		algorithm: Algorithm::Es256,
		key: vec![0x04; 65],
	}
}

/// A token header naming `kid`, with nothing after it that matters here.
fn token_with_kid(kid: &str) -> String {
	use base64::Engine;
	let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.encode(format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#));
	format!("{header}.e30.AAAA")
}

#[test]
fn an_empty_key_set_an_unknown_kid_and_a_poisoned_cache_are_told_apart() {
	let empty = OauthVerifier::from_jwks("i", "a", vec![]);
	let none = empty.validate(&token_with_kid("k"), 1).unwrap_err();
	assert!(matches!(none, Invalid::NoKeys));

	let known = OauthVerifier::from_jwks("i", "a", vec![jwk("other")]);
	let unknown = known.validate(&token_with_kid("k"), 1).unwrap_err();
	assert!(matches!(unknown, Invalid::UnknownKey));

	let cache = known.jwks_cache().expect("cache");
	let poisoner = std::sync::Arc::clone(&cache);
	let _ = std::thread::spawn(move || {
		let _guard = poisoner.write().expect("lock");
		panic!("poison the cache");
	})
	.join();
	let poisoned = known.validate(&token_with_kid("k"), 1).unwrap_err();
	assert!(matches!(poisoned, Invalid::KeysUnavailable));

	let reasons = [
		reason(&none),
		reason(&unknown),
		reason(&poisoned),
		reason(&Invalid::Token(jwt::JwtError::BadSignature)),
	];
	for (at, one) in reasons.iter().enumerate() {
		for other in &reasons[at + 1..] {
			assert_ne!(one, other);
		}
	}
}
