use super::*;
use crate::test_fixtures as fixtures;

/// Compute the client side of the exchange to drive the server in tests.
fn client_proof(password: &str, credentials: &ScramCredentials, auth_message: &str) -> Vec<u8> {
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(credentials.iterations).unwrap(),
		&credentials.salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac_sha256(&salted, b"Client Key");
	let stored_key = sha256(&client_key);
	let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
	(0..32)
		.map(|i| client_key[i] ^ client_signature[i])
		.collect()
}

fn run_exchange(password: &str, login_password: &str) -> Result<String, ScramError> {
	let nonce = fixtures::nonce();
	let credentials = ScramCredentials::derive(password, fixtures::salt(), 4096);
	let mut server = ScramServer::new(fixtures::nonce());
	let client_first = "n,,n=alice,r=clientnonce";
	let (user, server_first) = server.first(client_first, &credentials)?;
	assert_eq!(user, "alice");

	let without_proof = format!("c=biws,r=clientnonce{nonce}");
	let auth_message = format!("n=alice,r=clientnonce,{server_first},{without_proof}");
	// The client computes its proof from the *login* password.
	let proof = client_proof(login_password, &credentials, &auth_message);
	let client_final = format!("{without_proof},p={}", BASE64.encode(&proof));
	server.finish(&client_final, &credentials)
}

#[test]
fn stored_credentials_roundtrip() {
	let credentials = ScramCredentials::derive(fixtures::password(), fixtures::salt(), 4096);
	let stored = ScramStored::from_credentials(&credentials);
	let restored = stored.to_credentials().expect("decode");
	assert!(
		(restored.salt) == (credentials.salt),
		"credential field must match"
	);
	assert_eq!(restored.iterations, credentials.iterations);
	assert!(
		(restored.stored_key) == (credentials.stored_key),
		"credential field must match"
	);
	assert!(
		(restored.server_key) == (credentials.server_key),
		"credential field must match"
	);
}

#[test]
fn malformed_stored_credentials_rejected() {
	let stored = ScramStored {
		salt: "not base64!!!".to_string(),
		iterations: 4096,
		stored_key: "x".to_string(),
		server_key: "y".to_string(),
	};
	assert!(stored.to_credentials().is_none());
}

#[test]
fn correct_password_authenticates() {
	let result = run_exchange(fixtures::password(), fixtures::password()).expect("authenticated");
	assert!(result.starts_with("v="));
}

#[test]
fn wrong_password_fails() {
	assert!(
		(run_exchange(fixtures::password(), fixtures::second_password()))
			== (Err(ScramError::AuthenticationFailed)),
		"credential field must match"
	);
}

#[test]
fn server_first_carries_salt_and_iterations() {
	let nonce = fixtures::nonce();
	let credentials = ScramCredentials::derive(fixtures::password(), fixtures::salt(), 4096);
	let mut server = ScramServer::new(fixtures::nonce());
	let (_, server_first) = server.first("n,,n=bob,r=CN", &credentials).expect("first");
	assert!(
		(server_first) == (format!("r=CN{nonce},s={},i=4096", BASE64.encode(fixtures::salt()))),
		"credential field must match"
	);
}

#[test]
fn altered_nonce_is_rejected() {
	let credentials = ScramCredentials::derive(fixtures::password(), fixtures::salt(), 4096);
	let mut server = ScramServer::new(fixtures::nonce());
	server.first("n,,n=bob,r=CN", &credentials).expect("first");
	// A client-final echoing the wrong nonce is malformed.
	let bad = "c=biws,r=WRONG,p=AAAA";
	assert!(
		(server.finish(bad, &credentials)) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

#[test]
fn malformed_client_first_is_rejected() {
	let credentials = ScramCredentials::derive(fixtures::password(), fixtures::salt(), 4096);
	let mut server = ScramServer::new(fixtures::nonce());
	assert!(
		(server.first("garbage", &credentials)) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

/// Drive a full exchange with an explicit GS2 header and channel-binding
/// data, returning the server-final or the first error.
fn run_cb_exchange(
	cb: ChannelBinding,
	client_header: &str,
	client_cbind: &[u8],
) -> Result<String, ScramError> {
	let nonce = fixtures::nonce();
	let credentials = ScramCredentials::derive(fixtures::password(), fixtures::salt(), 4096);
	let mut server = ScramServer::new(fixtures::nonce()).with_channel_binding(cb);
	let client_first = format!("{client_header}n=alice,r=clientnonce");
	let (_, server_first) = server.first(&client_first, &credentials)?;
	let mut c = client_header.as_bytes().to_vec();
	c.extend_from_slice(client_cbind);
	let without_proof = format!("c={},r=clientnonce{nonce}", BASE64.encode(&c));
	let auth_message = format!("n=alice,r=clientnonce,{server_first},{without_proof}");
	let proof = client_proof(fixtures::password(), &credentials, &auth_message);
	let client_final = format!("{without_proof},p={}", BASE64.encode(&proof));
	server.finish(&client_final, &credentials)
}

const CERT_HASH: &[u8] = b"0123456789abcdef0123456789abcdef";

#[test]
fn plus_with_correct_binding_authenticates() {
	let result = run_cb_exchange(
		ChannelBinding::Required(CERT_HASH.to_vec()),
		"p=tls-server-end-point,,",
		CERT_HASH,
	);
	assert!(result.expect("authenticated").starts_with("v="));
}

#[test]
fn plus_with_wrong_binding_fails() {
	let result = run_cb_exchange(
		ChannelBinding::Required(CERT_HASH.to_vec()),
		"p=tls-server-end-point,,",
		b"a-different-32-byte-certificate!!",
	);
	assert!(
		(result) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

#[test]
fn plus_requires_the_p_flag() {
	// A -PLUS exchange where the client does not actually bind.
	let result = run_cb_exchange(ChannelBinding::Required(CERT_HASH.to_vec()), "n,,", b"");
	assert!(
		(result) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

#[test]
fn supported_rejects_downgrade_flag() {
	// `y,,` on the non-PLUS mechanism when the server offers -PLUS is a
	// downgrade attempt.
	let result = run_cb_exchange(ChannelBinding::Supported, "y,,", b"");
	assert!(
		(result) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

#[test]
fn supported_accepts_unbound_client() {
	let result = run_cb_exchange(ChannelBinding::Supported, "n,,", b"");
	assert!(result.expect("authenticated").starts_with("v="));
}

#[test]
fn supported_rejects_tampered_binding() {
	// The header says `n,,` but the c= carries extra bytes.
	let result = run_cb_exchange(ChannelBinding::Supported, "n,,", b"extra");
	assert!(
		(result) == (Err(ScramError::Malformed)),
		"credential field must match"
	);
}

#[test]
fn a_fresh_salt_is_never_the_declared_buffer_and_never_repeats() {
	// The three call sites this replaced each wrote `[0u8; 16]` and then
	// overwrote it. If a future edit drops the randomness and leaves the
	// buffer as declared, every account would share one known salt — so
	// the all-zero salt is asserted against explicitly, not just
	// inequality between two draws.
	let a = ScramStored::with_fresh_salt(fixtures::password()).expect("csprng");
	let b = ScramStored::with_fresh_salt(fixtures::password()).expect("csprng");
	let decoded = base64::engine::general_purpose::STANDARD
		.decode(&a.salt)
		.expect("salt is base64");
	assert_eq!(decoded.len(), SALT_LEN, "salt keeps its declared width");
	assert!(
		decoded.iter().any(|byte| *byte != 0),
		"the salt is not the all-zero buffer"
	);
	assert!((a.salt) != (b.salt), "credential field must differ");
	assert_eq!(a.iterations, SCRAM_ITERATIONS);
}

#[test]
fn a_fresh_salt_still_authenticates_the_password_it_derived_from() {
	// A salt that is random but not the one actually used would pass the
	// test above and break every login, so the round trip is checked too.
	let stored = ScramStored::with_fresh_salt(fixtures::password()).expect("csprng");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(&stored.salt)
		.expect("salt is base64");
	let again = ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		&salt,
		stored.iterations,
	));
	assert!(
		(again.stored_key) == (stored.stored_key),
		"credential field must match"
	);
	assert!(
		(again.server_key) == (stored.server_key),
		"credential field must match"
	);
}
