//! The credential recheck shared by WebSockets and event sources honors OAuth.

use super::super::{PushState, credential_still_valid, handle_ws_message};
use crate::api::state::MatchedAuth;
use crate::api::tests::base::{request_with_body, test_state};
use crate::api::{Principal, oauth::AuthzServer, router};
use axum::http::StatusCode;
use base64::Engine;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};

#[tokio::test]
async fn oauth_frames_keep_scopes_and_subject_and_stream_rechecks_notice_revocation() {
	let dir = tempfile::tempdir().unwrap();
	std::fs::create_dir_all(dir.path().join("accounts/alice/new")).unwrap();
	let rng = ring::rand::SystemRandom::new();
	let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let authz = AuthzServer::new(
		&base64::engine::general_purpose::STANDARD.encode(key.as_ref()),
		"issuer",
		"audience",
	)
	.unwrap();
	let state = test_state(dir.path(), 0).with_authz(authz);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let token = crate::jwt::sign(
		&json!({
			"sub": "alice", "iss": "issuer", "aud": "audience", "scope": "read",
			"iat": now, "exp": now + 3600,
			"jti": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
		}),
		crate::jwt::Algorithm::Es256,
		key.as_ref(),
	)
	.unwrap();
	let auth = MatchedAuth {
		token: Some(token.clone()),
		client_ip: None,
		configured: false,
	};
	let principal = Principal::for_token(&state, &auth);
	assert!(credential_still_valid(&state, &auth, &principal));
	let frames = handle_ws_message(
		&state,
		&principal,
		&json!({"@type": "Request", "methodCalls": [
			["Mailbox/get", {"accountId": "alice"}, "own"],
			["Mailbox/get", {"accountId": "foreign"}, "foreign"],
			["EmailSubmission/set", {"accountId": "alice", "create": {}}, "send"],
		]})
		.to_string(),
		&mut PushState::default(),
	);
	let reply: Value = serde_json::from_str(&frames[0]).unwrap();
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/get");
	assert_eq!(reply["methodResponses"][1][1]["type"], "accountNotFound");
	assert_eq!(reply["methodResponses"][2][1]["type"], "forbidden");
	let app = router(state.clone());
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/oauth/revoke",
		None,
		Some(json!({"token": token})),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(!credential_still_valid(&state, &auth, &principal));
}
