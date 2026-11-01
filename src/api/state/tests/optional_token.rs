//! Optional static credentials must never create an implicit administrator.

use super::*;
use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope, sha256_hash};

fn state(hash: Option<&str>) -> (tempfile::TempDir, ApiState) {
	let dir = tempfile::tempdir().unwrap();
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".into()],
			Default::default(),
			Vec::new(),
		)
		.unwrap(),
	);
	let state = ApiState::new_with_optional_token(
		hash,
		dir.path().into(),
		vec!["example.org".into()],
		store,
		crate::storage::FsSpool::open(dir.path()).unwrap(),
	);
	(dir, state)
}

#[tokio::test]
async fn absent_static_hash_never_matches_any_bearer_or_cached_digest() {
	let (_dir, state) = state(None);
	let real = crate::test_fixtures::api_token();
	// The digest prefix is read off a computed hash, not written as a literal.
	let prefix = sha256_hash(real).split_once(':').unwrap().0.to_owned() + ":";
	for token in [&real[..0], prefix.as_str(), real] {
		state.prime_configured_token(token);
		assert!(!state.bearer_is_configured(token));
		assert!(!state.bearer_is_configured_async(token, None).await.unwrap());
	}
	assert_eq!(state.argon2_stats(), (0, 0));
	assert_eq!(state.argon2_waiting(), 0);
}

#[tokio::test]
async fn every_scope_key_is_not_the_static_identity() {
	let (dir, mut state) = state(None);
	let token = crate::test_fixtures::api_key();
	let mut keys = ApiKeyStore::open(dir.path()).unwrap();
	keys.add(ApiKey {
		label: "all-scopes".into(),
		hash: sha256_hash(token),
		expires_at: None,
		ip_cidr: None,
		domains: Vec::new(),
		account: None,
		scopes: ["read", "write", "send", "scim"]
			.map(str::to_owned)
			.to_vec(),
	})
	.unwrap();
	state = state.with_api_keys(std::sync::Arc::new(
		crate::api::ApiKeySet::open(dir.path()).unwrap(),
	));
	for scope in [Scope::Read, Scope::Write, Scope::Send, Scope::Scim] {
		assert!(state.key_authorizes(token, None, &[scope]));
	}
	assert!(!state.bearer_is_configured_async(token, None).await.unwrap());
	let principal = crate::api::Principal::for_token(
		&state,
		&MatchedAuth {
			token: Some(token.into()),
			client_ip: None,
			configured: false,
		},
	);
	assert!(principal.credential().is_some());
}

#[tokio::test]
async fn configured_hashes_keep_matching_and_missing() {
	let token = crate::test_fixtures::api_token();
	for hash in [
		sha256_hash(token),
		crate::smtp::auth::tests::base::hash(token),
	] {
		let (_dir, state) = state(Some(&hash));
		assert!(
			!state
				.bearer_is_configured_async("sha256:", None)
				.await
				.unwrap()
		);
		assert!(state.bearer_is_configured(token));
		assert!(state.bearer_is_configured_async(token, None).await.unwrap());
		assert!(
			!state
				.bearer_is_configured_async("wrong", None)
				.await
				.unwrap()
		);
	}
}

#[tokio::test]
async fn absent_hash_miss_does_no_argon2_work() {
	let (_dir, absent) = state(None);
	let hash = crate::smtp::auth::tests::base::hash(crate::test_fixtures::api_token());
	let (_configured_dir, configured) = state(Some(&hash));
	for (label, state) in [("absent", &absent), ("configured argon2 miss", &configured)] {
		let started = std::time::Instant::now();
		assert!(
			!state
				.bearer_is_configured_async("sha256:", None)
				.await
				.unwrap()
		);
		eprintln!("{label}: {:?}", started.elapsed());
	}
	assert_eq!(absent.argon2_stats(), (0, 0));
	assert_eq!(configured.argon2_stats().0, 1);
	let hash = sha256_hash(crate::test_fixtures::api_token());
	let (_digest_dir, digest_state) = state(Some(&hash));
	for (label, state) in [
		("absent", &absent),
		("configured SHA-256 miss", &digest_state),
	] {
		let started = std::time::Instant::now();
		for _ in 0..10000 {
			assert!(
				!state
					.bearer_is_configured_async(std::hint::black_box("sha256:"), None)
					.await
					.unwrap()
			);
		}
		eprintln!("{label}, 10000 misses: {:?}", started.elapsed());
	}
}
