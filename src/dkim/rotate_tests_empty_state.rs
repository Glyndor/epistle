//! A rotation that never put a key in service leaves no state behind,
//! and a state that names no key reads as an absent state: the server
//! then signs with the configured key instead of refusing to say which
//! key it signs with.
//!
//! This is the shape a fresh install with a `[dns]` provider got on its
//! first start (Glyndor/epistle#1376): the rotation failed, the state
//! file it left named no selector, and `dkim show` and `status` could
//! not tell which key the server signed with.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A provider that refuses every write, so the rotation cannot publish
/// and is withdrawn.
struct RefusingProvider;

impl DnsProvider for RefusingProvider {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Remote("refused".into())) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// The `[dkim]` section of an install that has not rotated yet.
fn configured() -> crate::config::Dkim {
	toml::from_str("selector = 'configured'\nkey_file = '/etc/mail/configured.key'\n")
		.expect("dkim config")
}

/// A data directory with the configured key on disk and no rotation
/// state, and a rotator whose provider refuses every write.
fn fresh_install() -> (tempfile::TempDir, PathBuf, Rotator) {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let (pem, _) = super::super::generate_key().expect("key");
	let key_file = root.join("configured.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = Arc::new(Signer::load("configured", &key_file).expect("load"));
	let rotator = Rotator::new(
		root.clone(),
		ReloadableSigner::new(signer),
		Arc::new(RefusingProvider),
		"example.org".into(),
		vec!["example.org".into()],
		30 * 86_400,
		2 * 86_400,
	);
	(dir, root, rotator)
}

#[tokio::test]
async fn a_first_rotation_that_fails_leaves_no_state_file() {
	let (_dir, root, rotator) = fresh_install();
	let error = rotator.tick(86_400).await.expect_err("withdrawn");
	assert!(
		error.to_string().contains("withdrawn"),
		"the rotation is withdrawn: {error}"
	);
	assert!(
		!root.join(STATE_FILE).exists(),
		"a rotation that never put a key in service leaves no state file"
	);
	assert_eq!(
		read_state(&root).expect("the state reads"),
		None,
		"what is left on disk reads as an absent state"
	);
}

#[tokio::test]
async fn a_rotation_that_fails_keeps_the_key_that_was_in_service() {
	let (_dir, root, rotator) = fresh_install();
	// A rotation that already put a key in service keeps naming it when
	// the next one is withdrawn: the state is not empty, so the file
	// stays.
	let state = RotationState {
		selector: "ed0".into(),
		key_file: "dkim-ed0.key".into(),
		rotated_at: 0,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		root.join(STATE_FILE),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	let error = rotator.tick(30 * 86_400).await.expect_err("withdrawn");
	assert!(error.to_string().contains("withdrawn"), "{error}");
	let state = read_state(&root)
		.expect("the state reads")
		.expect("the state is there");
	assert_eq!(
		state.selector, "ed0",
		"the key that was in service keeps being named"
	);
}

#[test]
fn an_empty_state_file_reads_as_an_absent_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join(STATE_FILE),
		r#"{"selector": "", "key_file": "", "rotated_at": 0, "previous": null}"#,
	)
	.expect("write state");
	assert_eq!(
		read_state(dir.path()).expect("the state reads"),
		None,
		"a state that names no key is an absent state, not a corrupt one"
	);
	let active = active_ed25519(&configured(), dir.path()).expect("the active key");
	assert_eq!(
		active.selector, "configured",
		"the configured key signs while no rotation is in service"
	);
}

#[test]
fn a_state_with_a_pending_rotation_loads_even_without_a_selector() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join(STATE_FILE),
		r#"{"selector": "", "key_file": "", "rotated_at": 0, "previous": null,
		"pending": {"selector": "ed1", "key_file": "/tmp/dkim-ed1.key",
		"domains": ["example.org"], "started_at": 1}}"#,
	)
	.expect("write state");
	let state = read_state(dir.path())
		.expect("the state reads")
		.expect("the journal is there");
	assert_eq!(
		state.pending.expect("pending").selector,
		"ed1",
		"a rotation journaled before its key was in service still loads"
	);
	let active = active_ed25519(&configured(), dir.path()).expect("the active key");
	assert_eq!(
		active.selector, "configured",
		"the configured key signs while the first rotation is pending"
	);
}
