//! Unit tests for the (pure) rotation decision and the reloadable signer.

use super::*;

const DAY: u64 = 86_400;

fn state(selector: &str, rotated_at: u64, previous: Option<Previous>) -> RotationState {
	RotationState {
		selector: selector.to_string(),
		key_file: "dkim.key".into(),
		rotated_at,
		previous,
	}
}

#[test]
fn empty_state_rotates_to_bootstrap() {
	assert_eq!(
		decide(&RotationState::default(), 1_000, 30 * DAY, DAY),
		Decision::Rotate
	);
}

#[test]
fn rotates_once_interval_elapses() {
	let s = state("ed1", 1_000_000, None);
	// Before the interval: idle.
	assert_eq!(decide(&s, 1_000_000 + DAY, 30 * DAY, DAY), Decision::Idle);
	// After the interval: rotate.
	assert_eq!(
		decide(&s, 1_000_000 + 30 * DAY, 30 * DAY, DAY),
		Decision::Rotate
	);
}

#[test]
fn retires_previous_after_overlap_takes_precedence() {
	let previous = Previous {
		selector: "ed-old".into(),
		key_file: PathBuf::default(),
		retire_at: 2_000,
	};
	let s = state("ed-new", 0, Some(previous));
	// Overlap not elapsed: still idle (interval not reached either).
	assert_eq!(decide(&s, 1_999, 30 * DAY, DAY), Decision::Idle);
	// Overlap elapsed: retire the old selector, even though rotation is also due.
	let due = state(
		"ed-new",
		0,
		Some(Previous {
			selector: "ed-old".into(),
			key_file: PathBuf::default(),
			retire_at: 2_000,
		}),
	);
	assert_eq!(
		decide(&due, 100 * DAY, 30 * DAY, DAY),
		Decision::Retire("ed-old".into())
	);
}

#[test]
fn selector_is_day_unique_and_stable() {
	assert_eq!(selector_for(0), "ed0");
	assert_eq!(selector_for(DAY), "ed1");
	// Same day → same selector; next day → different.
	assert_eq!(selector_for(5 * DAY + 10), selector_for(5 * DAY + 20));
	assert_ne!(selector_for(5 * DAY), selector_for(6 * DAY));
}

#[cfg(unix)]
#[test]
fn write_key_creates_with_owner_only_perms_and_refuses_overwrite() {
	use std::os::unix::fs::PermissionsExt;

	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("dkim-sel.key");

	super::write_key(&path, "PEM").expect("write");
	let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
	// Never group/world readable: the private key has no permissive window.
	assert_eq!(mode & 0o077, 0, "mode = {:o}", mode);

	// A pre-existing path is an error (fail closed), not a silent overwrite.
	assert!(super::write_key(&path, "OTHER").is_err());
}

#[test]
fn reloadable_signer_swaps_the_active_signer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem1, _) = super::super::generate_key().expect("key1");
	let path1 = dir.path().join("a.key");
	std::fs::write(&path1, pem1).expect("write");
	let signer1 = std::sync::Arc::new(Signer::load("ed-a", &path1).expect("load1"));

	let handle = ReloadableSigner::new(signer1);
	assert!(!handle.current().dns_record_value().is_empty());

	let (pem2, _) = super::super::generate_key().expect("key2");
	let path2 = dir.path().join("b.key");
	std::fs::write(&path2, pem2).expect("write");
	let signer2 = std::sync::Arc::new(Signer::load("ed-b", &path2).expect("load2"));
	let before = handle.current().dns_record_value();
	handle.reload(signer2);
	// A fresh key changes the published public key.
	assert_ne!(handle.current().dns_record_value(), before);
}

mod tick_tests {
	use super::*;
	use std::pin::Pin;
	use std::sync::Mutex;

	use crate::dkim::generate_key;
	use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

	// `Op` and `ListOp` on the provider trait are private aliases; the
	// underlying type is spelled out here so the test module can implement
	// `DnsProvider` without reaching into `provider.rs`.
	type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
	type ListOp<'a> =
		Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

	/// An in-memory DNS provider that only records which TXT names it was asked
	/// to delete; writes and lists are no-ops.
	struct FakeProvider {
		deleted: Mutex<Vec<String>>,
	}

	impl DnsProvider for FakeProvider {
		fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
			Box::pin(async { Ok(()) })
		}

		fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
			let name = record.name;
			Box::pin(async move {
				self.deleted.lock().unwrap().push(name);
				Ok(())
			})
		}

		fn list(&self, _zone: &str) -> ListOp<'_> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	fn write_state(dir: &std::path::Path, state: &RotationState) {
		let bytes = serde_json::to_vec_pretty(state).expect("serialize state");
		std::fs::write(dir.join("dkim-rotation.json"), bytes).expect("write state");
	}

	/// Build a fully-loaded rotator against a tempdir with an active and a
	/// retired key file on disk, state.json pointing at them, and a live
	/// `Signer` over the active file.
	fn fixture() -> (
		tempfile::TempDir,
		std::path::PathBuf,
		std::path::PathBuf,
		Rotator,
		std::sync::Arc<FakeProvider>,
	) {
		let dir = tempfile::tempdir().expect("tempdir");
		let data_dir = dir.path().to_path_buf();
		let (pem, _) = generate_key().expect("key");

		let active_path = data_dir.join("dkim-ed-new.key");
		let retired_path = data_dir.join("dkim-ed-old.key");
		std::fs::write(&active_path, &pem).expect("write active");
		std::fs::write(&retired_path, &pem).expect("write retired");

		let signer =
			std::sync::Arc::new(Signer::load("ed-new", &active_path).expect("load active signer"));

		let provider = std::sync::Arc::new(FakeProvider {
			deleted: Mutex::new(Vec::new()),
		});
		let rotator = Rotator::new(
			data_dir.clone(),
			ReloadableSigner::new(signer),
			provider.clone(),
			"example.org".to_string(),
			"example.org".to_string(),
			30 * DAY,
			DAY,
		);

		write_state(
			&data_dir,
			&RotationState {
				selector: "ed-new".into(),
				key_file: active_path.clone(),
				rotated_at: 0,
				previous: Some(Previous {
					selector: "ed-old".into(),
					key_file: retired_path.clone(),
					retire_at: 100,
				}),
			},
		);
		(dir, active_path, retired_path, rotator, provider)
	}

	#[tokio::test]
	async fn retire_removes_retired_key_and_leaves_active_intact() {
		let (_dir, active_path, retired_path, rotator, provider) = fixture();

		let decision = rotator.tick(1_000).await.expect("tick");
		assert_eq!(decision, Decision::Retire("ed-old".into()));

		// DNS: the retired selector's TXT was sent to the provider.
		let deleted = provider.deleted.lock().unwrap().clone();
		assert!(
			deleted.iter().any(|n| n.starts_with("ed-old._domainkey")),
			"deleted: {deleted:?}"
		);
		assert!(
			!deleted.iter().any(|n| n.starts_with("ed-new._domainkey")),
			"active selector must not be retired: {deleted:?}"
		);

		// Disk: the retired file is gone, the active file is intact.
		assert!(!retired_path.exists(), "retired key file should be removed");
		assert!(active_path.exists(), "active key file must remain on disk");

		// State: previous cleared, active selector unchanged.
		let saved: RotationState = serde_json::from_slice(
			&std::fs::read(active_path.parent().unwrap().join("dkim-rotation.json")).unwrap(),
		)
		.unwrap();
		assert_eq!(saved.selector, "ed-new");
		assert_eq!(saved.key_file, active_path);
		assert!(saved.previous.is_none());
	}

	#[tokio::test]
	async fn retire_is_idempotent_when_key_file_already_missing() {
		let (_dir, active_path, retired_path, rotator, provider) = fixture();
		// The operator wiped the retired key file by hand; the rotation must
		// still complete successfully.
		std::fs::remove_file(&retired_path).expect("pre-delete retired file");

		let decision = rotator.tick(1_000).await.expect("tick");
		assert_eq!(decision, Decision::Retire("ed-old".into()));

		assert!(active_path.exists(), "active key file must remain on disk");
		let deleted = provider.deleted.lock().unwrap().clone();
		assert!(deleted.iter().any(|n| n.starts_with("ed-old._domainkey")));
	}

	#[tokio::test]
	async fn rotate_records_previous_key_file_for_later_retire() {
		// The fresh-bootstrap case writes a new key and leaves `previous`
		// empty. The recording-happens-on-rotate case is what subsequent
		// retires will rely on; this test pins that down.
		let dir = tempfile::tempdir().expect("tempdir");
		let data_dir = dir.path().to_path_buf();
		let (initial_pem, _) = generate_key().expect("key");

		let initial_path = data_dir.join("dkim-ed0.key");
		std::fs::write(&initial_path, &initial_pem).expect("write initial");
		let signer =
			std::sync::Arc::new(Signer::load("ed0", &initial_path).expect("load initial signer"));
		let provider = std::sync::Arc::new(FakeProvider {
			deleted: Mutex::new(Vec::new()),
		});
		let rotator = Rotator::new(
			data_dir.clone(),
			ReloadableSigner::new(signer),
			provider.clone(),
			"example.org".to_string(),
			"example.org".to_string(),
			30 * DAY,
			DAY,
		);
		write_state(
			&data_dir,
			&RotationState {
				selector: "ed0".into(),
				key_file: initial_path.clone(),
				rotated_at: 0,
				previous: None,
			},
		);

		// Day 31: interval has elapsed, so we Rotate to ed31.
		let decision = rotator.tick(31 * DAY).await.expect("tick");
		assert_eq!(decision, Decision::Rotate);

		// After the rotate, `previous` must carry the key path of the
		// selector being held for retirement.
		let saved: RotationState =
			serde_json::from_slice(&std::fs::read(data_dir.join("dkim-rotation.json")).unwrap())
				.unwrap();
		let prev = saved.previous.expect("rotate should record previous");
		assert_eq!(prev.selector, "ed0");
		assert_eq!(prev.key_file, initial_path);
	}
}
