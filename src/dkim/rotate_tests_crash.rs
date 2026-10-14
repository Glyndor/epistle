//! A rotation killed at any step leaves a state the next start completes
//! or rolls back: one active selector, its TXT published with the key on
//! disk, no TXT record and no key file that nothing names, and a signer
//! whose key receivers can look up, at the crash and after the restart.

use super::steps::Step;
use super::*;
use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::dkim::test_support::KeyDns;
use crate::dns::provider::ProviderError;
use crate::spf::{DnsFailure, DnsLookup};

pub(super) const DAY: u64 = 86_400;
pub(super) const NOW: u64 = 100 * DAY;
pub(super) const DOMAINS: [&str; 2] = ["example.org", "sub.example.org"];
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: crash\r\n\r\nHello\r\n";

/// The zone as the provider holds it. It outlives every restart.
#[derive(Default)]
pub(super) struct Zone {
	pub(super) records: Mutex<HashMap<String, Vec<String>>>,
	/// Refuse every delete while set.
	pub(super) refuse_deletes: AtomicBool,
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for Zone {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.records
			.lock()
			.unwrap()
			.insert(record.name, vec![record.value]);
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		if self.refuse_deletes.load(Ordering::SeqCst) {
			return Box::pin(async { Err(ProviderError::Remote("refused".into())) });
		}
		self.records.lock().unwrap().remove(&record.name);
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		let records = self
			.records
			.lock()
			.unwrap()
			.iter()
			.flat_map(|(name, values)| {
				values.iter().map(move |value| DnsRecord {
					name: format!("{name}."),
					kind: crate::dns::provider::RecordKind::Txt,
					value: value.clone(),
					ttl: 300,
					proxied: None,
				})
			})
			.collect();
		Box::pin(async move { Ok(records) })
	}
}

/// A resolver over the zone that answers nothing for its first `hidden`
/// queries, or never when `hidden` is `usize::MAX`.
pub(super) struct Resolver {
	pub(super) zone: Arc<Zone>,
	pub(super) hidden: usize,
	pub(super) queries: AtomicUsize,
}

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

impl DnsLookup for Resolver {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let query = self.queries.fetch_add(1, Ordering::Relaxed);
		let records = if query >= self.hidden {
			self.zone
				.records
				.lock()
				.unwrap()
				.get(name)
				.cloned()
				.unwrap_or_default()
		} else {
			Vec::new()
		};
		Box::pin(async move { Ok(records) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// What the zone and the data directory hold before the crash.
pub(super) enum Start {
	/// `ed0` is active and a rotation to `ed100` is due.
	RotationDue,
	/// `ed100` is active and `ed0` is past its overlap window.
	RetireDue,
}

/// How the resolver treats the new selector.
#[derive(Clone, Copy)]
pub(super) enum Visibility {
	/// The first query misses, so the rotator waits once, then it shows.
	AfterOneWait,
	/// The new selector never shows, so the rotation is withdrawn.
	Never,
}

pub(super) struct Lab {
	_dir: tempfile::TempDir,
	pub(super) root: PathBuf,
	pub(super) zone: Arc<Zone>,
}

impl Lab {
	pub(super) fn new(start: Start) -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let root = dir.path().to_path_buf();
		let zone = Arc::new(Zone::default());
		let lab = Lab {
			_dir: dir,
			root,
			zone,
		};
		let ed0 = lab.install_key("ed0", "ed0.key");
		let state = match start {
			Start::RotationDue => RotationState {
				selector: "ed0".into(),
				key_file: ed0,
				rotated_at: 0,
				previous: None,
				pending: None,
				rsa: None,
			},
			Start::RetireDue => RotationState {
				selector: "ed100".into(),
				key_file: lab.install_key("ed100", "dkim-ed100.key"),
				rotated_at: NOW - DAY,
				previous: Some(Previous {
					selector: "ed0".into(),
					key_file: ed0,
					retire_at: NOW - 1,
					rsa: None,
				}),
				pending: None,
				rsa: None,
			},
		};
		std::fs::write(
			lab.root.join(STATE_FILE),
			serde_json::to_vec(&state).expect("state JSON"),
		)
		.expect("write state");
		lab
	}

	/// Write a key file and publish its TXT under `selector` for every domain.
	pub(super) fn install_key(&self, selector: &str, file: &str) -> PathBuf {
		let (pem, record) = super::super::generate_key().expect("key");
		let path = self.root.join(file);
		std::fs::write(&path, pem).expect("write key");
		for domain in DOMAINS {
			self.zone.records.lock().unwrap().insert(
				format!("{selector}._domainkey.{domain}"),
				vec![record.clone()],
			);
		}
		path
	}

	/// A server process starting on the data directory: the signer it loads
	/// at startup and the rotator around it.
	pub(super) fn start(&self, visibility: Visibility) -> (ReloadableSigner, Rotator) {
		self.start_with(visibility, &DOMAINS)
	}

	/// [`Lab::start`] with the signing domains of a changed configuration.
	pub(super) fn start_with(
		&self,
		visibility: Visibility,
		domains: &[&str],
	) -> (ReloadableSigner, Rotator) {
		let active = active_ed25519(&unused_config(), &self.root).expect("active key at startup");
		let signer = ReloadableSigner::new(Arc::new(
			Signer::load(&active.selector, &active.key_file).expect("startup loads the active key"),
		));
		let hidden = match visibility {
			Visibility::AfterOneWait => 1,
			Visibility::Never => usize::MAX,
		};
		let resolver = Arc::new(Resolver {
			zone: self.zone.clone(),
			hidden,
			queries: AtomicUsize::new(0),
		});
		let rotator = Rotator::new(
			self.root.clone(),
			signer.clone(),
			self.zone.clone(),
			"example.org".into(),
			domains.iter().map(|d| d.to_string()).collect(),
			30 * DAY,
			2 * DAY,
		)
		.with_publication_check(resolver, vec![Duration::ZERO]);
		(signer, rotator)
	}

	/// Sign with `signer` and verify against the zone as it stands.
	pub(super) async fn assert_verifies(&self, signer: &ReloadableSigner, when: &str) {
		let header = signer.current().sign("example.org", RAW).expect("sign");
		let dns = KeyDns(self.zone.records.lock().unwrap().clone());
		let signed = [header.as_bytes(), RAW].concat();
		let results = crate::dkim::verify_message(&dns, &signed).await;
		assert_eq!(results.len(), 1, "{when}: one signature");
		assert_eq!(
			results[0].outcome,
			crate::dkim::DkimOutcome::Pass,
			"{when}: the signing key must be the one published"
		);
	}

	/// One active selector with its TXT and key, the previous one only when
	/// the state still holds it, nothing pending, nothing else anywhere.
	pub(super) async fn assert_settled(
		&self,
		signer: &ReloadableSigner,
		active: &str,
		previous: Option<&str>,
	) {
		let raw: serde_json::Value =
			serde_json::from_slice(&std::fs::read(self.root.join(STATE_FILE)).expect("state"))
				.expect("state JSON");
		assert!(
			raw.get("pending").is_none_or(serde_json::Value::is_null),
			"no rotation is left pending: {raw}"
		);
		let state = read_state(&self.root).expect("state").expect("state");
		assert_eq!(state.selector, active, "active selector");
		assert_eq!(
			state.previous.as_ref().map(|p| p.selector.as_str()),
			previous,
			"previous selector"
		);

		let mut keys = vec![self.root.join(&state.key_file)];
		keys.extend(state.previous.iter().map(|p| p.key_file.clone()));
		let expected: BTreeSet<String> = keys
			.iter()
			.map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
			.collect();
		let on_disk: BTreeSet<String> = std::fs::read_dir(&self.root)
			.expect("data dir")
			.map(|entry| {
				entry
					.expect("entry")
					.file_name()
					.to_string_lossy()
					.into_owned()
			})
			.filter(|name| name.ends_with(".key") || name.ends_with(".tmp"))
			.collect();
		assert_eq!(on_disk, expected, "key files on disk");

		let records = self.zone.records.lock().unwrap().clone();
		let names: BTreeSet<&String> = records.keys().collect();
		let selectors: Vec<&str> = std::iter::once(active).chain(previous).collect();
		let wanted: BTreeSet<String> = selectors
			.iter()
			.flat_map(|s| DOMAINS.iter().map(move |d| format!("{s}._domainkey.{d}")))
			.collect();
		assert_eq!(names, wanted.iter().collect(), "TXT records in the zone");
		let key = Signer::load(active, &self.root.join(&state.key_file)).expect("active key loads");
		for domain in DOMAINS {
			assert_eq!(
				records[&format!("{active}._domainkey.{domain}")],
				vec![key.dns_record_value()],
				"the TXT at {domain} is the active key"
			);
		}
		self.assert_verifies(signer, "after the restart").await;
	}
}

/// Only the `[dkim]` section matters to `active_ed25519`, and the state
/// file always exists in these tests.
pub(super) fn unused_config() -> crate::config::Dkim {
	toml::from_str("selector = \"configured\"\nkey_file = \"/nonexistent.key\"\n").expect("dkim")
}

/// Kill the rotator at `step` at [`NOW`] and check that what is signing
/// at that moment verifies.
pub(super) async fn crash(lab: &Lab, step: Step, visibility: Visibility) {
	let (signer, rotator) = lab.start(visibility);
	let crashed = rotator.crash_at(step).tick(NOW).await;
	assert!(
		crashed
			.as_ref()
			.is_err_and(|error| error.to_string().contains("crash injected")),
		"the rotator must reach {step:?} and stop with the injected crash"
	);
	lab.assert_verifies(&signer, "in the crashed process").await;
}

/// [`crash`], then start again, check that the startup signer verifies and
/// let one tick the next day finish the job.
pub(super) async fn crash_and_restart(
	lab: &Lab,
	step: Step,
	visibility: Visibility,
) -> ReloadableSigner {
	crash(lab, step, visibility).await;
	let (restarted, rotator) = lab.start(visibility);
	lab.assert_verifies(&restarted, "at the restart").await;
	// The next day, so a rotation begun again from scratch would pick
	// another selector and leave the first one's key and records behind.
	let _ = rotator.tick(NOW + DAY).await;
	restarted
}

macro_rules! completes {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = Lab::new(Start::RotationDue);
			let signer = crash_and_restart(&lab, $step, Visibility::AfterOneWait).await;
			lab.assert_settled(&signer, "ed100", Some("ed0")).await;
		}
	)*};
}

macro_rules! rolls_back {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = Lab::new(Start::RotationDue);
			let signer = crash_and_restart(&lab, $step, Visibility::Never).await;
			lab.assert_settled(&signer, "ed0", None).await;
		}
	)*};
}

macro_rules! retires {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = Lab::new(Start::RetireDue);
			let signer = crash_and_restart(&lab, $step, Visibility::AfterOneWait).await;
			lab.assert_settled(&signer, "ed100", None).await;
		}
	)*};
}

completes! {
	crash_after_journal_completes_rotation: Step::Journaled,
	crash_after_key_write_completes_rotation: Step::KeyWritten,
	crash_after_first_publish_completes_rotation: Step::Published(0),
	crash_after_last_publish_completes_rotation: Step::Published(1),
	crash_during_dns_wait_completes_rotation: Step::Waiting,
	crash_after_confirmation_completes_rotation: Step::Confirmed,
	crash_after_commit_keeps_rotation: Step::Committed,
	crash_after_signer_swap_keeps_rotation: Step::Swapped,
}

rolls_back! {
	crash_during_failing_dns_wait_rolls_back: Step::Waiting,
	crash_after_marking_withdrawal_rolls_back: Step::Withdrawing,
	crash_after_first_withdrawal_rolls_back: Step::WithdrawnRecord(0),
	crash_after_last_withdrawal_rolls_back: Step::WithdrawnRecord(1),
	crash_after_withdrawn_key_removal_rolls_back: Step::WithdrawnKey,
}

retires! {
	crash_after_first_retired_record_finishes_retirement: Step::RetiredRecord(0),
	crash_after_last_retired_record_finishes_retirement: Step::RetiredRecord(1),
	crash_after_retired_key_removal_finishes_retirement: Step::RetiredKey,
	crash_after_retired_state_save_finishes_retirement: Step::RetiredState,
}
