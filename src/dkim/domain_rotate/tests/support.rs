//! A zone in memory that is both the publisher and the resolver of a
//! rotation, and the domain fixtures the tests share.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::*;
use crate::dkim::rotate::Step;
use crate::dkim::{DkimOutcome, Signer, verify_message};
use crate::spf::{DnsFailure, DnsLookup};

pub(super) const DAY: u64 = 86_400;
/// Interval and overlap of the test rotators.
pub(super) const INTERVAL: u64 = 30 * DAY;
pub(super) const OVERLAP: u64 = 5 * DAY;

/// One zone: what was published, and what the resolver is made to see.
#[derive(Default)]
pub(super) struct Zone {
	pub records: Mutex<HashMap<String, String>>,
	/// Names the resolver answers with nothing, whatever was published.
	pub hidden: Mutex<HashSet<String>>,
	/// Names the resolver answers with this value instead.
	pub forged: Mutex<HashMap<String, String>>,
	/// Every write, in order: `publish <name>` or `withdraw <name>`.
	pub log: Mutex<Vec<String>>,
	/// A publication to a name containing this is refused.
	pub refuse_publish: Mutex<Option<String>>,
}

impl Zone {
	pub(super) fn record(&self, name: &str) -> Option<String> {
		self.records.lock().unwrap().get(name).cloned()
	}

	pub(super) fn log(&self) -> Vec<String> {
		self.log.lock().unwrap().clone()
	}

	/// The published records as a resolver of signatures sees them.
	pub(super) fn key_dns(&self) -> crate::dkim::test_support::KeyDns {
		let records = self.records.lock().unwrap();
		crate::dkim::test_support::KeyDns(
			records
				.iter()
				.map(|(name, value)| (name.clone(), vec![value.clone()]))
				.collect(),
		)
	}
}

impl KeyPublisher for Zone {
	fn publish<'a>(&'a self, name: &'a str, value: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			if let Some(refused) = self.refuse_publish.lock().unwrap().as_deref()
				&& name.contains(refused)
			{
				return Err(format!("publish {name}: refused by the provider"));
			}
			self.log.lock().unwrap().push(format!("publish {name}"));
			self.records
				.lock()
				.unwrap()
				.insert(name.to_string(), value.to_string());
			Ok(())
		})
	}

	fn withdraw<'a>(&'a self, name: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			self.log.lock().unwrap().push(format!("withdraw {name}"));
			self.records.lock().unwrap().remove(name);
			Ok(())
		})
	}
}

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

impl DnsLookup for Zone {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let answer = if self.hidden.lock().unwrap().contains(name) {
			Vec::new()
		} else if let Some(forged) = self.forged.lock().unwrap().get(name) {
			vec![forged.clone()]
		} else {
			self.record(name).into_iter().collect()
		};
		Box::pin(async move { Ok(answer) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A hosted domain with a key of its own, as `domain add` leaves it.
#[derive(Clone)]
pub(super) struct Domain {
	pub data_dir: PathBuf,
	pub entry: crate::config::DkimDomain,
	pub signer: ReloadableSigner,
	/// When the configured key was made (its file's modification time).
	pub made_at: u64,
}

impl Domain {
	/// The domain's key directory.
	pub(super) fn dir(&self) -> PathBuf {
		state_dir(&self.data_dir, &self.entry.name).expect("key dir")
	}

	/// A rotator for the domain over `zone`, with no waits between lookups.
	pub(super) fn rotator(&self, zone: &Arc<Zone>) -> DomainRotator {
		DomainRotator::new(
			self.data_dir.clone(),
			self.entry.clone(),
			self.signer.clone(),
			Arc::clone(zone) as Arc<dyn KeyPublisher>,
			Arc::clone(zone) as Arc<dyn DnsLookup>,
			Vec::new(),
		)
		.expect("rotator")
		.with_windows(INTERVAL, OVERLAP)
	}

	/// [`Domain::rotator`] stopped at `step`.
	pub(super) fn crashing(&self, zone: &Arc<Zone>, step: Step) -> DomainRotator {
		self.rotator(zone).crash_at(step)
	}

	/// The saved state of the domain.
	pub(super) fn state(&self) -> crate::dkim::rotate::RotationState {
		read_state(&self.dir())
			.expect("state reads")
			.expect("state exists")
	}

	/// The record name of `selector` at this domain.
	pub(super) fn name(&self, selector: &str) -> String {
		format!("{selector}._domainkey.{}", self.entry.name)
	}

	/// Whether mail the live signer signs now verifies against `zone`.
	pub(super) async fn verifies(&self, zone: &Zone) -> bool {
		let raw = format!(
			"From: user@{}\r\nTo: x@remote.example\r\nSubject: hi\r\n\r\nbody\r\n",
			self.entry.name
		)
		.into_bytes();
		let header = self
			.signer
			.current()
			.sign(&self.entry.name, &raw)
			.expect("signs");
		let mut full = header.into_bytes();
		full.extend_from_slice(&raw);
		verify_message(&zone.key_dns(), &full)
			.await
			.iter()
			.all(|result| result.outcome == DkimOutcome::Pass)
	}
}

fn modified(path: &Path) -> u64 {
	std::fs::metadata(path)
		.and_then(|m| m.modified())
		.map(|t| {
			t.duration_since(std::time::UNIX_EPOCH)
				.expect("after the epoch")
				.as_secs()
		})
		.expect("mtime")
}

/// `name` with a fresh ed25519 key of its own under `data_dir`, its record
/// already published in `zone` under `own1`.
pub(super) fn domain(data_dir: &Path, name: &str, zone: &Zone) -> Domain {
	let dir = state_dir(data_dir, name).expect("key dir");
	std::fs::create_dir_all(&dir).expect("mkdir");
	let (pem, txt) = crate::dkim::generate_key().expect("key");
	let key_file = dir.join("ed25519.pem");
	std::fs::write(&key_file, pem).expect("write key");
	zone.records
		.lock()
		.unwrap()
		.insert(format!("own1._domainkey.{name}"), txt);
	let signer = Signer::load("own1", &key_file).expect("load");
	Domain {
		data_dir: data_dir.to_path_buf(),
		made_at: modified(&key_file),
		entry: crate::config::DkimDomain {
			name: name.to_string(),
			selector: "own1".into(),
			key_file,
			rsa_selector: None,
			rsa_key_file: None,
		},
		signer: ReloadableSigner::new(Arc::new(signer)),
	}
}
