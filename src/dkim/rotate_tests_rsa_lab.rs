//! A data directory, a zone and a dual-signing server for the tests of
//! the RSA half of a rotation: [`super::tests_crash::Lab`] plus a
//! configured RSA key, and RSA keys made in process at test time.

use super::tests_crash::{DOMAINS, Lab, NOW, Resolver, Start, Visibility};
use super::*;
use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use crate::dkim::test_support::{KeyDns, rsa_verifies, signature_fields, signature_headers};

const DAY: u64 = 86_400;
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: dual\r\n\r\nHello\r\n";

/// The configured RSA selector and its key file inside the data directory.
pub(super) const CONFIGURED: &str = "rsa0";
const CONFIGURED_FILE: &str = "configured-rsa.key";

/// Three distinct 2048-bit RSA keys `(PEM, TXT value)`, made in process
/// once per test run. `Err` names why they could not be made.
pub(super) fn rsa_pool() -> Result<&'static [(String, String); 3], String> {
	static POOL: OnceLock<Result<[(String, String); 3], String>> = OnceLock::new();
	POOL.get_or_init(|| {
		let make = || crate::dkim::generate_rsa_key(2048).map_err(|error| error.to_string());
		Ok([make()?, make()?, make()?])
	})
	.as_ref()
	.map_err(Clone::clone)
}

/// The generator a rotation under test calls: always the third pool key,
/// which no lab installs before a rotation.
pub(super) fn rotated_rsa() -> Result<(String, String), String> {
	rsa_pool().map(|pool| pool[2].clone())
}

/// Print why an RSA test did not run. It does not count as a pass: the
/// output says what was not exercised.
pub(super) fn skipped(reason: &str) {
	eprintln!("skip: no RSA key could be generated ({reason}); the RSA rotation was not exercised");
}

pub(super) struct RsaLab {
	pub(super) lab: Lab,
}

impl RsaLab {
	/// [`Lab::new`] with the configured RSA key published. With
	/// [`Start::RetireDue`] the state also names a rotated RSA key `rsa100`
	/// in service and a retired `rsa50` beside `ed0`.
	pub(super) fn new(start: Start) -> Result<Self, String> {
		let pool = rsa_pool()?;
		let retire_due = matches!(start, Start::RetireDue);
		let lab = RsaLab {
			lab: Lab::new(start),
		};
		lab.install(CONFIGURED, CONFIGURED_FILE, &pool[0]);
		if retire_due {
			let active = lab.install("rsa100", "dkim-rsa100.key", &pool[1]);
			let retired = lab.install("rsa50", "dkim-rsa50.key", &pool[2]);
			let mut state = read_state(&lab.lab.root).expect("state").expect("state");
			state.rsa = Some(RsaKey {
				selector: "rsa100".into(),
				key_file: active,
			});
			let previous = state.previous.as_mut().expect("previous");
			previous.rsa = Some(RsaKey {
				selector: "rsa50".into(),
				key_file: retired,
			});
			lab.write_state(&state);
		}
		Ok(lab)
	}

	pub(super) fn root(&self) -> &std::path::Path {
		&self.lab.root
	}

	pub(super) fn write_state(&self, state: &RotationState) {
		std::fs::write(
			self.root().join(STATE_FILE),
			serde_json::to_vec(state).expect("state JSON"),
		)
		.expect("write state");
	}

	/// Write an RSA key file and publish its TXT under `selector`.
	fn install(&self, selector: &str, file: &str, key: &(String, String)) -> PathBuf {
		let path = self.root().join(file);
		std::fs::write(&path, &key.0).expect("write RSA key");
		for domain in DOMAINS {
			self.lab.zone.records.lock().unwrap().insert(
				format!("{selector}._domainkey.{domain}"),
				vec![key.1.clone()],
			);
		}
		path
	}

	/// The `[dkim]` section of a dual-signing configuration.
	pub(super) fn config(&self) -> crate::config::Dkim {
		toml::from_str(&format!(
			"selector = \"configured\"\nkey_file = \"/nonexistent.key\"\nrsa_selector = \"{CONFIGURED}\"\nrsa_key_file = \"{}\"\n",
			self.root().join(CONFIGURED_FILE).display()
		))
		.expect("dkim")
	}

	/// A server starting on the data directory, dual-signing with the keys
	/// [`active_ed25519`] and [`active_rsa`] name, or with ed25519 only
	/// when `dual` is false (the operator turned RSA off).
	pub(super) fn start(&self, visibility: Visibility, dual: bool) -> (ReloadableSigner, Rotator) {
		let config = self.config();
		let active = active_ed25519(&config, self.root()).expect("active ed25519 key");
		let mut signer =
			Signer::load(&active.selector, &active.key_file).expect("the ed25519 key loads");
		if dual {
			let rsa = active_rsa(&config, self.root())
				.expect("active RSA key")
				.expect("dual signing is configured");
			signer = signer
				.with_rsa(&rsa.selector, &rsa.key_file)
				.expect("the RSA key loads");
		}
		let signer = ReloadableSigner::new(Arc::new(signer));
		let hidden = match visibility {
			Visibility::AfterOneWait => 1,
			Visibility::Never => usize::MAX,
		};
		let resolver = Arc::new(Resolver {
			zone: self.lab.zone.clone(),
			hidden,
			queries: AtomicUsize::new(0),
		});
		let rotator = Rotator::new(
			self.root().to_path_buf(),
			signer.clone(),
			self.lab.zone.clone(),
			"example.org".into(),
			DOMAINS.iter().map(|d| d.to_string()).collect(),
			30 * DAY,
			2 * DAY,
		)
		.with_publication_check(resolver, vec![Duration::ZERO])
		.with_rsa_keygen(rotated_rsa);
		(signer, rotator)
	}

	/// Sign with both keys and verify both signatures against the zone.
	pub(super) async fn assert_verifies(
		&self,
		signer: &ReloadableSigner,
		ed: &str,
		rsa: &str,
		when: &str,
	) {
		let header = signer.current().sign("example.org", RAW).expect("sign");
		let signed = [header.as_bytes(), RAW].concat();
		let selectors: Vec<String> = signature_fields(&signed)
			.into_iter()
			.map(|(selector, _, _)| selector)
			.collect();
		assert_eq!(selectors, [ed, rsa], "{when}: the selectors that sign");
		let records = self.lab.zone.records.lock().unwrap().clone();
		let lines = signature_headers(header.as_bytes());
		let ed_signed = [lines[0].as_bytes(), RAW].concat();
		let results = crate::dkim::verify_message(&KeyDns(records.clone()), &ed_signed).await;
		assert_eq!(
			results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
			[crate::dkim::DkimOutcome::Pass],
			"{when}: the ed25519 key must be the one published"
		);
		let published = records
			.get(&format!("{rsa}._domainkey.example.org"))
			.and_then(|values| values.first())
			.cloned()
			.unwrap_or_default();
		assert!(
			rsa_verifies(&lines[1], &published, RAW),
			"{when}: the RSA key must be the one published"
		);
	}

	/// The state names `ed` and the rotated RSA key `rsa` (the configured
	/// one when `None`), `previous` the retired pair; nothing is pending,
	/// and the zone and the data directory hold those keys plus the
	/// configured RSA key, nothing else.
	pub(super) async fn assert_settled(
		&self,
		signer: &ReloadableSigner,
		ed: &str,
		rsa: Option<&str>,
		previous: Option<(&str, Option<&str>)>,
	) {
		let state = read_state(self.root()).expect("state").expect("state");
		assert!(state.pending.is_none(), "no rotation is left pending");
		assert_eq!(state.selector, ed, "active ed25519 selector");
		assert_eq!(
			state.rsa.as_ref().map(|r| r.selector.as_str()),
			rsa,
			"active RSA selector in the state"
		);
		assert_eq!(
			state.previous.as_ref().map(|p| (
				p.selector.as_str(),
				p.rsa.as_ref().map(|r| r.selector.as_str())
			)),
			previous,
			"previous selectors"
		);
		let mut files = vec![self.root().join(&state.key_file)];
		files.extend(state.rsa.iter().map(|r| self.root().join(&r.key_file)));
		if let Some(p) = &state.previous {
			files.push(p.key_file.clone());
			files.extend(p.rsa.iter().map(|r| r.key_file.clone()));
		}
		files.push(self.root().join(CONFIGURED_FILE));
		let expected: BTreeSet<String> = files
			.iter()
			.map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
			.collect();
		let on_disk: BTreeSet<String> = std::fs::read_dir(self.root())
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

		let mut selectors = vec![ed, rsa.unwrap_or(CONFIGURED), CONFIGURED];
		if let Some((old_ed, old_rsa)) = previous {
			selectors.push(old_ed);
			selectors.extend(old_rsa);
		}
		let wanted: BTreeSet<String> = selectors
			.iter()
			.flat_map(|s| DOMAINS.iter().map(move |d| format!("{s}._domainkey.{d}")))
			.collect();
		let records = self.lab.zone.records.lock().unwrap().clone();
		let names: BTreeSet<String> = records.keys().cloned().collect();
		assert_eq!(names, wanted, "TXT records in the zone");
		if let Some(rsa) = &state.rsa {
			let value = crate::dkim::rsa_record_value(&self.root().join(&rsa.key_file))
				.expect("RSA key loads");
			for domain in DOMAINS {
				assert!(
					records[&format!("{}._domainkey.{domain}", rsa.selector)]
						== vec![value.clone()],
					"the RSA TXT at {domain} is the active RSA key"
				);
			}
		}
		self.assert_verifies(signer, ed, rsa.unwrap_or(CONFIGURED), "settled")
			.await;
	}
}

/// Kill a dual-signing rotator at `step` at [`NOW`], check that what signs
/// then verifies, start again and let a tick the next day finish the job.
pub(super) async fn crash_and_restart(
	lab: &RsaLab,
	step: super::steps::Step,
	visibility: Visibility,
) -> ReloadableSigner {
	let (signer, rotator) = lab.start(visibility, true);
	let before = signer.current();
	let crashed = rotator.crash_at(step).tick(NOW).await;
	assert!(
		crashed
			.as_ref()
			.is_err_and(|error| error.to_string().contains("crash injected")),
		"the rotator must reach {step:?} and stop with the injected crash"
	);
	let current = signer.current();
	let (ed, rsa) = (current.selector(), current.rsa_selector().expect("RSA"));
	lab.assert_verifies(&signer, ed, rsa, "in the crashed process")
		.await;
	assert_eq!(
		(ed == before.selector()),
		(rsa == before.rsa_selector().expect("RSA")),
		"both keys switch together or neither does"
	);
	let (restarted, rotator) = lab.start(visibility, true);
	let current = restarted.current();
	let (ed, rsa) = (current.selector(), current.rsa_selector().expect("RSA"));
	lab.assert_verifies(&restarted, ed, rsa, "at the restart")
		.await;
	let _ = rotator.tick(NOW + DAY).await;
	restarted
}
