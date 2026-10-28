//! The RSA half of a rotation outside the crash matrix: state files written
//! before RSA rotation existed, which RSA key is in service, a key that
//! cannot be made, a second rotation, and dual signing turned off.

use super::crash::{DOMAINS, NOW, Start, Visibility};
use super::rsa_lab::{CONFIGURED, RsaLab, skipped};
use super::steps::Step;
use super::*;

const DAY: u64 = 86_400;

fn dkim(rsa: bool) -> crate::config::Dkim {
	let mut text = "selector = 'cfg'\nkey_file = '/etc/mail/configured.key'\n".to_string();
	if rsa {
		text.push_str("rsa_selector = 'rsa-cfg'\nrsa_key_file = '/etc/mail/rsa.key'\n");
	}
	toml::from_str(&text).expect("dkim config")
}

/// A state as releases before RSA rotation wrote it, every optional part
/// present: no `rsa` field anywhere.
const OLD_STATE: &str = r#"{
  "selector": "ed200",
  "key_file": "dkim-ed200.key",
  "rotated_at": 17280000,
  "previous": {"selector": "ed100", "key_file": "/var/lib/epistle/dkim-ed100.key", "retire_at": 18489600},
  "pending": {"selector": "ed210", "key_file": "/var/lib/epistle/dkim-ed210.key", "domains": ["example.org"], "started_at": 18144000}
}"#;

#[test]
fn a_state_written_before_rsa_rotation_still_loads() {
	let dir = tempfile::tempdir().expect("directory");
	std::fs::write(dir.path().join(STATE_FILE), OLD_STATE).expect("state");
	let state = read_state(dir.path()).expect("loads").expect("present");
	assert_eq!(state.selector, "ed200");
	assert_eq!(state.rsa, None, "no RSA key was rotated");
	let previous = state.previous.as_ref().expect("previous");
	assert_eq!(previous.selector, "ed100");
	assert_eq!(previous.rsa, None);
	let pending = state.pending.as_ref().expect("pending");
	assert_eq!(pending.selector, "ed210");
	assert_eq!(
		pending.rsa, None,
		"the pending rotation covers ed25519 only"
	);

	let active = active_rsa(&dkim(true), dir.path())
		.expect("active")
		.expect("dual signing");
	assert_eq!(active.selector, "rsa-cfg", "the configured RSA key signs");
	assert_eq!(active.key_file, PathBuf::from("/etc/mail/rsa.key"));

	let written = serde_json::to_string(&state).expect("serialize");
	assert!(
		!written.contains("\"rsa\""),
		"a state without RSA keys is written as before, so an older release can read it back"
	);
}

#[test]
fn active_rsa_follows_the_state_once_a_rotation_named_one() {
	let dir = tempfile::tempdir().expect("directory");
	assert_eq!(
		active_rsa(&dkim(true), dir.path()).expect("active"),
		Some(ActiveKey {
			selector: "rsa-cfg".into(),
			key_file: "/etc/mail/rsa.key".into(),
		}),
		"without a state the configured key signs"
	);
	std::fs::write(
		dir.path().join(STATE_FILE),
		r#"{"selector":"ed7","key_file":"dkim-ed7.key","rotated_at":5,"previous":null,
		"rsa":{"selector":"rsa7","key_file":"dkim-rsa7.key"}}"#,
	)
	.expect("state");
	assert_eq!(
		active_rsa(&dkim(true), dir.path()).expect("active"),
		Some(ActiveKey {
			selector: "rsa7".into(),
			key_file: dir.path().join("dkim-rsa7.key"),
		}),
		"the rotated key signs, its path resolved against the data directory"
	);
	assert_eq!(
		active_rsa(&dkim(false), dir.path()).expect("active"),
		None,
		"without rsa_selector and rsa_key_file nothing signs with RSA"
	);
}

#[tokio::test]
async fn an_rsa_key_that_cannot_be_made_withdraws_the_whole_rotation() {
	let lab = match RsaLab::new(Start::RotationDue) {
		Ok(lab) => lab,
		Err(reason) => return skipped(&reason),
	};
	let (signer, rotator) = lab.start(Visibility::AfterOneWait, true);
	let rotator = rotator.with_rsa_keygen(|| Err("the key generator failed".to_string()));
	let error = rotator.tick(NOW).await.expect_err("withdrawn");
	assert!(
		error.to_string().contains("withdrawn")
			&& error.to_string().contains("generate the RSA key"),
		"the rotation is withdrawn because the RSA key could not be made"
	);
	lab.assert_settled(&signer, "ed0", None, None).await;
	let reported = std::fs::read_to_string(lab.root().join(ERROR_FILE)).expect("error file");
	assert!(
		reported.contains("generate the RSA key"),
		"`dkim show` can tell why"
	);
}

#[tokio::test]
async fn a_second_dual_rotation_retires_the_rotated_rsa_key() {
	let lab = match RsaLab::new(Start::RetireDue) {
		Ok(lab) => lab,
		Err(reason) => return skipped(&reason),
	};
	let (signer, rotator) = lab.start(Visibility::AfterOneWait, true);
	assert_eq!(
		rotator.tick(NOW).await.expect("retire"),
		Decision::Retire("ed0".into())
	);
	let later = NOW + 31 * DAY;
	assert_eq!(rotator.tick(later).await.expect("rotate"), Decision::Rotate);
	lab.assert_settled(
		&signer,
		"ed131",
		Some("rsa131"),
		Some(("ed100", Some("rsa100"))),
	)
	.await;
	assert_eq!(
		rotator.tick(later + 3 * DAY).await.expect("retire"),
		Decision::Retire("ed100".into())
	);
	lab.assert_settled(&signer, "ed131", Some("rsa131"), None)
		.await;
}

/// The signer signs with ed25519 alone, and with the selector `ed`.
fn assert_ed25519_only(signer: &ReloadableSigner, ed: &str) {
	let current = signer.current();
	assert_eq!(current.selector(), ed);
	assert_eq!(current.rsa_selector(), None, "nothing signs with RSA");
}

#[tokio::test]
async fn turning_dual_signing_off_retires_the_rotated_rsa_key() {
	let lab = match RsaLab::new(Start::RetireDue) {
		Ok(lab) => lab,
		Err(reason) => return skipped(&reason),
	};
	let (signer, rotator) = lab.start(Visibility::AfterOneWait, false);
	rotator.tick(NOW).await.expect("retire");
	rotator.tick(NOW + 31 * DAY).await.expect("rotate");
	assert_ed25519_only(&signer, "ed131");
	let state = read_state(lab.root()).expect("state").expect("state");
	assert_eq!(state.rsa, None, "the state stops naming an RSA key");
	let previous = state.previous.expect("previous");
	assert_eq!(
		previous.rsa.map(|rsa| rsa.selector),
		Some("rsa100".to_string()),
		"the rotated RSA key retires with the previous selector"
	);
	assert!(
		!lab.root().join("dkim-rsa131.key").exists(),
		"no RSA key is made without dual signing"
	);
}

#[tokio::test]
async fn dual_signing_turned_off_during_a_rotation_withdraws_it() {
	let lab = match RsaLab::new(Start::RotationDue) {
		Ok(lab) => lab,
		Err(reason) => return skipped(&reason),
	};
	let (_, rotator) = lab.start(Visibility::AfterOneWait, true);
	let crashed = rotator.crash_at(Step::RsaPublished(0)).tick(NOW).await;
	assert!(crashed.is_err_and(|e| e.to_string().contains("crash injected")));
	let (signer, rotator) = lab.start(Visibility::AfterOneWait, false);
	let error = rotator.tick(NOW + 60).await.expect_err("withdrawn");
	assert!(
		error.to_string().contains("turned off"),
		"withdrawn because dual signing was turned off"
	);
	assert_ed25519_only(&signer, "ed0");
	let names: Vec<String> = lab
		.lab
		.zone
		.records
		.lock()
		.unwrap()
		.keys()
		.cloned()
		.collect();
	assert!(
		names
			.iter()
			.all(|name| !name.starts_with("ed100.") && !name.starts_with("rsa100.")),
		"the withdrawn rotation leaves no record"
	);
	assert!(!lab.root().join("dkim-rsa100.key").exists());
	assert!(!lab.root().join("dkim-ed100.key").exists());
	rotator.tick(NOW + DAY).await.expect("ed25519 rotation");
	assert_ed25519_only(&signer, "ed101");
	assert!(
		lab.lab
			.zone
			.records
			.lock()
			.unwrap()
			.contains_key(&format!("{CONFIGURED}._domainkey.{}", DOMAINS[0])),
		"the configured RSA key's record is left alone"
	);
}

/// A resolver that shows every record of the zone except the RSA ones.
struct WithoutRsa(Arc<super::crash::Zone>);

type Lookup<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for WithoutRsa {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let records = if name.starts_with("rsa") {
			Vec::new()
		} else {
			self.0
				.records
				.lock()
				.unwrap()
				.get(name)
				.cloned()
				.unwrap_or_default()
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

#[tokio::test]
async fn an_rsa_key_dns_never_shows_withdraws_both_keys() {
	let lab = match RsaLab::new(Start::RotationDue) {
		Ok(lab) => lab,
		Err(reason) => return skipped(&reason),
	};
	let (signer, rotator) = lab.start(Visibility::AfterOneWait, true);
	let rotator = rotator.with_publication_check(
		Arc::new(WithoutRsa(lab.lab.zone.clone())),
		vec![std::time::Duration::ZERO],
	);
	let error = rotator.tick(NOW).await.expect_err("withdrawn");
	assert!(
		error.to_string().contains("rsa100._domainkey"),
		"withdrawn because the RSA record never showed"
	);
	lab.assert_settled(&signer, "ed0", None, None).await;
}

#[allow(unused_imports)]
use super::super::rsa;
