//! A domain that dual-signs rotates both keys in one step: both published
//! and confirmed before either signs, both taken back when either fails.

use std::sync::Arc;

use super::*;

use super::support::{DAY, INTERVAL, Zone, domain};

/// `b.example` signing with an ed25519 and an RSA key of its own, both
/// published.
fn dual(dir: &std::path::Path, zone: &Zone) -> super::support::Domain {
	let mut d = domain(dir, "b.example", zone);
	let rsa_file = d.dir().join("rsa.pem");
	let (pem, txt) = crate::dkim::generate_rsa_key(2048).expect("rsa key");
	std::fs::write(&rsa_file, pem).expect("write rsa");
	zone.records.lock().unwrap().insert(d.name("ownrsa1"), txt);
	d.entry.rsa_selector = Some("ownrsa1".into());
	d.entry.rsa_key_file = Some(rsa_file.clone());
	let signer = crate::dkim::Signer::load("own1", &d.entry.key_file)
		.expect("ed")
		.with_rsa("ownrsa1", &rsa_file)
		.expect("rsa");
	d.signer = ReloadableSigner::new(Arc::new(signer));
	d
}

#[tokio::test]
async fn both_keys_rotate_together_and_both_signatures_verify() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = dual(dir.path(), &zone);
	let now = d.made_at + INTERVAL;
	d.rotator(&zone).tick(now).await.expect("rotates");
	let day = now / DAY;
	assert_eq!(d.signer.current().selector(), format!("own{day}"));
	assert_eq!(
		d.signer.current().rsa_selector(),
		Some(format!("ownrsa{day}").as_str())
	);
	assert!(d.verifies(&zone).await, "both signatures verify");
	let state = d.state();
	assert_eq!(
		state.rsa.map(|rsa| rsa.selector),
		Some(format!("ownrsa{day}"))
	);
	assert!(
		zone.record(&d.name("ownrsa1")).is_some(),
		"configured RSA kept"
	);
	let active = active_keys(&d.entry, &d.data_dir).expect("active");
	assert_eq!(
		active.rsa.map(|rsa| rsa.selector),
		Some(format!("ownrsa{day}"))
	);
}

#[tokio::test]
async fn an_rsa_record_that_never_shows_takes_both_keys_back() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = dual(dir.path(), &zone);
	let now = d.made_at + INTERVAL;
	let day = now / DAY;
	zone.hidden
		.lock()
		.unwrap()
		.insert(d.name(&format!("ownrsa{day}")));
	d.rotator(&zone).tick(now).await.expect_err("withdrawn");
	assert_eq!(d.signer.current().selector(), "own1");
	assert_eq!(d.signer.current().rsa_selector(), Some("ownrsa1"));
	assert!(zone.record(&d.name(&format!("own{day}"))).is_none());
	assert!(zone.record(&d.name(&format!("ownrsa{day}"))).is_none());
	assert!(d.verifies(&zone).await);
}

#[tokio::test]
async fn an_rsa_key_that_cannot_be_made_takes_the_rotation_back() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = dual(dir.path(), &zone);
	let error = d
		.rotator(&zone)
		.with_rsa_keygen(|| Err("no openssl".into()))
		.tick(d.made_at + INTERVAL)
		.await
		.expect_err("withdrawn");
	assert!(error.to_string().contains("no openssl"), "{error}");
	assert_eq!(d.signer.current().selector(), "own1");
	assert!(
		zone.log().iter().all(|line| line.starts_with("withdraw")),
		"nothing was published: {:?}",
		zone.log()
	);
	assert!(read_state(&d.dir()).expect("reads").is_none());
}
