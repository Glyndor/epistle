//! A new key signs only once a resolver shows its record with that key.
//! Otherwise the rotation is taken back and the current key keeps signing.

use std::sync::Arc;

use super::*;

use super::support::{DAY, INTERVAL, Zone, domain};

#[tokio::test]
async fn a_record_the_resolver_never_shows_is_withdrawn_and_the_old_key_keeps_signing() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let selector = format!("own{}", now / DAY);
	zone.hidden.lock().unwrap().insert(d.name(&selector));
	let error = d.rotator(&zone).tick(now).await.expect_err("withdrawn");
	assert!(
		error.to_string().contains("does not show the new key"),
		"{error}"
	);
	assert_eq!(d.signer.current().selector(), "own1", "still the old key");
	assert!(d.verifies(&zone).await, "and mail still verifies");
	assert_eq!(
		zone.log(),
		[
			format!("publish {}", d.name(&selector)),
			format!("withdraw {}", d.name(&selector))
		]
	);
	assert!(zone.record(&d.name(&selector)).is_none());
	assert!(
		!d.dir().join(format!("{selector}.pem")).exists(),
		"the unused key file is removed"
	);
	assert!(
		read_state(&d.dir()).expect("reads").is_none(),
		"nothing is left in the journal"
	);
	let reason = last_error(&d.data_dir, "b.example").expect("the reason is kept");
	assert!(reason.contains("withdrawn"), "{reason}");
}

#[tokio::test]
async fn a_record_that_shows_another_key_does_not_confirm() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let selector = format!("own{}", now / DAY);
	let (_, other) = crate::dkim::generate_key().expect("another key");
	zone.forged.lock().unwrap().insert(d.name(&selector), other);
	d.rotator(&zone).tick(now).await.expect_err("withdrawn");
	assert_eq!(d.signer.current().selector(), "own1");
	assert!(zone.record(&d.name(&selector)).is_none());
}

#[tokio::test]
async fn a_refused_publication_switches_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	*zone.refuse_publish.lock().unwrap() = Some("own".into());
	let error = d
		.rotator(&zone)
		.tick(d.made_at + INTERVAL)
		.await
		.expect_err("withdrawn");
	assert!(
		error.to_string().contains("refused by the provider"),
		"{error}"
	);
	assert_eq!(d.signer.current().selector(), "own1");
	assert!(read_state(&d.dir()).expect("reads").is_none());
}

#[tokio::test]
async fn a_resolver_that_shows_the_record_late_still_confirms_it() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let name = d.name(&format!("own{}", now / DAY));
	zone.hidden.lock().unwrap().insert(name.clone());
	let rotator = DomainRotator::new(
		d.data_dir.clone(),
		d.entry.clone(),
		d.signer.clone(),
		Arc::clone(&zone) as Arc<dyn KeyPublisher>,
		Arc::clone(&zone) as Arc<dyn crate::spf::DnsLookup>,
		vec![std::time::Duration::from_millis(50)],
	)
	.expect("rotator")
	.with_windows(INTERVAL, DAY);
	let reveal = {
		let zone = Arc::clone(&zone);
		tokio::spawn(async move {
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
			zone.hidden.lock().unwrap().remove(&name);
		})
	};
	rotator
		.tick(now)
		.await
		.expect("confirmed on the second look");
	reveal.await.expect("revealed");
	assert_ne!(d.signer.current().selector(), "own1");
	assert!(d.verifies(&zone).await);
}
