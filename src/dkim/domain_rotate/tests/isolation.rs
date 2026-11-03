//! One domain's rotation touches only that domain: its records, its key
//! directory and its signer. A new selector never takes a name another key
//! may still be published under.

use std::sync::Arc;

use super::*;

use super::support::{DAY, INTERVAL, Zone, domain};

#[tokio::test]
async fn rotating_one_domain_leaves_another_untouched() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let b = domain(dir.path(), "b.example", &zone);
	let c = domain(dir.path(), "c.example", &zone);
	let c_record = zone.record(&c.name("own1"));
	b.rotator(&zone)
		.tick(b.made_at + INTERVAL)
		.await
		.expect("b rotates");
	assert!(
		zone.log()
			.iter()
			.all(|line| line.ends_with("._domainkey.b.example")),
		"only b.example's records are written: {:?}",
		zone.log()
	);
	assert_eq!(zone.record(&c.name("own1")), c_record);
	assert_eq!(c.signer.current().selector(), "own1");
	assert!(read_state(&c.dir()).expect("reads").is_none());
	assert!(c.verifies(&zone).await, "c.example still verifies");
	assert!(b.verifies(&zone).await, "b.example verifies on its new key");
	assert_ne!(
		b.signer.current().dns_record_value(),
		c.signer.current().dns_record_value(),
		"the two domains never end up on one key"
	);
}

#[tokio::test]
async fn a_new_selector_never_takes_a_reserved_name() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	let day_name = format!("own{}", now / DAY);
	// The `[dkim]` key happens to be published at this domain under the very
	// name the rotation would pick.
	let (_, shared) = crate::dkim::generate_key().expect("shared key");
	zone.records
		.lock()
		.unwrap()
		.insert(d.name(&day_name), shared.clone());
	d.rotator(&zone)
		.reserving(vec![day_name.clone()])
		.tick(now)
		.await
		.expect("rotates");
	assert_eq!(d.signer.current().selector(), format!("{day_name}x2"));
	assert_eq!(
		zone.record(&d.name(&day_name)),
		Some(shared),
		"the reserved record is not replaced"
	);
}

#[tokio::test]
async fn a_second_rotation_on_the_same_day_takes_another_name() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Arc::new(Zone::default());
	let d = domain(dir.path(), "b.example", &zone);
	let now = d.made_at + INTERVAL;
	d.rotator(&zone).force_rotate(now).await.expect("first");
	let first = d.state().selector;
	d.rotator(&zone)
		.with_windows(INTERVAL, 0)
		.force_rotate(now + 60)
		.await
		.expect("second");
	assert_ne!(d.state().selector, first);
	assert!(d.verifies(&zone).await);
}
