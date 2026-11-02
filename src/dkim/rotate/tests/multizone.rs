//! Rotation across zones: each signing domain is published in, and retired
//! from, the zone that holds it, so a router can hand each call to the
//! credential of that zone.

use super::*;
use std::pin::Pin;
use std::sync::Mutex;

use crate::dns::provider::ProviderError;

const DAY: u64 = 86_400;

/// Remembers the zone every call named.
#[derive(Default)]
struct ZoneLog {
	upserts: Mutex<Vec<(String, String)>>,
	deletes: Mutex<Vec<(String, String)>>,
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for ZoneLog {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.upserts
			.lock()
			.unwrap()
			.push((zone.to_string(), record.name));
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.deletes
			.lock()
			.unwrap()
			.push((zone.to_string(), record.name));
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn rotator(log: Arc<ZoneLog>, zones: &[&str], domains: &[&str]) -> (tempfile::TempDir, Rotator) {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = super::super::super::generate_key().expect("ed25519 key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(
		Signer::load("ed0", &key_file).expect("load ed25519"),
	));
	let rotator = Rotator::new(
		root.clone(),
		signer,
		log,
		zones[0].to_string(),
		domains.iter().map(|s| s.to_string()).collect(),
		30 * DAY,
		DAY,
	)
	.with_zones(zones.iter().map(|s| s.to_string()).collect());
	let state = RotationState {
		selector: "ed0".into(),
		key_file,
		rotated_at: 0,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		root.join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	(dir, rotator)
}

#[tokio::test]
async fn each_domain_is_published_and_retired_in_its_own_zone() {
	let log = Arc::new(ZoneLog::default());
	let (_dir, rotator) = rotator(
		log.clone(),
		&["example.org", "client.net", "eu.example.org"],
		&[
			"example.org",
			"mail.example.org",
			"client.net",
			"eu.example.org",
		],
	);
	assert_eq!(rotator.tick(31 * DAY).await.unwrap(), Decision::Rotate);
	let upserts = log.upserts.lock().unwrap().clone();
	let zone_of = |name: &str| {
		upserts
			.iter()
			.find(|(_, written)| written == name)
			.map(|(zone, _)| zone.as_str())
	};
	assert_eq!(zone_of("ed31._domainkey.example.org"), Some("example.org"));
	assert_eq!(
		zone_of("ed31._domainkey.mail.example.org"),
		Some("example.org")
	);
	assert_eq!(zone_of("ed31._domainkey.client.net"), Some("client.net"));
	// The nested zone wins over its parent.
	assert_eq!(
		zone_of("ed31._domainkey.eu.example.org"),
		Some("eu.example.org")
	);

	let retire = 31 * DAY + ROTATE_OVERLAP_DAYS * DAY + 1;
	rotator.tick(retire).await.unwrap();
	let deletes = log.deletes.lock().unwrap().clone();
	assert!(deletes.contains(&("client.net".into(), "ed0._domainkey.client.net".into())));
	assert!(deletes.contains(&(
		"example.org".into(),
		"ed0._domainkey.mail.example.org".into()
	)));
}

/// A provider whose zones each hold one leftover DKIM record.
struct Leftovers;

impl DnsProvider for Leftovers {
	fn upsert(&self, _: &str, _: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, _: &str, _: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let name = format!("ed9._domainkey.{zone}");
		Box::pin(async move { Ok(vec![txt_record(&name, "v=DKIM1; k=ed25519; p=AAAA")]) })
	}
}

#[tokio::test]
async fn leftover_records_are_looked_for_in_every_zone() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let zones = ["example.org".to_string(), "client.net".to_string()];
	let found = find_orphans(
		dir.path(),
		Some(&Leftovers),
		&zones,
		&["example.org".to_string(), "client.net".to_string()],
		&[],
	)
	.await
	.expect("orphans");
	assert_eq!(
		found.records,
		vec![
			"ed9._domainkey.client.net".to_string(),
			"ed9._domainkey.example.org".to_string()
		]
	);
}
