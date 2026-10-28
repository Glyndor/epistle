//! A rotated key signs only once DNS shows its TXT record with the right
//! key. A provider that accepted the write is not proof: until a resolver
//! sees the record, receivers cannot verify the new signatures.

use super::*;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::dns::provider::ProviderError;
use crate::spf::{DnsFailure, DnsLookup};

const DAY: u64 = 86_400;
const NOW: u64 = 100 * DAY;
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: rotation\r\n\r\nHello\r\n";

/// The zone as the provider holds it.
#[derive(Default)]
struct Zone {
	records: Mutex<HashMap<String, Vec<String>>>,
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
		self.records.lock().unwrap().remove(&record.name);
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// How the resolver behaves towards the published zone.
enum View {
	/// Answers from the zone from the given query on (0-based).
	From(usize),
	/// Never sees a record.
	Never,
	/// Sees a record at the name, with someone else's key.
	WrongKey,
}

struct Resolver {
	zone: Arc<Zone>,
	view: View,
	queries: AtomicUsize,
}

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

impl DnsLookup for Resolver {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let query = self.queries.fetch_add(1, Ordering::Relaxed);
		let published = self.zone.records.lock().unwrap().get(name).cloned();
		let records = match self.view {
			View::From(first) if query >= first => published.unwrap_or_default(),
			View::WrongKey if published.is_some() => {
				vec!["v=DKIM1; k=ed25519; p=c29tZW9uZSBlbHNl".to_string()]
			}
			_ => Vec::new(),
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

struct Fixture {
	dir: tempfile::TempDir,
	signer: ReloadableSigner,
	rotator: Rotator,
	zone: Arc<Zone>,
	resolver: Arc<Resolver>,
}

fn fixture(view: View) -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let (pem, record) = super::super::super::generate_key().expect("key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("ed0", &key_file).expect("load")));
	let zone = Arc::new(Zone::default());
	zone.records
		.lock()
		.unwrap()
		.insert("ed0._domainkey.example.org".into(), vec![record]);
	let resolver = Arc::new(Resolver {
		zone: Arc::clone(&zone),
		view,
		queries: AtomicUsize::new(0),
	});
	let rotator = Rotator::new(
		root.clone(),
		signer.clone(),
		zone.clone(),
		"example.org".into(),
		vec!["example.org".into()],
		30 * DAY,
		DAY,
	)
	.with_publication_check(
		resolver.clone(),
		vec![Duration::from_secs(30), Duration::from_secs(60)],
	);
	let state = RotationState {
		selector: "ed0".into(),
		key_file,
		rotated_at: 0,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		root.join(STATE_FILE),
		serde_json::to_vec(&state).expect("state"),
	)
	.expect("write state");
	Fixture {
		dir,
		signer,
		rotator,
		zone,
		resolver,
	}
}

/// The selector the live signer puts in `s=`.
fn signing_selector(signer: &ReloadableSigner) -> String {
	let header = signer.current().sign("example.org", RAW).expect("sign");
	crate::dkim::test_support::signature_fields(&[header.as_bytes(), RAW].concat())[0]
		.0
		.clone()
}

#[tokio::test(start_paused = true)]
async fn a_key_that_never_appears_in_dns_never_signs() {
	let f = fixture(View::Never);
	let new_selector = selector_for(NOW);

	let result = f.rotator.tick(NOW).await;

	assert!(result.is_err(), "the rotation must report the failure");
	assert_eq!(signing_selector(&f.signer), "ed0");
	assert_eq!(read_state(f.dir.path()).unwrap().unwrap().selector, "ed0");
	// One immediate query and one after each wait.
	assert_eq!(f.resolver.queries.load(Ordering::Relaxed), 3);
	// Nothing left half done: the unconfirmed record and key are gone.
	let records = f.zone.records.lock().unwrap().clone();
	assert!(
		!records.contains_key(&format!("{new_selector}._domainkey.example.org")),
		"{:?}",
		records.keys()
	);
	assert!(
		!f.dir
			.path()
			.join(format!("dkim-{new_selector}.key"))
			.exists()
	);
	// The operator sees why in `epistle dkim show`.
	let error = last_error(f.dir.path()).expect("error recorded");
	assert!(error.contains(&new_selector), "{error}");
}

#[tokio::test(start_paused = true)]
async fn someone_elses_key_at_the_name_is_not_publication() {
	let f = fixture(View::WrongKey);
	assert!(f.rotator.tick(NOW).await.is_err());
	assert_eq!(signing_selector(&f.signer), "ed0");
}

#[tokio::test(start_paused = true)]
async fn a_key_that_shows_up_late_signs_once_seen() {
	let f = fixture(View::From(2));
	assert_eq!(f.rotator.tick(NOW).await.expect("tick"), Decision::Rotate);
	assert_eq!(f.resolver.queries.load(Ordering::Relaxed), 3);
	assert_eq!(signing_selector(&f.signer), selector_for(NOW));
	assert_eq!(
		read_state(f.dir.path()).unwrap().unwrap().selector,
		selector_for(NOW)
	);
}

#[tokio::test]
async fn a_withdrawn_rotation_reaches_the_webhook() {
	use axum::extract::State;
	type Seen = Arc<Mutex<Vec<String>>>;
	async fn hook(State(seen): State<Seen>, body: String) -> &'static str {
		seen.lock().unwrap().push(body);
		"ok"
	}
	let seen: Seen = Arc::default();
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(hook))
		.with_state(Arc::clone(&seen));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let url = format!("http://{}/hook", listener.local_addr().expect("addr"));
	tokio::spawn(async move { axum::serve(listener, app).await });

	let f = fixture(View::Never);
	let webhook = crate::webhook::Webhook::new(&url, None).expect("webhook");
	let rotator = f
		.rotator
		.with_publication_check(f.resolver.clone(), Vec::new())
		.with_webhook(Arc::new(webhook));
	assert!(rotator.tick(NOW).await.is_err());
	let bodies = seen.lock().unwrap().clone();
	assert_eq!(bodies.len(), 1, "{bodies:?}");
	let event: serde_json::Value = serde_json::from_str(&bodies[0]).expect("json");
	assert_eq!(event["event"], "dkim_rotation_failed");
	assert_eq!(event["selector"], selector_for(NOW).as_str());
	assert_eq!(signing_selector(&f.signer), "ed0");
}

#[allow(unused_imports)]
use super::super::rsa;
