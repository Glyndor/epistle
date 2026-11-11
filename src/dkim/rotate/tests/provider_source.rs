//! The provider is built again at the start of every cycle, so a credential
//! that changed between two cycles is the one the next cycle writes with.

use super::request::{Dns, fixture};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const DAY: u64 = 86_400;

#[tokio::test]
async fn each_cycle_builds_the_provider_again_and_writes_with_the_new_one() {
	let mut f = fixture(false);
	let builds = Arc::new(AtomicUsize::new(0));
	// Each build is the provider of a different credential.
	let built: Arc<std::sync::Mutex<Vec<Arc<Dns>>>> = Arc::default();
	let source: ProviderSource = {
		let (builds, built) = (Arc::clone(&builds), Arc::clone(&built));
		Arc::new(move || {
			builds.fetch_add(1, Ordering::SeqCst);
			let next = Arc::new(Dns::default());
			built.lock().unwrap().push(Arc::clone(&next));
			Ok(next as Arc<dyn DnsProvider>)
		})
	};
	f.rotator = f.rotator.with_provider_source(source);
	assert_eq!(
		builds.load(Ordering::SeqCst),
		0,
		"nothing is built before a cycle"
	);

	request_rotation(f.dir.path(), 5 * DAY).expect("request");
	f.rotator.cycle(5 * DAY + 60, false).await.expect("cycle");
	f.rotator.cycle(6 * DAY, false).await.expect("second cycle");

	assert_eq!(builds.load(Ordering::SeqCst), 2, "one build per cycle");
	assert!(
		f.dns.upserts.lock().unwrap().is_empty(),
		"the provider the rotator was given is not used once a source replaces it"
	);
	let built = built.lock().unwrap();
	assert_eq!(
		built[0].upserts.lock().unwrap().len(),
		2,
		"the first cycle writes with the provider it built"
	);
	assert!(built[1].upserts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_cycle_whose_provider_cannot_be_built_writes_nothing() {
	let mut f = fixture(false);
	f.rotator = f.rotator.with_provider_source(Arc::new(|| {
		Err("the token_env variable X is not set".into())
	}));
	request_rotation(f.dir.path(), 5 * DAY).expect("request");

	f.rotator.cycle(5 * DAY + 60, false).await.expect("cycle");

	assert_eq!(
		f.signer.current().selector(),
		"ed0",
		"the key does not switch"
	);
	assert!(f.dns.upserts.lock().unwrap().is_empty());
	assert!(
		pending_request(f.dir.path()).is_some(),
		"the request stays for the next cycle"
	);
}
