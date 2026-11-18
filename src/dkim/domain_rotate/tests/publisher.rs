//! The publisher over the `[dns]` providers: the zone a name goes to, and
//! one write at a time across the domains that share it.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// Records `<op> <zone> <name> <value>` for every call.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl DnsProvider for Recording {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let line = format!("upsert {zone} {} {}", record.name, record.value);
		Box::pin(async move {
			self.0.lock().unwrap().push(line);
			Ok(())
		})
	}

	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let line = format!("delete {zone} {} {}", record.name, record.value);
		Box::pin(async move {
			self.0.lock().unwrap().push(line);
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn publisher(provider: &Arc<Recording>) -> ProviderPublisher {
	ProviderPublisher::new(
		Arc::clone(provider) as Arc<dyn DnsProvider>,
		vec!["example.org".into(), "sub.example.org".into()],
	)
}

#[tokio::test]
async fn a_name_goes_to_the_longest_zone_that_holds_it() {
	let provider = Arc::new(Recording::default());
	let p = publisher(&provider);
	p.publish("own1._domainkey.sub.example.org", "v=DKIM1; p=A")
		.await
		.expect("publish");
	p.withdraw("own1._domainkey.example.org")
		.await
		.expect("withdraw");
	assert_eq!(
		*provider.0.lock().unwrap(),
		[
			"upsert sub.example.org own1._domainkey.sub.example.org v=DKIM1; p=A",
			"delete example.org own1._domainkey.example.org ",
		]
	);
}

#[tokio::test]
async fn a_name_in_no_zone_is_refused_and_nothing_is_written() {
	let provider = Arc::new(Recording::default());
	let p = publisher(&provider);
	let error = p
		.publish("own1._domainkey.other.net", "v=DKIM1; p=A")
		.await
		.expect_err("refused");
	assert!(error.contains("none of the [dns] zones"), "{error}");
	p.withdraw("own1._domainkey.other.net")
		.await
		.expect_err("refused");
	assert!(provider.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_write_waits_for_the_lock_shared_with_other_domains() {
	let provider = Arc::new(Recording::default());
	let writes = Arc::new(tokio::sync::Mutex::new(()));
	let p = Arc::new(publisher(&provider).sharing_writes(Arc::clone(&writes)));
	let held = writes.lock().await;
	let task = {
		let p = Arc::clone(&p);
		tokio::spawn(async move {
			p.publish("own1._domainkey.example.org", "v=DKIM1; p=A")
				.await
		})
	};
	tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	assert!(
		provider.0.lock().unwrap().is_empty(),
		"no write while another domain holds the lock"
	);
	drop(held);
	task.await.expect("task").expect("publish");
	assert_eq!(provider.0.lock().unwrap().len(), 1);
}

/// Through a provider that checks a precondition, the DKIM record at the
/// name is replaced and a TXT of another purpose there stays, on publish and
/// on withdrawal.
#[tokio::test]
async fn a_guarded_provider_keeps_the_txt_of_another_purpose() {
	use crate::dns::provider::RecordKind;
	use crate::dns::publish::FakeGuardedProvider;
	const NAME: &str = "own1._domainkey.example.org";
	let txt = |value: &str| DnsRecord::new(NAME, RecordKind::Txt, value, 300);
	let provider = Arc::new(FakeGuardedProvider::holding(vec![
		txt("v=DKIM1; p=OLD"),
		txt("verification=abc"),
	]));
	let p = ProviderPublisher::new(
		Arc::clone(&provider) as Arc<dyn DnsProvider>,
		vec!["example.org".into()],
	);
	let values = || {
		let mut values: Vec<String> = provider.records().into_iter().map(|r| r.value).collect();
		values.sort();
		values
	};
	p.publish(NAME, "v=DKIM1; p=NEW").await.expect("publish");
	assert_eq!(values(), ["v=DKIM1; p=NEW", "verification=abc"]);
	p.withdraw(NAME).await.expect("withdraw");
	assert_eq!(values(), ["verification=abc"]);
}

/// A publisher over a live provider writes through the provider of the
/// current cycle: one built again from the source after a refresh, and the
/// one built before when the source fails.
#[tokio::test]
async fn a_live_publisher_writes_through_the_provider_of_the_cycle() {
	use crate::dns::provider::live::LiveProvider;
	let first = Arc::new(Recording::default());
	let second = Arc::new(Recording::default());
	let builds = Arc::new(Mutex::new(vec![
		Err("the token file is not readable".to_string()),
		Ok(Arc::clone(&second) as Arc<dyn DnsProvider>),
	]));
	let source = {
		let builds = Arc::clone(&builds);
		Arc::new(move || builds.lock().unwrap().pop().expect("a build"))
	};
	let live = Arc::new(LiveProvider::from_source(
		Arc::clone(&first) as Arc<dyn DnsProvider>,
		source,
	));
	let p = ProviderPublisher::live(live, vec!["example.org".into()]);
	p.publish("own1._domainkey.example.org", "v=DKIM1; p=A")
		.await
		.expect("publish");
	p.refresh();
	p.publish("own2._domainkey.example.org", "v=DKIM1; p=B")
		.await
		.expect("publish");
	p.refresh();
	p.publish("own3._domainkey.example.org", "v=DKIM1; p=C")
		.await
		.expect("publish");
	assert_eq!(first.0.lock().unwrap().len(), 1, "before the first cycle");
	assert_eq!(
		*second.0.lock().unwrap(),
		[
			"upsert example.org own2._domainkey.example.org v=DKIM1; p=B",
			"upsert example.org own3._domainkey.example.org v=DKIM1; p=C",
		],
		"the build of the second cycle failed and the first one kept writing"
	);
}
