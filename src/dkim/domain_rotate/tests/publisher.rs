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
