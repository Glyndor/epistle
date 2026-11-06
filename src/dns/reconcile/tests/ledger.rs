//! What the ledger claims: only what epistle really published.

use super::run::{harness, publish, read};
use super::support::{holds, txt};
use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::DnsProvider;
use crate::dns::reconcile::store;

fn spf() -> DnsRecord {
	txt("example.org", "v=spf1 mx -all")
}

/// A write that failed must not leave a claim in the ledger: the ledger is
/// the only proof of ownership, and a record epistle never published would
/// be taken away from whoever published it later.
#[test]
fn a_write_that_failed_leaves_the_ledger_without_a_claim() {
	/// A provider that refuses every write: nothing goes out.
	struct Refuses(Zone);
	impl DnsProvider for Refuses {
		fn upsert(&self, _zone: &str, _record: DnsRecord) -> crate::dns::provider::Op<'_> {
			Box::pin(async {
				Err(crate::dns::provider::ProviderError::Remote(
					"the provider refused the write".into(),
				))
			})
		}
		fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
			self.0.delete(zone, record)
		}
		fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
			self.0.list(zone)
		}
	}
	let h = harness();
	let provider = Refuses(Zone::default());
	let report = publish(&h, &provider, read(&h, &provider, &[spf()]));
	assert!(report.failure.is_some(), "{:?}", report.failure);
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(
		ledger.entries.is_empty(),
		"the ledger must not claim a record that was never written: {:#?}",
		ledger.entries
	);
	// Another account publishes the same value, and the configuration no
	// longer needs it: the run must not take it away.
	provider.0.records.lock().unwrap().push(spf());
	let report = publish(&h, &provider, read(&h, &provider, &[]));
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert!(
		holds(&provider.0.snapshot(), &spf()),
		"a record of somebody else must stay"
	);
}
