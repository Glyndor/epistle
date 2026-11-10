//! A name whose zone the provider cannot find: the run reads the others,
//! and nothing is retired for want of the name that was left out.

use super::run::{harness_two_zones, mx, publish, read_zones, spf};
use super::support::{holds, txt};
use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::DnsProvider;
use crate::dns::records::PublishRecord;

/// A provider that cannot say whether it holds one zone.
struct Dumb {
	inner: Zone,
	dumb: String,
}
impl DnsProvider for Dumb {
	fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.inner.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.inner.delete(zone, record)
	}
	fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
		self.inner.list(zone)
	}
	fn has_zone<'a>(&'a self, zone: &'a str) -> crate::dns::provider::ZoneOp<'a> {
		if zone == self.dumb {
			return Box::pin(async {
				Err(crate::dns::provider::ProviderError::Remote(
					"401 unauthorized".into(),
				))
			});
		}
		self.inner.has_zone(zone)
	}
}

/// Finding the zone of a name is a read too: a name whose zone the
/// provider cannot answer for (a rejected credential, the network) is
/// reported and left alone, and the other zones are published.
#[test]
fn a_name_whose_zone_cannot_be_found_does_not_stop_the_other_zones() {
	let h = harness_two_zones();
	let provider = Dumb {
		inner: Zone::default(),
		dumb: "other.net".to_string(),
	};
	let wanted = vec![
		PublishRecord {
			zone: "example.org".into(),
			record: spf(),
		},
		PublishRecord {
			zone: "other.net".into(),
			record: txt("other.net", "v=spf1 mx -all"),
		},
		PublishRecord {
			zone: "other.net".into(),
			record: txt("_dmarc.other.net", "v=DMARC1; p=none"),
		},
	];
	let survey = read_zones(&h, &provider, &wanted).expect("the other zone is read");
	assert_eq!(survey.failures.len(), 1, "{:#?}", survey.failures);
	assert_eq!(survey.failures[0].zone, "other.net");
	assert!(
		survey.failures[0].reason.contains("401 unauthorized"),
		"{}",
		survey.failures[0].reason
	);
	assert_eq!(survey.zones.len(), 1, "{:#?}", survey.zones);
	assert_eq!(survey.zones[0].plan.zone, "example.org");
	let report = publish(&h, &provider, survey);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert!(holds(&provider.inner.snapshot(), &spf()));
}

/// A name left out because its zone could not be found is a needed
/// record nobody listed this run: nothing may be retired as unneeded.
#[test]
fn an_unresolved_name_retires_nothing() {
	let h = harness_two_zones();
	let provider = Dumb {
		inner: Zone::default(),
		dumb: "other.net".to_string(),
	};
	let own = |record: &DnsRecord| PublishRecord {
		zone: "example.org".into(),
		record: record.clone(),
	};
	let first = read_zones(&h, &provider, &[own(&spf()), own(&mx())]).expect("first run");
	let report = publish(&h, &provider, first);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert!(holds(&provider.inner.snapshot(), &mx()));
	// The next run no longer asks for the MX, and a name of the other
	// zone cannot be placed: the MX stays, nothing is known to retire it.
	let wanted = vec![
		own(&spf()),
		PublishRecord {
			zone: "other.net".into(),
			record: txt("other.net", "v=spf1 mx -all"),
		},
	];
	let second = read_zones(&h, &provider, &wanted).expect("second run");
	let report = publish(&h, &provider, second);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert!(
		holds(&provider.inner.snapshot(), &mx()),
		"an incomplete needed set must not retire epistle's own record"
	);
}
