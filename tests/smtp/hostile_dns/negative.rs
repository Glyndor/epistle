//! NODATA and NXDOMAIN are distinct wire replies, but both represent absent
//! policy records here. They must not be conflated with SERVFAIL.

use epistle::dmarc::DmarcOutcome;
use epistle::spf::SpfOutcome;

use super::harness::*;
use super::wire::{Reply, Wire};

#[test]
fn spf_nodata_and_nxdomain_are_none() {
	// Mutation: NoRecordsFound => Err(Temporary) in SystemDns::lookup.
	bounded(async {
		for reply in [Reply::Nodata, Reply::Nxdomain] {
			let wire = Wire::tcp(reply).await;
			assert_eq!(spf(&wire.dns).await, SpfOutcome::None);
			wire.assert_queries();
		}
	});
}

#[test]
fn dmarc_nodata_and_nxdomain_are_none() {
	// Mutation: NoRecordsFound => Err(Temporary) in SystemDns::lookup.
	bounded(async {
		for reply in [Reply::Nodata, Reply::Nxdomain] {
			let wire = Wire::tcp(reply).await;
			assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::None);
			wire.assert_queries();
		}
	});
}

#[test]
fn mtasts_nodata_and_nxdomain_are_absent() {
	// Mutation: NoRecordsFound => Err(Temporary) in SystemDns::lookup.
	bounded(async {
		for reply in [Reply::Nodata, Reply::Nxdomain] {
			let wire = Wire::tcp(reply).await;
			assert_eq!(store().policy(&wire.dns, DOMAIN).await, Ok(None));
			wire.assert_queries();
		}
	});
}
