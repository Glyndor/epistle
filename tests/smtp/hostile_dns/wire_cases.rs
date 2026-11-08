//! These tests exercise SystemDns too, rather than returning canned errors
//! from DnsLookup. A deadline, query ceiling and allocation ceiling bound
//! every evaluation. Transport errors must never become policy absence.

use epistle::dmarc::DmarcOutcome;
use epistle::mtasts::PolicyError;
use epistle::spf::SpfOutcome;

use super::harness::*;
use super::wire::{Reply, Wire};

// A CNAME loop ends in "no records" inside the resolver, which is the same as
// a domain that publishes nothing: absence, not a temporary failure.
#[test]
fn spf_cname_loop_is_none() {
	// Mutation: map NoRecordsFound to Err(Temporary) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Loop).await;
		assert_eq!(spf(&wire.dns).await, SpfOutcome::None);
		wire.assert_queries();
	});
}

#[test]
fn dmarc_cname_loop_is_none() {
	// Mutation: map NoRecordsFound to Err(Temporary) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Loop).await;
		assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::None);
		wire.assert_queries();
	});
}

#[test]
fn mtasts_cname_loop_is_absent() {
	// Mutation: map NoRecordsFound to Err(Temporary) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Loop).await;
		assert_eq!(store().policy(&wire.dns, DOMAIN).await, Ok(None));
		wire.assert_queries();
	});
}

#[test]
fn spf_truncated_without_tcp_is_temperror() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::truncated_without_tcp().await;
		assert_eq!(spf(&wire.dns).await, SpfOutcome::TempError);
		wire.assert_queries();
	});
}

#[test]
fn dmarc_truncated_without_tcp_is_temperror() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::truncated_without_tcp().await;
		assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::TempError);
		wire.assert_queries();
	});
}

#[test]
fn mtasts_truncated_without_tcp_is_temporary() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::truncated_without_tcp().await;
		assert_eq!(
			store().policy(&wire.dns, DOMAIN).await,
			Err(PolicyError::Temporary("TXT lookup failed".into()))
		);
		wire.assert_queries();
	});
}

#[test]
fn spf_large_wire_txt_is_permerror() {
	// Mutation: map SPF record::parse errors to TempError.
	bounded(async {
		let wire = Wire::tcp(Reply::LargeTxt).await;
		assert_eq!(spf(&wire.dns).await, SpfOutcome::PermError);
		wire.assert_queries();
	});
}

#[test]
fn dmarc_large_wire_txt_is_permerror() {
	// Mutation: map malformed DMARC records to TempError.
	bounded(async {
		let wire = Wire::tcp(Reply::LargeTxt).await;
		assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::PermError);
		wire.assert_queries();
	});
}

#[test]
fn mtasts_large_wire_txt_with_invalid_id_is_absent() {
	// Mutation: return Temporary instead of the discovered id in observe_id.
	bounded(async {
		let wire = Wire::tcp(Reply::LargeTxt).await;
		assert_eq!(store().policy(&wire.dns, DOMAIN).await, Ok(None));
		wire.assert_queries();
	});
}

#[test]
fn spf_1000_wire_records_are_permerror() {
	// Mutation: disable the second-record guard in SPF fetch_record.
	bounded(async {
		let wire = Wire::tcp(Reply::Thousand).await;
		assert_eq!(spf(&wire.dns).await, SpfOutcome::PermError);
		wire.assert_queries();
	});
}

#[test]
fn dmarc_1000_wire_records_are_none() {
	// Mutation: disable the second-record guard in DMARC lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Thousand).await;
		assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::None);
		wire.assert_queries();
	});
}

#[test]
fn mtasts_1000_wire_records_are_absent() {
	// Mutation: return Temporary instead of the discovered id in observe_id.
	bounded(async {
		let wire = Wire::tcp(Reply::Thousand).await;
		assert_eq!(store().policy(&wire.dns, DOMAIN).await, Ok(None));
		wire.assert_queries();
	});
}

#[test]
fn spf_servfail_is_not_absence() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Servfail).await;
		assert_eq!(spf(&wire.dns).await, SpfOutcome::TempError);
		wire.assert_queries();
	});
}

#[test]
fn dmarc_servfail_is_not_absence() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Servfail).await;
		assert_eq!(dmarc(&wire.dns).await, DmarcOutcome::TempError);
		wire.assert_queries();
	});
}

#[test]
fn mtasts_servfail_is_not_absence() {
	// Mutation: map Err(_) to Ok(Vec::new()) in SystemDns::lookup.
	bounded(async {
		let wire = Wire::tcp(Reply::Servfail).await;
		assert_eq!(
			store().policy(&wire.dns, DOMAIN).await,
			Err(PolicyError::Temporary("TXT lookup failed".into()))
		);
		wire.assert_queries();
	});
}
