//! Taking a record out of a zone without taking somebody else's with it.
//!
//! The provider contract has two ways to remove a record. The ordinary
//! [`DnsProvider::delete`] follows the write rule: a tagged TXT takes every
//! TXT of the same purpose at the name with it, and another kind takes the
//! whole set at the name. [`DnsProvider::delete_exact`] removes one value
//! and nothing else, so a record another account wrote between the listing
//! and the removal survives.
//!
//! A provider that cannot match by value answers
//! [`ProviderError::Unsupported`]; there the ordinary delete is the only
//! removal it offers, and the window the exact delete closes stays open for
//! that provider.

use std::time::Duration;

use super::survey::within;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

/// Remove `record` from `zone`, one value at a time when the provider can.
///
/// The exact removal is asked for first: it is the only one that leaves a
/// record of somebody else's alone. A provider that cannot match by value
/// refuses it, and the ordinary delete removes the record the way the
/// provider's own contract says.
///
/// The answer says whether the removal was the exact one. It is not when the
/// provider could not match by value: the record went out without a
/// precondition, and one another account added in that moment went with it.
pub(super) async fn remove(
	provider: &dyn DnsProvider,
	zone: &str,
	record: &DnsRecord,
	timeout: Duration,
) -> Result<bool, ProviderError> {
	match within(timeout, provider.delete_exact(zone, record.clone())).await {
		// The provider cannot remove one value: the ordinary delete is
		// the removal it offers.
		Err(ProviderError::Unsupported) => within(timeout, provider.delete(zone, record.clone()))
			.await
			.map(|()| false),
		outcome => outcome.map(|()| true),
	}
}
