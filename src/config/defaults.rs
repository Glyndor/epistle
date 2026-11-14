//! The values the schema fills in when the file leaves a field out.

/// Default for
/// [`Config::masked_addresses_max`](crate::config::Config::masked_addresses_max).
/// Generous enough for the usual disposable-alias use cases (one address per
/// signup service); caps abuse before it can mint the whole 8-character
/// suffix space.
pub(super) fn default_masked_addresses_max() -> usize {
	100
}

/// Default for the identification switches that are on unless the operator
/// turns them off: a `Feedback-ID`, the bulk unsubscribe address, the list
/// id, `Auto-Submitted` on server-generated mail and `Organization`.
pub(super) fn default_yes() -> bool {
	true
}

/// Default for
/// [`Config::bulk_recipients`](crate::config::Config::bulk_recipients):
/// twenty-one recipients or more is bulk, the threshold
/// [`crate::smtp::identification::Policy`] ships.
pub(super) fn default_bulk_recipients() -> usize {
	crate::smtp::identification::DEFAULT_BULK_RECIPIENTS
}
