//! `TLS-Required: No` (RFC 8689 section 3): the sender asks that the
//! message be delivered even when the recipient's MTA-STS or DANE policy
//! would refuse an unverified connection, for instance to report a broken
//! certificate to the people who run it. STARTTLS is still used when the
//! MX offers it.
//!
//! Only a local sender may ask for that. Inbound mail loses the field when
//! it enters the routing sink, so a third party cannot downgrade our policy
//! for a copy we forward; what is left on a queued message came from one of
//! our own accounts. REQUIRETLS on the same message wins: RFC 8689 section
//! 4.1 says the field is then ignored.

use crate::smtp::trace::{header_values, strip_headers};

/// The header field name, as RFC 8689 registers it.
const FIELD: &str = "tls-required";

/// Whether `data` asks for TLS to be optional: exactly one `TLS-Required`
/// field (section 3 allows no more), with the value `No`.
pub(crate) fn optional(data: &[u8]) -> bool {
	matches!(header_values(data, FIELD).as_slice(), [value] if value.eq_ignore_ascii_case("no"))
}

/// `data` without any `TLS-Required` field, for mail from elsewhere.
pub(crate) fn strip(data: Vec<u8>) -> Vec<u8> {
	if header_values(&data, FIELD).is_empty() {
		return data;
	}
	strip_headers(&data, &[FIELD])
}
