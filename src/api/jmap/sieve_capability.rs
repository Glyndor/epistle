//! `urn:ietf:params:jmap:sieve` (RFC 9661 section 1.2.1): what the Session
//! says about Sieve scripts.
//!
//! Every number comes from the constant the store or the interpreter applies,
//! so what a client is told and what ManageSieve and JMAP enforce cannot
//! drift apart.

use serde_json::{Value, json};

use crate::managesieve::store::{MAX_NAME_BYTES, MAX_SCRIPT_BYTES, MAX_SCRIPTS};
use crate::sieve::interp::MAX_REDIRECTS;

/// The capability URN.
pub(super) const SIEVE_CAPABILITY: &str = "urn:ietf:params:jmap:sieve";

/// The value in the Session's `capabilities`: the implementation, by name and
/// version.
pub(super) fn session_value() -> Value {
	json!({ "implementation": concat!("epistle ", env!("CARGO_PKG_VERSION")) })
}

/// The value in each account's `accountCapabilities`.
///
/// `maxSizeScriptName` is below the 512 octets RFC 9661 asks for: a script
/// name is a file name, and 200 octets is the most that fits next to the
/// staging name of an atomic write.
pub(super) fn account_value() -> Value {
	json!({
		"maxSizeScriptName": MAX_NAME_BYTES,
		"maxSizeScript": MAX_SCRIPT_BYTES,
		"maxNumberScripts": MAX_SCRIPTS,
		"maxNumberRedirects": MAX_REDIRECTS,
		"sieveExtensions": crate::sieve::extensions().collect::<Vec<_>>(),
		"notificationMethods": null,
		"externalLists": null,
	})
}
