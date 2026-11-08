//! The migration adapter: the responses a source server sends.

use super::common::INPUT_CAP;

/// The responses a source server sends to `migrate imap`, read with the
/// bounded reader and handed to every parser the client calls: status lines
/// and response codes, CAPABILITY, LIST, NAMESPACE and FETCH. The source may
/// be compromised, or impersonated when the run skips certificate checks.
pub fn migrate_imap_response(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::migrate::imap::fuzzing::responses_for_fuzzing(raw);
}
