//! A script's content as a JMAP blob (RFC 9661 section 2.2).
//!
//! A `SieveScript` names its content by `blobId`, and a client downloads it
//! through the ordinary download URL. The blob is not a file of its own: its
//! id names one version of one script, `sieve-<script id>-<revision>`, and
//! the download reads that version out of the script store. A script that has
//! been rewritten since is a new blob id, and the old one is gone, as a blob
//! never changes under its id.

use std::path::Path;

use crate::managesieve::store::ScriptStore;

/// What every script blob id starts with.
const PREFIX: &str = "sieve-";

/// The media type a script is served as.
pub(super) const MEDIA_TYPE: &str = "application/sieve; charset=utf-8";

/// The store of `account`: the one ManageSieve uses.
pub(super) fn store(data_dir: &Path, account: &str) -> ScriptStore {
	ScriptStore::new(&data_dir.join("accounts"), account)
}

/// The blob id of version `rev` of the script `id`.
pub(super) fn blob_id(id: &str, rev: u64) -> String {
	format!("{PREFIX}{id}-{rev}")
}

/// The script id and revision a blob id names, if it is one this server
/// minted: 32 hex digits and a decimal revision, and nothing else.
fn parse(blob_id: &str) -> Option<(&str, u64)> {
	let (id, rev) = blob_id.strip_prefix(PREFIX)?.split_once('-')?;
	let is_id = id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
	let is_rev = !rev.is_empty() && rev.len() <= 20 && rev.bytes().all(|b| b.is_ascii_digit());
	if !is_id || !is_rev {
		return None;
	}
	Some((id, rev.parse().ok()?))
}

/// The octets of the script blob `blob_id` in `account`, if it is one of that
/// account's current script versions.
pub(super) fn content(data_dir: &Path, account: &str, blob_id: &str) -> Option<Vec<u8>> {
	let (id, rev) = parse(blob_id)?;
	store(data_dir, account)
		.version_content(id, rev)
		.ok()
		.map(String::into_bytes)
}

#[cfg(test)]
mod tests;
