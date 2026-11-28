//! The cursor of a page: where the walk of the queue stopped.
//!
//! The walk stops on the last entry it read, and that entry may be one the
//! key cannot see: a key confined to some domains walks over the entries of
//! the other tenants. So the cursor is that entry's id when the key reaches
//! it, and a sealed marker when it does not. The marker is sealed under a key
//! the process holds and the client does not, so it names no entry and the
//! position it carries is not readable by the client.
//!
//! The marker is good for as long as the process lives. A client that comes
//! back with one the server cannot open is told to start the listing again.

use base64::Engine;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::OnceLock;
use uuid::Uuid;

/// What a sealed marker starts with, so it is told from a plain id.
const PREFIX: &str = "q1.";

/// Length of the key the markers are sealed under.
const KEY_LEN: usize = 32;

/// What the sealed bytes are bound to, so a marker of another use is refused.
const CONTEXT: &[u8] = b"epistle queue cursor v1";

/// The base the markers are written in: URL-safe, so a marker travels in a
/// query string as it is.
fn base() -> base64::engine::general_purpose::GeneralPurpose {
	base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The key this process seals the markers with. It is made once and never
/// leaves the process: a client cannot read the position a marker carries,
/// and the marker stops opening when the process restarts.
fn key() -> Option<&'static LessSafeKey> {
	static KEY: OnceLock<Option<LessSafeKey>> = OnceLock::new();
	KEY.get_or_init(|| {
		let mut bytes = [0u8; KEY_LEN];
		SystemRandom::new().fill(&mut bytes).ok()?;
		let unbound = UnboundKey::new(&CHACHA20_POLY1305, &bytes).ok()?;
		Some(LessSafeKey::new(unbound))
	})
	.as_ref()
}

/// Seal the position the walk stopped at, so the client carries it without
/// learning the id of an entry it cannot see.
///
/// The marker is the nonce, the sealed position and the tag of the seal.
pub fn seal(position: Uuid) -> Option<String> {
	let key = key()?;
	let mut nonce = [0u8; NONCE_LEN];
	SystemRandom::new().fill(&mut nonce).ok()?;
	let mut sealed = position.as_bytes().to_vec();
	key.seal_in_place_append_tag(
		Nonce::assume_unique_for_key(nonce),
		Aad::from(CONTEXT),
		&mut sealed,
	)
	.ok()?;
	let mut marker = nonce.to_vec();
	marker.append(&mut sealed);
	Some(format!("{PREFIX}{}", base().encode(marker)))
}

/// The position a cursor names: the id of an entry, or the sealed position
/// the walk stopped at.
///
/// A plain id is the form 0.15.0 issued, and any one is taken: it only says
/// after which entry the walk resumes. `None` for a cursor that is neither a
/// plain id nor a marker this process sealed.
pub fn anchor(cursor: &str) -> Option<Uuid> {
	if let Ok(id) = Uuid::parse_str(cursor) {
		return Some(id);
	}
	let encoded = cursor.strip_prefix(PREFIX)?;
	let mut bytes = base().decode(encoded).ok()?;
	if bytes.len() <= NONCE_LEN {
		return None;
	}
	let mut nonce = [0u8; NONCE_LEN];
	nonce.copy_from_slice(&bytes[..NONCE_LEN]);
	let key = key()?;
	let plain = key
		.open_within(
			Nonce::assume_unique_for_key(nonce),
			Aad::from(CONTEXT),
			&mut bytes,
			NONCE_LEN..,
		)
		.ok()?;
	Uuid::from_slice(plain).ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_sealed_position_opens_where_it_was_sealed() {
		let position = Uuid::now_v7();
		let marker = seal(position).expect("seal");
		assert!(marker.starts_with(PREFIX), "{marker}");
		assert_eq!(anchor(&marker), Some(position));
	}

	#[test]
	fn a_sealed_position_names_no_entry() {
		let position = Uuid::now_v7();
		let marker = seal(position).expect("seal");
		assert!(!marker.contains(&position.to_string()), "{marker}");
	}

	#[test]
	fn a_marker_of_another_position_is_refused() {
		let marker = seal(Uuid::now_v7()).expect("seal");
		let mut tampered = marker.into_bytes();
		let last = tampered.len() - 1;
		tampered[last] = if tampered[last] == b'a' { b'b' } else { b'a' };
		assert_eq!(anchor(std::str::from_utf8(&tampered).expect("utf8")), None);
	}

	#[test]
	fn a_cursor_that_is_not_one_of_ours_is_refused() {
		assert_eq!(anchor("not-a-cursor"), None);
		assert_eq!(anchor("q1.not-base64"), None);
		assert_eq!(anchor(""), None);
	}
}
