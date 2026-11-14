//! The layout of the ledger file: its header, its records, and the checksum
//! that tells a whole record from a torn one.

use std::io;

/// The fingerprint of one message identity.
pub(in crate::migrate::imap) type Fingerprint = [u8; 32];

/// What marks the file as ours, and the version of the record layout.
pub(super) const MAGIC: &[u8; 8] = b"EPSTLG1\0";

/// Magic, UIDVALIDITY, and four octets left at zero. How many records the file
/// holds is read from its length, not from the header.
pub(super) const HEADER: u64 = 16;

/// UID, fingerprint and checksum.
pub(super) const RECORD: u64 = 40;

/// The largest ledger. At 40 octets per record it holds 26 million confirmed
/// messages, far past any mailbox that still has room for them.
pub(super) const MAX_LEDGER_BYTES: u64 = 1024 * 1024 * 1024;

/// The first 32 bits of the SHA-256 over a record, so a torn or altered
/// record is caught instead of read as another message.
pub(super) fn checksum(uid: u32, fingerprint: &Fingerprint) -> u32 {
	let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
	hash.update(&uid.to_le_bytes());
	hash.update(fingerprint);
	u32::from_le_bytes(
		hash.finish().as_ref()[..4]
			.try_into()
			.expect("SHA-256 prefix"),
	)
}

/// The UID and fingerprint of one record, when its checksum holds.
pub(super) fn decode(bytes: &[u8]) -> io::Result<(u32, Fingerprint)> {
	let mut fingerprint = [0u8; 32];
	fingerprint.copy_from_slice(&bytes[4..36]);
	let uid = u32::from_le_bytes(bytes[..4].try_into().expect("uid"));
	if u32::from_le_bytes(bytes[36..40].try_into().expect("checksum"))
		!= checksum(uid, &fingerprint)
	{
		return Err(io::Error::other("record checksum"));
	}
	Ok((uid, fingerprint))
}

/// The header bytes of a ledger that holds no records yet.
pub(super) fn header(uid_validity: u32) -> Vec<u8> {
	let mut bytes = Vec::with_capacity(HEADER as usize);
	bytes.extend_from_slice(MAGIC);
	bytes.extend_from_slice(&uid_validity.to_le_bytes());
	bytes.resize(HEADER as usize, 0);
	bytes
}
