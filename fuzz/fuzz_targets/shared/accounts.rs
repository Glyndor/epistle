//! The two accounts the session targets share: names, passwords drawn by
//! the process, and a directory built in memory that verifies them cheaply.
//! Each target includes this file and uses a part of it.

#![allow(dead_code)]

use std::sync::Arc;

use argon2::{Algorithm, Argon2, CustomizedPasswordHasher, Params, Version};
use libfuzzer_sys::arbitrary::Unstructured;

use epistle::smtp::directory::Directory;

/// The two accounts of every run. A session signs in as one of them at
/// most; the other is the neighbour it must never reach.
pub const NAMES: [&str; 2] = ["acct-a", "acct-b"];
pub const DOMAIN: &str = "example.org";

pub struct Account {
	pub name: &'static str,
	pub secret: String,
	/// A string that only this account's stored mail and folder names carry.
	/// Seeing it in a reply to the other account is a leak, unless the client
	/// typed it itself.
	pub marker: String,
}

/// Hex of `count` bytes of the input, for the wrong passwords a client
/// tries.
pub fn hex(u: &mut Unstructured, count: usize) -> String {
	let mut bytes = u.bytes(count).map(<[u8]>::to_vec).unwrap_or_default();
	bytes.resize(count, 0);
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex of a value the process draws once, so no secret is written in this
/// file and none costs input bytes: libFuzzer starts with short inputs, and
/// what the setup takes, the commands do not get. A run names a password by
/// the account it belongs to, so a reproduced crash behaves the same with
/// other values.
fn drawn(index: u64) -> String {
	use std::hash::{BuildHasher, RandomState};
	static STATE: std::sync::LazyLock<RandomState> = std::sync::LazyLock::new(RandomState::new);
	format!("{:016x}", STATE.hash_one(index))
}

pub fn accounts() -> Vec<Account> {
	NAMES
		.iter()
		.zip(0u64..)
		.map(|(name, i)| Account {
			name,
			secret: drawn(2 * i),
			// The index keeps the two markers apart.
			marker: format!("Mark{i}x{}", &drawn(2 * i + 1)[..8]),
		})
		.collect()
}

/// The account a user name and password sign in as, if they match one. The
/// name may be the account or its address in any case.
pub fn which(accounts: &[Account], login: &(String, String)) -> Option<usize> {
	let (name, pass) = login;
	accounts.iter().position(|a| {
		let address = format!("{}@{DOMAIN}", a.name);
		(name == a.name || name.eq_ignore_ascii_case(&address)) && *pass == a.secret
	})
}

/// An argon2id hash at the smallest cost the format allows. Verifying it is
/// what a login pays here, and at the stored cost a run would spend its time
/// hashing instead of driving the session.
fn cheap_hash(secret: &str, salt: &[u8]) -> String {
	let params = Params::new(8, 1, 1, None).expect("argon2 floor parameters");
	Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone())
		.hash_password_customized(secret.as_bytes(), salt, None, None, params)
		.expect("argon2 hash")
		.to_string()
}

pub fn directory(accounts: &[Account]) -> Arc<Directory> {
	// The salt only has to be valid: the input is better spent on commands.
	let hashes: Vec<(String, String)> = accounts
		.iter()
		.map(|a| {
			let salt = format!("{}{}", a.name, a.secret);
			(a.name.to_string(), cheap_hash(&a.secret, salt.as_bytes()))
		})
		.collect();
	let addresses = accounts
		.iter()
		.map(|a| (format!("{}@{DOMAIN}", a.name), a.name.to_string()));
	Arc::new(Directory::new([DOMAIN.to_string()], addresses).with_password_hashes(hashes))
}

pub fn base64(input: &[u8]) -> String {
	const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::new();
	for chunk in input.chunks(3) {
		let n = chunk
			.iter()
			.enumerate()
			.fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
		for i in 0..4 {
			if i <= chunk.len() {
				out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
			} else {
				out.push('=');
			}
		}
	}
	out
}
