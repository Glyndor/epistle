//! Shared CLI helpers: stdin reading, token hashing, secret generation, the
//! at-rest key setup and the key-generation command bodies.

mod dkim_keys;
mod input;
mod oauth_keys;
mod output;
mod secret;
mod storage_crypto;
#[cfg(test)]
mod tests;
mod token_hash;

pub(super) use dkim_keys::{dkim_keygen, generate_rsa_key};
pub(super) use oauth_keys::{
	derive_oauth_public_from_private, generate_oauth_keypair, oauth_keygen,
};
pub(super) use secret::generate_secret;
pub(crate) use storage_crypto::attach_file_accounts;
pub(super) use storage_crypto::{message_crypto, storage_keygen};
pub(super) use token_hash::token_hash;
#[cfg(test)]
pub(super) use token_hash::token_hash_from;
