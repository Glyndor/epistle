//! The `tls-server-end-point` channel binding of the certificate in service.

use std::sync::{Arc, RwLock};

/// The `tls-server-end-point` channel binding (RFC 5929) of the certificate
/// the listeners present: the SHA-256 of its leaf (DER). Every listener
/// holds a clone and reads it when a session starts, so a certificate
/// reloaded at runtime changes the binding SCRAM-SHA-256-PLUS checks
/// together with the certificate itself.
#[derive(Clone, Debug)]
pub struct EndPoint(Arc<RwLock<Vec<u8>>>);

impl EndPoint {
	/// Wrap the binding of the certificate loaded at start.
	pub fn new(hash: Vec<u8>) -> Self {
		EndPoint(Arc::new(RwLock::new(hash)))
	}

	/// The binding of the certificate in service now.
	pub fn current(&self) -> Vec<u8> {
		self.0.read().expect("end point lock").clone()
	}

	/// Replace the binding after the certificate was reloaded.
	pub fn set(&self, hash: Vec<u8>) {
		*self.0.write().expect("end point lock") = hash;
	}
}

/// The `tls-server-end-point` binding of a leaf certificate (DER).
pub fn end_point_of(leaf_der: &[u8]) -> Vec<u8> {
	ring::digest::digest(&ring::digest::SHA256, leaf_der)
		.as_ref()
		.to_vec()
}
