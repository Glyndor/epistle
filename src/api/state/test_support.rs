//! API state test support.

use super::*;

impl ApiState {
	/// Test-only: count one wrong token from `ip` without sending a request.
	#[cfg(test)]
	pub(crate) fn seed_auth_failure(&self, ip: std::net::IpAddr) {
		self.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.record_failure(Some(ip), std::time::Instant::now());
	}

	/// Test-only: change how many requests may wait for an argon2 turn.
	#[cfg(test)]
	pub(crate) fn with_argon2_queue(mut self, max: usize) -> Self {
		Arc::get_mut(&mut self.inner)
			.expect("with_argon2_queue must be called before the state is shared")
			.argon2_queue_max = max;
		self
	}

	/// Test-only: requests holding a place in the argon2 queue right now.
	#[cfg(test)]
	pub(crate) fn argon2_waiting(&self) -> usize {
		self.inner
			.argon2_waiting
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.total()
	}

	/// Test-only: (clients, /48s) that hold a place in the argon2 queue.
	#[cfg(test)]
	pub(crate) fn argon2_queue_tracked(&self) -> (usize, usize) {
		self.inner
			.argon2_waiting
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.tracked()
	}

	/// Test-only: argon2 verifications running right now.
	#[cfg(test)]
	pub(crate) fn argon2_running(&self) -> usize {
		self.inner.argon2_stats[1].load(std::sync::atomic::Ordering::SeqCst)
	}

	/// Test-only: (argon2 runs started, most at once).
	#[cfg(test)]
	pub(crate) fn argon2_stats(&self) -> (usize, usize) {
		use std::sync::atomic::Ordering::SeqCst;
		(
			self.inner.argon2_stats[0].load(SeqCst),
			self.inner.argon2_stats[2].load(SeqCst),
		)
	}

	/// Test-only: behave as if the configured token had already verified once.
	#[cfg(test)]
	pub(crate) fn prime_configured_token(&self, token: &str) {
		let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
		let mut known = [0u8; 32];
		known.copy_from_slice(digest.as_ref());
		let _ = self.inner.configured_digest.set(known);
	}

	/// Test-only: lower the global failure ceiling so a test can reach it.
	#[cfg(test)]
	pub(crate) fn with_auth_global_max(mut self, max: u32) -> Self {
		let inner = Arc::get_mut(&mut self.inner)
			.expect("with_auth_global_max must be called before the state is shared");
		let now = std::time::Instant::now();
		let window = inner
			.auth_limiter
			.get_mut()
			.unwrap_or_else(|p| p.into_inner())
			.window();
		inner.auth_limiter =
			std::sync::Mutex::new(ClientLimiters::new(window).with_global_max(max, now));
		self
	}

	/// Replace the auth-failure limiter with one built around a custom
	/// window. Test-only: the router-level rate-limit test builds its state
	/// with a long window so the wall clock under a loaded parallel run is
	/// never the thing under test. The window logic itself is covered by
	/// `mod_tests_limiter.rs`. Must be called before the state is shared
	/// (the other builders quietly no-op when the `Arc` is already taken;
	/// this one panics, because a test-only builder that silently does
	/// nothing defeats its own control).
	#[cfg(test)]
	pub(crate) fn with_auth_window(mut self, window: std::time::Duration) -> Self {
		let inner = Arc::get_mut(&mut self.inner)
			.expect("with_auth_window must be called before the state is shared");
		inner.auth_limiter = std::sync::Mutex::new(ClientLimiters::new(window));
		self
	}
}
