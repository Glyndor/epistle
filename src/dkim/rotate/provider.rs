//! The provider the rotator writes through, and how it is picked up again.
//!
//! A token read from a file or from the configuration can change while the
//! server runs, so a source can be given that builds the provider again at
//! the start of every cycle. A token read from an environment variable is
//! the one of the process and only changes with a restart.

use std::sync::{Arc, Mutex};

use crate::dns::provider::DnsProvider;

/// Builds the provider from the configuration as it is now. The error is
/// logged and says what is missing.
pub type ProviderSource = Arc<dyn Fn() -> Result<Arc<dyn DnsProvider>, String> + Send + Sync>;

/// The provider of the rotator: the one it was given, replaced at the start
/// of each cycle when a source is set.
pub(super) struct LiveProvider {
	current: Mutex<Arc<dyn DnsProvider>>,
	source: Option<ProviderSource>,
}

impl LiveProvider {
	pub(super) fn fixed(provider: Arc<dyn DnsProvider>) -> Self {
		LiveProvider {
			current: Mutex::new(provider),
			source: None,
		}
	}

	pub(super) fn with_source(&mut self, source: ProviderSource) {
		self.source = Some(source);
	}

	/// The provider to write through now.
	pub(super) fn get(&self) -> Arc<dyn DnsProvider> {
		let current = self
			.current
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		Arc::clone(&current)
	}

	/// Build the provider again when a source is set. On failure the provider
	/// of the last cycle is kept and the reason returned, so the caller does
	/// not write with a credential the configuration no longer holds.
	pub(super) fn refresh(&self) -> Result<(), String> {
		let Some(source) = &self.source else {
			return Ok(());
		};
		let built = source()?;
		*self
			.current
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner) = built;
		Ok(())
	}
}
