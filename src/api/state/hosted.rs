//! The hosted domains the management API answers with, and how they follow
//! the domain state of a running server.

use std::sync::Arc;

use super::ApiState;
use crate::config::Config;
use crate::domain::catalog::Catalog;
use crate::editable::LiveConfig;

/// The hosted domains at one moment: the list, which are switched off and
/// what each is.
#[derive(Debug, Clone, Default)]
pub struct HostedView {
	/// The hosted domains.
	pub domains: Vec<String>,
	/// Those switched off.
	pub disabled: Vec<String>,
	/// What each is, as `epistle domain show` reads it.
	pub catalog: Catalog,
}

impl HostedView {
	/// A server that knows only its domains and which are switched off.
	pub fn hosting(domains: Vec<String>, disabled: Vec<String>) -> Self {
		HostedView {
			catalog: Catalog::hosting(&domains, &disabled),
			domains,
			disabled,
		}
	}

	/// The hosted domains of `config`.
	pub fn of(config: &Config) -> Self {
		HostedView {
			domains: config.domains.clone(),
			disabled: config.disabled_domains.clone(),
			catalog: Catalog::from_config(config),
		}
	}
}

impl ApiState {
	/// The hosted domains now.
	pub(crate) fn hosted(&self) -> Arc<HostedView> {
		Arc::clone(&self.inner.hosted.read().expect("api hosted lock"))
	}

	pub(super) fn set_hosted(&self, view: HostedView) {
		*self.inner.hosted.write().expect("api hosted lock") = Arc::new(view);
	}

	/// Answer with the hosted domains of `live` and follow every reload of
	/// it, and write domain changes through it. Must be set before the
	/// state is shared.
	pub fn with_live_domains(mut self, live: Arc<LiveConfig>) -> Self {
		self.set_hosted(HostedView::of(&live.current()));
		let hosted = Arc::clone(&self.inner.hosted);
		live.on_change(move |config| {
			*hosted.write().expect("api hosted lock") = Arc::new(HostedView::of(config));
		});
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.live_domains = Some(live);
		}
		self
	}

	/// The live domain state, when the server runs with one.
	pub fn live_domains(&self) -> Option<&Arc<LiveConfig>> {
		self.inner.live_domains.as_ref()
	}
}
