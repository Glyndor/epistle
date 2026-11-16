//! The admin event stream's share of the API state.

use super::*;
use crate::api::events::{EventLimits, Hub};

impl ApiState {
	/// The ring of notifications and the count of open event streams.
	pub(crate) fn events(&self) -> &Hub {
		&self.inner.events
	}

	/// Apply the operator's bounds on the admin event stream. Must be set
	/// before the state is shared.
	pub fn with_event_limits(mut self, limits: EventLimits) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.events = Hub::new(limits);
		}
		self
	}
}
