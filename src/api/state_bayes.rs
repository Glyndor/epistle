//! Per-account Bayesian corpus wiring on the shared API state.
//!
//! `Email/set` feeds the training queue on a `$Junk` / `$NotJunk`
//! change; account-removal drops the rows through the BayesStore. The
//! builder/accessor pairs sit here so the rest of `state.rs` stays
//! under the line limit and the bayes surface is one place to read in
//! full.

use std::sync::Arc;

use super::ApiState;

/// State slots owned by the per-account Bayesian wiring.
#[derive(Default)]
pub(super) struct BayesBindings {
	/// The bounded queue to the per-account Bayesian trainer. `Email/set`
	/// feeds it on a `$Junk` / `$NotJunk` change. `None` without a
	/// database, and `Email/set` answers the same.
	pub(super) training: Option<crate::antispam::training_queue::TrainingQueue>,
	/// The Bayesian store, so account removal can drop the corpus rows
	/// of the account. `None` without a database.
	pub(super) bayes_store: Option<crate::antispam::corpus::BayesStore>,
}

impl ApiState {
	/// Attach the training queue. Must be set before the state is shared.
	pub fn with_training(
		mut self,
		training: crate::antispam::training_queue::TrainingQueue,
	) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.bayes.training = Some(training);
		}
		self
	}

	/// Attach the Bayesian store. Must be set before the state is shared.
	pub fn with_bayes_store(mut self, store: crate::antispam::corpus::BayesStore) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.bayes.bayes_store = Some(store);
		}
		self
	}

	/// The training queue wired into the API state, when one was
	/// attached.
	pub fn training(&self) -> Option<&crate::antispam::training_queue::TrainingQueue> {
		self.inner.bayes.training.as_ref()
	}

	/// The underlying `BayesStore` wired into the API state, when one
	/// was attached. Account-removal uses it to drop the account's
	/// per-scope rows.
	pub fn bayes_store(&self) -> Option<&crate::antispam::corpus::BayesStore> {
		self.inner.bayes.bayes_store.as_ref()
	}
}
