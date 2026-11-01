//! The challenges an order has published and not yet withdrawn.
//!
//! An order can end three ways: validation finishes, validation fails, or the
//! future driving it is dropped (shutdown, an aborted renewal task). The first
//! two reach the withdrawal in the order flow. The third never does, because a
//! dropped future runs no more of its body, so the withdrawal is tied to this
//! guard instead: whatever is still recorded when it is dropped is withdrawn
//! by a task spawned on the running runtime.

use std::sync::Arc;

use super::super::challenge::ChallengeResponder;
use super::super::jws::AccountKey;

/// Challenges published for one order, withdrawn on every exit.
pub(super) struct Published {
	pub(super) responder: Arc<dyn ChallengeResponder>,
	key: Arc<AccountKey>,
	/// `(domain, token)` of every challenge published or being published.
	/// An entry is recorded before its publish starts, so a publish that
	/// half-succeeded is withdrawn too.
	entries: Vec<(String, String)>,
}

impl Published {
	pub(super) fn new(responder: Arc<dyn ChallengeResponder>, key: Arc<AccountKey>) -> Self {
		Published {
			responder,
			key,
			entries: Vec::new(),
		}
	}

	/// Record a challenge about to be published.
	pub(super) fn record(&mut self, domain: &str, token: &str) {
		self.entries.push((domain.to_string(), token.to_string()));
	}

	/// Withdraw everything recorded. An entry leaves the list only after its
	/// withdrawal completed, so a future dropped half way through leaves the
	/// rest to the drop handler.
	pub(super) async fn withdraw_all(&mut self) {
		while let Some((domain, token)) = self.entries.last() {
			self.responder.withdraw(domain, token, &self.key).await;
			self.entries.pop();
		}
	}
}

impl Drop for Published {
	fn drop(&mut self) {
		if self.entries.is_empty() {
			return;
		}
		let entries = std::mem::take(&mut self.entries);
		let responder = self.responder.clone();
		let key = self.key.clone();
		// The withdrawal of a dropped order runs detached. It is not
		// guaranteed: a runtime that stops before the task finishes drops it,
		// so what was pending is logged now, where an operator can clean it.
		let pending: Vec<&str> = entries.iter().map(|(domain, _)| domain.as_str()).collect();
		tracing::warn!(
			?pending,
			"acme: order dropped with challenges still published; withdrawing them detached"
		);
		let Ok(runtime) = tokio::runtime::Handle::try_current() else {
			tracing::warn!(
				?pending,
				"acme: order dropped outside a runtime; its challenges were not withdrawn"
			);
			return;
		};
		runtime.spawn(async move {
			for (domain, token) in entries.iter().rev() {
				responder.withdraw(domain, token, &key).await;
			}
		});
	}
}
