//! What the health routes run, and how many runs may overlap.

use std::path::PathBuf;
use std::sync::Arc;

use crate::cli::status::{CheckArea, RunHold};

use super::ApiState;

/// Health runs that may be in progress at once on a server. A run asks the
/// listeners, DNS, the certificate and the database, so it is for a few
/// callers at a time and not for a crowd.
pub(super) const MAX_HEALTH_RUNS: usize = 2;

/// The places for health runs. One of them is made when the server starts and
/// every API listener of the server shares it, so the limit is the server's
/// and not each listener's.
#[derive(Clone)]
pub struct HealthGate(Arc<tokio::sync::Semaphore>);

impl HealthGate {
	/// A gate with `MAX_HEALTH_RUNS` places.
	pub fn new() -> Self {
		HealthGate(Arc::new(tokio::sync::Semaphore::new(MAX_HEALTH_RUNS)))
	}
}

impl Default for HealthGate {
	fn default() -> Self {
		Self::new()
	}
}

/// The state of the health routes.
#[derive(Default)]
pub(super) struct HealthRuns {
	/// Where the configuration was read from.
	path: Option<PathBuf>,
	/// The areas `GET /api/v1/health` runs; all of them unless a test says.
	areas: Option<Vec<CheckArea>>,
	/// The places for runs.
	gate: HealthGate,
	/// What keeps every blocking thread of a run until a test lets it go.
	#[cfg(test)]
	blocker: Option<Arc<crate::cli::status::Blocker>>,
	/// The time an area gets, when a test shortens it.
	#[cfg(test)]
	limit: Option<std::time::Duration>,
	/// Runs alive now and the most that were at once, for the tests.
	#[cfg(test)]
	alive: Arc<(
		std::sync::atomic::AtomicUsize,
		std::sync::atomic::AtomicUsize,
	)>,
}

impl ApiState {
	/// Name the file the configuration was read from. Must be set before the
	/// state is shared.
	pub fn with_config_path(mut self, path: PathBuf) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.health.path = Some(path);
		}
		self
	}

	/// Take the places for health runs from `gate`, which the server shares
	/// among every API listener. Must be set before the state is shared.
	pub fn with_health_gate(mut self, gate: HealthGate) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.health.gate = gate;
		}
		self
	}

	/// Run only `areas` for `GET /api/v1/health`, for a test that cannot ask
	/// the network. Must be set before the state is shared.
	#[cfg(test)]
	pub(crate) fn with_health_areas(mut self, areas: Vec<CheckArea>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.health.areas = Some(areas);
		}
		self
	}

	/// Keep every blocking thread of a run in `blocker` until the test opens
	/// it, for a test of what a run that outlives its client holds. Must be
	/// set before the state is shared.
	#[cfg(test)]
	pub(crate) fn with_health_blocker(
		mut self,
		blocker: Arc<crate::cli::status::Blocker>,
		limit: Option<std::time::Duration>,
	) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.health.blocker = Some(blocker);
			inner.health.limit = limit;
		}
		self
	}

	/// Wait until `places` places of the gate are free at once: the runs that
	/// held them are over. The limit is only there so that a lost signal fails
	/// the test and does not hang it.
	#[cfg(test)]
	pub(crate) async fn health_places_free(&self, places: u32) {
		let free = tokio::time::timeout(
			std::time::Duration::from_secs(120),
			Arc::clone(&self.inner.health.gate.0).acquire_many_owned(places),
		)
		.await;
		assert!(free.is_ok(), "the places never came back");
	}

	/// The file the configuration was read from, when the server knows it.
	pub(crate) fn config_path(&self) -> Option<PathBuf> {
		self.inner.health.path.clone()
	}

	/// The areas `GET /api/v1/health` runs.
	pub(crate) fn health_areas(&self) -> Vec<CheckArea> {
		self.inner
			.health
			.areas
			.clone()
			.unwrap_or_else(|| CheckArea::ALL.to_vec())
	}

	/// The place of one more health run, or `None` when [`MAX_HEALTH_RUNS`]
	/// are in progress.
	pub(crate) fn try_health_run(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
		Arc::clone(&self.inner.health.gate.0)
			.try_acquire_owned()
			.ok()
	}

	/// What a run keeps: its place, until the last thing it started has ended.
	pub(crate) fn health_hold(&self) -> Option<RunHold> {
		let permit = self.try_health_run()?;
		#[cfg(test)]
		return Some(RunHold::blocked(
			permit,
			self.inner.health.blocker.clone(),
			self.inner.health.limit,
		));
		#[cfg(not(test))]
		Some(RunHold::new(permit))
	}

	/// Count a run as alive until the guard drops, for the tests.
	#[cfg(test)]
	pub(crate) fn health_run_alive(&self) -> impl Drop + use<> {
		use std::sync::atomic::Ordering;
		struct Alive(
			Arc<(
				std::sync::atomic::AtomicUsize,
				std::sync::atomic::AtomicUsize,
			)>,
		);
		impl Drop for Alive {
			fn drop(&mut self) {
				self.0.0.fetch_sub(1, Ordering::SeqCst);
			}
		}
		let counts = Arc::clone(&self.inner.health.alive);
		let now = counts.0.fetch_add(1, Ordering::SeqCst) + 1;
		counts.1.fetch_max(now, Ordering::SeqCst);
		Alive(counts)
	}

	/// Runs alive now, for the tests.
	#[cfg(test)]
	pub(crate) fn health_alive(&self) -> usize {
		self.inner
			.health
			.alive
			.0
			.load(std::sync::atomic::Ordering::SeqCst)
	}

	/// The most runs that were alive at once, for the tests.
	#[cfg(test)]
	pub(crate) fn health_peak(&self) -> usize {
		self.inner
			.health
			.alive
			.1
			.load(std::sync::atomic::Ordering::SeqCst)
	}
}
