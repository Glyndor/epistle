//! Stopping the renewal loop at shutdown.
//!
//! The loop is otherwise dropped with the runtime, and an order dropped that
//! way withdraws its challenges on a detached task that the stopping runtime
//! does not run. Stopped through [`Renewal::stop`], the loop drops the order
//! in flight itself and withdraws what is still published while `serve`
//! waits for it, up to a deadline.

use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// The running renewal loop, held by `serve` until shutdown.
pub struct Renewal {
	stop: watch::Sender<bool>,
	task: JoinHandle<()>,
}

/// The loop's side of the stop request.
pub struct StopSignal(watch::Receiver<bool>);

impl StopSignal {
	/// Resolve once a stop was asked for. A [`Renewal`] dropped without
	/// asking never resolves it: the loop then ends with the runtime, as it
	/// did before it could be stopped.
	pub async fn requested(&mut self) {
		if self.0.wait_for(|stop| *stop).await.is_err() {
			std::future::pending::<()>().await;
		}
	}
}

impl Renewal {
	/// Spawn the loop `run` builds from its stop signal.
	pub fn spawn<F>(run: impl FnOnce(StopSignal) -> F) -> Self
	where
		F: Future<Output = ()> + Send + 'static,
	{
		let (stop, signal) = watch::channel(false);
		Renewal {
			stop,
			task: tokio::spawn(run(StopSignal(signal))),
		}
	}

	/// Ask the loop to stop and wait up to `deadline` for it to withdraw
	/// what it still has published. `true` when it finished in time; on
	/// `false` the loop is aborted and whatever a journal holds is withdrawn
	/// at the next start.
	pub async fn stop(self, deadline: Duration) -> bool {
		let _ = self.stop.send(true);
		let mut task = self.task;
		match tokio::time::timeout(deadline, &mut task).await {
			Ok(_) => true,
			Err(_) => {
				task.abort();
				tracing::warn!(
					"acme: challenges still being withdrawn after {}s; the next start withdraws what is left",
					deadline.as_secs()
				);
				false
			}
		}
	}
}
