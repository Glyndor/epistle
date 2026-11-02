//! The end of `serve`: run until a listener fails or a stop signal comes,
//! then drain (see [`crate::shutdown`]).

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::acme::renew::Renewal;
use crate::shutdown::Drain;

/// How long open connections get to finish after SIGTERM. The generated
/// compose file gives `mail` a 30 s `stop_grace_period`, and podup sends
/// SIGKILL when that runs out, so the drain has to end first.
pub(super) const DRAIN_DEADLINE: Duration =
	Duration::from_secs(crate::cli::init::MAIL_STOP_GRACE_SECS - 5);

/// How long the ACME renewal loop gets to withdraw the challenges it still
/// has published. It runs alongside the drain, so it shares its deadline;
/// what is left after it is withdrawn at the next start.
pub(super) const ACME_STOP_DEADLINE: Duration = DRAIN_DEADLINE;

/// Wait for the listeners; on SIGTERM or SIGINT drain and return `Ok`.
/// Either way the ACME renewal loop, when there is one, is stopped first.
pub(super) async fn until_stopped(
	tasks: Vec<JoinHandle<std::io::Result<()>>>,
	drain: &Drain,
	renewal: Option<Renewal>,
) -> std::io::Result<()> {
	let signal = async {
		let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
			.expect("register SIGTERM handler");
		tokio::select! {
			_ = term.recv() => "SIGTERM",
			_ = tokio::signal::ctrl_c() => "SIGINT",
		}
	};
	until(tasks, drain, renewal, signal).await
}

/// [`until_stopped`] with the stop signal as a future that resolves to the
/// signal's name.
pub(super) async fn until(
	tasks: Vec<JoinHandle<std::io::Result<()>>>,
	drain: &Drain,
	renewal: Option<Renewal>,
	signal: impl Future<Output = &'static str>,
) -> std::io::Result<()> {
	let listeners = async {
		for task in tasks {
			task.await
				.map_err(|error| std::io::Error::other(error.to_string()))??;
		}
		Ok::<(), std::io::Error>(())
	};
	tokio::select! {
		result = listeners => {
			stop_renewal(renewal).await;
			result
		}
		name = signal => {
			tracing::info!(signal = name, "stopping: no new connections, letting open ones finish");
			drain.begin();
			let (left, ()) = tokio::join!(drain.finished(DRAIN_DEADLINE), stop_renewal(renewal));
			if left == 0 {
				tracing::info!("every connection finished, shutting down");
			} else {
				tracing::warn!(left, "connections still open after {}s, shutting down", DRAIN_DEADLINE.as_secs());
			}
			Ok(())
		}
	}
}

/// Stop the renewal loop, if any, within [`ACME_STOP_DEADLINE`].
async fn stop_renewal(renewal: Option<Renewal>) {
	if let Some(renewal) = renewal {
		renewal.stop(ACME_STOP_DEADLINE).await;
	}
}
