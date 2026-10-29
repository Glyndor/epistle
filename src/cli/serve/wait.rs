//! The end of `serve`: run until a listener fails or a stop signal comes,
//! then drain (see [`crate::shutdown`]).

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::shutdown::Drain;

/// How long open connections get to finish after SIGTERM. The generated
/// compose file gives `mail` a 30 s `stop_grace_period`, and podup sends
/// SIGKILL when that runs out, so the drain has to end first.
pub(super) const DRAIN_DEADLINE: Duration =
	Duration::from_secs(crate::cli::init::MAIL_STOP_GRACE_SECS - 5);

/// Wait for the listeners; on SIGTERM or SIGINT drain and return `Ok`.
pub(super) async fn until_stopped(
	tasks: Vec<JoinHandle<std::io::Result<()>>>,
	drain: &Drain,
) -> std::io::Result<()> {
	let signal = async {
		let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
			.expect("register SIGTERM handler");
		tokio::select! {
			_ = term.recv() => "SIGTERM",
			_ = tokio::signal::ctrl_c() => "SIGINT",
		}
	};
	let listeners = async {
		for task in tasks {
			task.await
				.map_err(|error| std::io::Error::other(error.to_string()))??;
		}
		Ok::<(), std::io::Error>(())
	};
	tokio::select! {
		result = listeners => result,
		name = signal => {
			tracing::info!(signal = name, "stopping: no new connections, letting open ones finish");
			drain.begin();
			let left = drain.finished(DRAIN_DEADLINE).await;
			if left == 0 {
				tracing::info!("every connection finished, shutting down");
			} else {
				tracing::warn!(left, "connections still open after {}s, shutting down", DRAIN_DEADLINE.as_secs());
			}
			Ok(())
		}
	}
}
