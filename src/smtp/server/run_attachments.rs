//! The attachment policy on inbound mail, at the point where the content
//! scanner decides. Split from `run.rs` to keep the connection loop under
//! the code-line limit.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWrite;

use super::{Reply, Server, send};
use crate::antispam::attachments::policy::{Action, WARNING_HEADER};
use crate::smtp::session::AcceptedMessage;

/// How long past the inspection's own deadline the session waits for it:
/// room for a blocking pool that is slow to start the task.
const SLACK: Duration = Duration::from_secs(5);

/// The reply when the inspection cannot run or finish now.
const UNAVAILABLE: &str = "4.7.1 content scan unavailable, try again later";

impl Server {
	/// Remove any attachment warning the sender wrote from unauthenticated
	/// inbound `message`, then inspect its attachments and apply the
	/// policy, when there is one. Returns `true` when a reply refusing the
	/// message was already sent and the message must be dropped.
	///
	/// The inspection is CPU-bound and runs on the blocking pool, within
	/// caps on how many run at once in total and for the client at `peer`.
	/// Past a cap, past the deadline, or if the inspection panicked, the
	/// message is deferred with a `451`: a check that did not run never lets
	/// mail through, and the session goes on.
	pub(super) async fn screen_attachments<W>(
		&self,
		message: &mut AcceptedMessage,
		stream: &mut W,
		peer: Option<IpAddr>,
	) -> Result<bool, std::io::Error>
	where
		W: AsyncWrite + Unpin,
	{
		// Only the server's own inspection speaks in this header, whatever
		// the mode.
		crate::smtp::trace::strip_headers_in_place(&mut message.data, &[WARNING_HEADER]);
		let Some(policy) = &self.attachments else {
			return Ok(false);
		};
		let Some(permit) = policy.admit_inbound(peer) else {
			tracing::warn!("attachment inspection busy; deferring the message");
			send(stream, &Reply::single(451, UNAVAILABLE)).await?;
			return Ok(true);
		};
		let data = std::mem::take(&mut message.data);
		let deadline = policy.timeout() + SLACK;
		let policy = Arc::clone(policy);
		// The permit travels with the work: the slot stays taken until the
		// inspection really ends, also when this session stops waiting.
		let task = tokio::task::spawn_blocking(move || {
			let _permit = permit;
			let (_, decision) = policy.check(&data);
			(data, decision)
		});
		let Ok(Ok((data, decision))) = tokio::time::timeout(deadline, task).await else {
			tracing::error!("attachment inspection failed or timed out; deferring the message");
			send(stream, &Reply::single(451, UNAVAILABLE)).await?;
			return Ok(true);
		};
		message.data = data;
		if decision.action == Action::Reject {
			tracing::info!(reasons = ?decision.reasons, "attachment policy: rejecting");
			self.metrics.rejected(crate::metrics::RejectReason::Scanner);
			send(
				stream,
				&Reply::single(550, "5.7.1 attachment type not accepted"),
			)
			.await?;
			return Ok(true);
		}
		decision.stamp(&mut message.data);
		if decision.action == Action::Quarantine {
			tracing::info!(reasons = ?decision.reasons, "attachment policy: quarantining to Rejects");
			if message.mailbox.is_none() {
				self.metrics.quarantined();
			}
			message.mailbox = Some("Rejects".to_string());
		} else if decision.action == Action::Flag {
			tracing::info!(reasons = ?decision.reasons, "attachment policy: flagging");
		}
		Ok(false)
	}
}
