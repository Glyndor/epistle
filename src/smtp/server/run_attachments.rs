//! The attachment policy on inbound mail, at the point where the content
//! scanner decides. Split from `run.rs` to keep the connection loop under
//! the code-line limit.

use std::sync::Arc;

use tokio::io::AsyncWrite;

use super::{Reply, Server, send};
use crate::antispam::attachments::policy::{Action, Policy};
use crate::smtp::session::AcceptedMessage;

impl Server {
	/// Inspect the attachments of unauthenticated inbound `message` and
	/// apply the policy. Returns `true` when a reply refusing the message
	/// was already sent and the message must be dropped.
	///
	/// The inspection is CPU-bound and runs off the async runtime. If it
	/// cannot finish (the task panicked), the message is deferred with a
	/// `451`: a check that did not run never lets mail through.
	pub(super) async fn screen_attachments<W>(
		&self,
		policy: &Arc<Policy>,
		message: &mut AcceptedMessage,
		stream: &mut W,
	) -> Result<bool, std::io::Error>
	where
		W: AsyncWrite + Unpin,
	{
		let data = std::mem::take(&mut message.data);
		let policy = Arc::clone(policy);
		let checked = tokio::task::spawn_blocking(move || {
			let (_, decision) = policy.check(&data);
			(data, decision)
		})
		.await;
		let Ok((data, decision)) = checked else {
			tracing::error!("attachment inspection failed; deferring the message");
			send(
				stream,
				&Reply::single(451, "4.7.1 content scan unavailable, try again later"),
			)
			.await?;
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
