//! What the routing sink queues on behalf of a local delivery: the copies
//! a forward or a Sieve redirect sends onward, and the 5.4.6 bounce for a
//! delivery refused as a forwarding loop. Kept apart from `routing.rs`,
//! which decides which recipients are local at all.

use crate::queue::bounce::{ReportRecipient, build_failed};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::SinkError;

use super::delivery::{Redirect, forwarded_copy};
use super::routing::SplitDelivery;

impl SplitDelivery {
	/// Queue every redirect of `message`, preserving the (non-null)
	/// original sender behind SRS when it is on. Each copy names the
	/// address whose delivery forwarded it in `Delivered-To`, so a copy
	/// that comes back is recognised, and is ARC-sealed over that field.
	pub(super) fn queue_redirects(
		&self,
		message: &AcceptedMessage,
		redirects: Vec<Redirect>,
	) -> Result<(), SinkError> {
		for redirect in redirects {
			let data = forwarded_copy(&redirect.delivered_to, &message.data);
			let data = match self.arc_seal(&data) {
				Some(arc_headers) => [arc_headers.into_bytes(), data].concat(),
				None => data,
			};
			let forwarded = AcceptedMessage {
				reverse_path: self.forward_sender(&message.reverse_path),
				recipients: vec![redirect.to],
				data,
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			};
			self.store_outbound(&forwarded)?;
			if let Some(metrics) = &self.metrics {
				metrics.forwarded();
			}
		}
		Ok(())
	}

	/// Bounce `message` to its sender for every address in `looped` with
	/// `554 5.4.6`, the same status the SMTP hop limit refuses a loop with.
	/// A bounce (null sender) gets nothing back, and neither does an
	/// address that asked for no failure notice.
	pub(super) fn bounce_loops(
		&self,
		message: &AcceptedMessage,
		looped: &[String],
	) -> Result<(), SinkError> {
		let recipients: Vec<ReportRecipient> = looped
			.iter()
			.inspect(|_| {
				if let Some(metrics) = &self.metrics {
					metrics.rejected(crate::metrics::RejectReason::Loop);
				}
			})
			.filter(|address| !message.no_dsn.contains(address))
			.map(|address| {
				tracing::info!("refusing a message that loops through a forward");
				ReportRecipient::new(
					address,
					&format!("554 5.4.6 mail forwarding loop for {address}"),
				)
			})
			.collect();
		let hostname = looped
			.first()
			.and_then(|address| address.rsplit_once('@'))
			.map_or("localhost", |(_, domain)| domain);
		if recipients.is_empty() {
			return Ok(());
		}
		match build_failed(
			hostname,
			&message.reverse_path,
			&recipients,
			&message.data,
			std::time::SystemTime::now(),
		) {
			Some(bounce) => self.store_outbound(&bounce),
			None => Ok(()),
		}
	}
}
