//! Shared side effects for removing a queued message.

use std::path::Path;
use std::sync::Arc;

use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord, Envelope, FsSpool};

/// Remove one entry, then record its pending recipients and notify the webhook.
pub fn remove(
	spool: &FsSpool,
	evidence_root: &Path,
	data_dir: &Path,
	retention_days: u64,
	id: uuid::Uuid,
	now: u64,
	webhook: Option<&Arc<crate::webhook::Webhook>>,
) -> std::io::Result<Envelope> {
	let envelope = crate::evidence::cancel::remove(spool, evidence_root, id)?;
	let log = DeliveryLog::open(data_dir, retention_days);
	if log.is_enabled() {
		for recipient in &envelope.recipients {
			let state = envelope.recipient_state(recipient);
			if state.status != crate::storage::RecipientStatus::Pending {
				continue;
			}
			let record = DeliveryRecord {
				time: now,
				spool_id: id,
				account: envelope.account.clone(),
				from: envelope.reverse_path.clone(),
				recipient: recipient.clone(),
				outcome: DeliveryOutcome::Canceled,
				remote: state.remote.clone(),
				reply: state.last_error.clone(),
				attempt: state.attempts,
				extra: envelope.extra.clone(),
				class: envelope.class,
			};
			if let Err(error) = log.append(&record) {
				tracing::warn!(%id, %error, "delivery log write failed");
			}
			if let Some(webhook) = webhook {
				notify(
					webhook,
					crate::webhook::WebhookEvent::Canceled {
						spool_id: id,
						recipient: recipient.clone(),
						extra: envelope.extra.clone(),
					},
				);
			}
		}
	}
	Ok(envelope)
}

fn notify(webhook: &Arc<crate::webhook::Webhook>, event: crate::webhook::WebhookEvent) {
	let webhook = Arc::clone(webhook);
	if let Ok(handle) = tokio::runtime::Handle::try_current() {
		handle.spawn(async move { webhook.notify(&event).await });
		return;
	}
	match tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime.block_on(async {
			let wait = std::time::Duration::from_secs(10);
			let _ = tokio::time::timeout(wait, webhook.notify(&event)).await;
		}),
		Err(error) => tracing::warn!(%error, "no runtime to post the webhook event"),
	}
}
