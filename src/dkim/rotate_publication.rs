//! Confirming a rotated key in DNS before it signs.
//!
//! The provider accepting an upsert says nothing about what receivers'
//! resolvers see: a secondary may lag, the zone may not be the one the
//! domain is delegated to, or the write may have been dropped. Signing
//! with a key nobody can look up makes every message fail DKIM, so the
//! rotator queries the new selector through a resolver, retrying with
//! growing pauses, and switches only when every signing domain shows the
//! new key. When it never shows, the old key keeps signing: mail is never
//! sent unsigned and never signed with a key that cannot be verified.

use super::*;

/// Pauses between the queries that look for a new selector: about an
/// hour in all, enough to outlast the negative caching of a resolver that
/// asked for the name before it existed.
pub fn publication_waits() -> Vec<std::time::Duration> {
	[30, 60, 120, 240, 480, 900, 1800]
		.into_iter()
		.map(std::time::Duration::from_secs)
		.collect()
}

impl Rotator {
	/// Wait until `selector` publishes the key in `txt` for every signing
	/// domain. `Ok` when no check is configured.
	pub(super) async fn confirm_published(&self, selector: &str, txt: &str) -> Result<(), String> {
		let Some((resolver, waits)) = &self.publication_check else {
			return Ok(());
		};
		let expected = key_of(txt);
		let mut waits = waits.iter();
		loop {
			let mut missing = None;
			for domain in &self.signing_domains {
				let name = Self::record_name(selector, domain);
				let seen = match resolver.txt(&name).await {
					Ok(values) => values.iter().any(|value| key_of(value) == expected),
					Err(_) => false,
				};
				if !seen {
					missing = Some(name);
					break;
				}
			}
			let Some(name) = missing else {
				return Ok(());
			};
			match waits.next() {
				Some(wait) => tokio::time::sleep(*wait).await,
				None => return Err(format!("{name} does not show the new key in DNS")),
			}
		}
	}

	/// Report a rotation that was withdrawn because its key never became
	/// visible: the error file `epistle dkim show` prints, a log line and
	/// the webhook.
	pub(super) async fn report_unpublished(&self, selector: &str, reason: &str, now: u64) {
		tracing::error!(%selector, %reason, "DKIM rotation withdrawn; the current key keeps signing");
		let _ = std::fs::write(
			self.data_dir.join(ERROR_FILE),
			format!("{now} rotation to {selector} withdrawn: {reason}\n"),
		);
		if let Some(webhook) = &self.webhook {
			webhook
				.notify(&crate::webhook::WebhookEvent::DkimRotationFailed {
					selector: selector.to_string(),
					reason: reason.to_string(),
				})
				.await;
		}
	}
}

/// The `p=` value of a DKIM key record, whitespace removed, so a record
/// split into several strings or spaced differently still compares equal.
fn key_of(record: &str) -> Option<String> {
	record.split(';').find_map(|tag| {
		let (name, value) = tag.split_once('=')?;
		(name.trim() == "p").then(|| value.chars().filter(|c| !c.is_whitespace()).collect())
	})
}
