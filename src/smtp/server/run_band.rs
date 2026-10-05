//! Uncertain-band logic for the SMTP server.
//!
//! Split out of `run.rs` to keep the connection loop's code-line count
//! under the CI hard limit (500). The band is the slice of mail where the
//! local Bayesian classifier is not confident in either direction; on an
//! unauthenticated message the server consults the LLM hook (if any) and,
//! when configured, the SubjectPass signed-token path. The token path
//! refuses with `550 5.7.1` and a freshly minted token the sender can paste
//! in the `Subject:`; the resend that carries it is accepted as ham.
//!
//! The check runs after DNSBL, SPF, DMARC and the scanner hook in the
//! caller, so a valid token never overrides a hard rejection.

use tokio::io::AsyncWrite;

use super::{Server, send};
use crate::smtp::address::Address;
use crate::smtp::directory::{Directory, Resolution};
use crate::smtp::session::AcceptedMessage;

/// What the caller should do after the band has had its say.
pub(super) enum BandOutcome {
	/// Continue with the post-band path (deliver or quarantine as configured).
	Continue,
	/// A `550 5.7.1` challenge was sent to the client and the message must
	/// be dropped without being stored or trained on: the sender is
	/// expected to resend with the token in the subject, at which point the
	/// SubjectPass verifier accepts it.
	Challenged,
}

impl Server {
	/// Apply the uncertain-band logic to `message`. `is_authenticated` is
	/// precomputed by the caller so this function stays free of the
	/// session borrow. Returns `Continue` to let the caller proceed with
	/// the normal accept/quarantine path, or `Challenged` after the band
	/// has refused the message and incremented the counter.
	pub(super) async fn handle_uncertain_band<W>(
		&self,
		message: &mut AcceptedMessage,
		is_authenticated: bool,
		stream: &mut W,
	) -> Result<BandOutcome, std::io::Error>
	where
		W: AsyncWrite + Unpin,
	{
		// Authenticated mail is never consulted: the directory already
		// proves the sender's identity, so the band only acts on
		// unauthenticated traffic.
		let Some(bayes) = &self.bayes else {
			return Ok(BandOutcome::Continue);
		};
		if is_authenticated {
			return Ok(BandOutcome::Continue);
		}
		// Bounces (MAIL FROM:<>) carry no sender to challenge and no
		// subject a real person ever reads: the band must not get in their
		// way. Continue down the normal accept/quarantine path.
		if message.reverse_path.is_empty() {
			return Ok(BandOutcome::Continue);
		}
		// An upstream scanner (or any other screening hook the run loop
		// ran before the band) has already set a destination mailbox, so
		// it has also already trained the message and decided what to do
		// with it. A SubjectPass challenge would discard the message
		// without training, contradicting that decision and quietly
		// retraining the spam corpus on every retry. Stay out of the
		// way and let the run loop deliver the message to the chosen
		// mailbox.
		if message.mailbox.is_some() {
			return Ok(BandOutcome::Continue);
		}

		// Per-account scope: the first recipient that resolves to a local
		// account wins, in envelope order. A scope with no own training
		// falls back to the shared corpus inside `score_for_account`, so
		// an account that has never marked a message still gets the
		// server's general training. With no resolvable recipient the
		// band consults the shared corpus directly: nothing the
		// per-account scope would have answered could change the
		// outcome.
		let account = scoring_account(&self.directory.current(), &message.recipients);
		let scope = account
			.as_deref()
			.unwrap_or(crate::antispam::corpus::SHARED);
		let score = match bayes.score_for_account(scope, &message.data).await {
			Some(score) => score,
			None => {
				// Score failed (DB hiccup or missing trainer); treat the
				// message as outside the band (Accept) rather than
				// blocking mail.
				self.metrics.llm_failed();
				tracing::warn!("llm band score unavailable; accepting");
				return Ok(BandOutcome::Continue);
			}
		};

		// The band is bounded by the LLM hook when one is configured;
		// without an LLM the entire `[0, 1]` range is the band, so the
		// SubjectPass challenge path always runs.
		let in_band = self
			.llm
			.as_ref()
			.map(|llm| llm.is_uncertain(score))
			.unwrap_or(true);
		if !in_band {
			return Ok(BandOutcome::Continue);
		}

		let Some(pass) = &self.subjectpass else {
			// No SubjectPass configured: defer to the LLM hook only.
			return self.handle_llm_only(message).await;
		};

		let subject = crate::antispam::subjectpass::header_value(&message.data, "subject");
		let recipient = message.recipients.first().map(String::as_str).unwrap_or("");
		let day = unix_day_now();

		// Token in the subject: accept the message as ham and skip the band.
		if pass.accepts(subject.as_deref(), &message.reverse_path, recipient, day) {
			self.metrics.subjectpass_passed();
			return Ok(BandOutcome::Continue);
		}

		// No valid token: try the LLM hook if one is configured. A
		// `Failed` outcome falls through to the challenge.
		if let Some(llm) = &self.llm {
			self.metrics.llm_consulted();
			match llm.classifier.consult(&message.data).await {
				crate::antispam::llm::ConsultOutcome::Verdict(
					crate::antispam::hook::HookVerdict::Quarantine,
				) => {
					self.metrics.llm_quarantined();
					self.train_corpus(&message.data, true);
					message.mailbox = Some("Rejects".to_string());
					return Ok(BandOutcome::Continue);
				}
				crate::antispam::llm::ConsultOutcome::Verdict(_) => {
					return Ok(BandOutcome::Continue);
				}
				crate::antispam::llm::ConsultOutcome::Failed => {
					self.metrics.llm_failed();
					send(
						stream,
						&crate::antispam::subjectpass::challenge_reply(
							pass,
							&message.reverse_path,
							recipient,
							day,
						),
					)
					.await?;
					self.metrics.subjectpass_challenged();
					return Ok(BandOutcome::Challenged);
				}
			}
		}

		// No LLM, no token: challenge.
		send(
			stream,
			&crate::antispam::subjectpass::challenge_reply(
				pass,
				&message.reverse_path,
				recipient,
				day,
			),
		)
		.await?;
		self.metrics.subjectpass_challenged();
		Ok(BandOutcome::Challenged)
	}

	/// Apply the LLM-only band path (SubjectPass disabled). Same as the
	/// historical behaviour: consult the hook, accept on `Accept`, drop
	/// to `Rejects` on `Quarantine`, fail open on `Failed`.
	async fn handle_llm_only(
		&self,
		message: &mut AcceptedMessage,
	) -> Result<BandOutcome, std::io::Error> {
		let Some(llm) = &self.llm else {
			return Ok(BandOutcome::Continue);
		};
		self.metrics.llm_consulted();
		match llm.classifier.consult(&message.data).await {
			crate::antispam::llm::ConsultOutcome::Verdict(
				crate::antispam::hook::HookVerdict::Quarantine,
			) => {
				self.metrics.llm_quarantined();
				self.train_corpus(&message.data, true);
				message.mailbox = Some("Rejects".to_string());
			}
			crate::antispam::llm::ConsultOutcome::Verdict(_) => {}
			crate::antispam::llm::ConsultOutcome::Failed => {
				self.metrics.llm_failed();
			}
		}
		Ok(BandOutcome::Continue)
	}
}

/// Pick the account name the uncertain-band scorer should ask the corpus
/// to score `text` against.
///
/// The governing account is the first recipient in envelope order that
/// resolves to a local account:
/// - `Resolution::Account(name)` contributes `name`;
/// - `Resolution::Alias(targets)` contributes the first target (the
///   multi-target alias is local by construction, so its members are
///   themselves accounts);
/// - `Resolution::NotLocal`, `Resolution::UnknownUser`, and an address
///   that fails `Address::parse` are skipped, as a remote recipient is
///   not an account this server trains for, and an unknown local user
///   has no account name to key on.
///
/// The first hit wins so two recipients in the same message never
/// disagree about which scope is consulted: the envelope order is the
/// order RCPT TO delivered them. For a multi-target alias only its first
/// target is ever consulted.
///
/// Returning `None` means "no local recipient at all", so the caller
/// scores against the shared corpus directly (see
/// [`crate::antispam::corpus::SHARED`]).
fn scoring_account(directory: &Directory, recipients: &[String]) -> Option<String> {
	for recipient in recipients {
		let Ok(address) = Address::parse(recipient) else {
			continue;
		};
		match directory.resolve(&address) {
			Resolution::Account(name) => return Some(name),
			Resolution::Alias(mut targets) if !targets.is_empty() => {
				return Some(targets.remove(0));
			}
			Resolution::Alias(_) | Resolution::NotLocal | Resolution::UnknownUser => continue,
		}
	}
	None
}

/// Today's day stamp as `unix_seconds / 86400`. SubjectPass binds its HMAC
/// to the same 2-character base32 day stamp SRS uses, so today and
/// yesterday are both valid for a fresh token.
fn unix_day_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0)
}

#[cfg(test)]
#[path = "run_band_tests.rs"]
mod tests;
