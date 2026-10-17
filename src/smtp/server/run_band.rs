//! Uncertain-band logic and the Bayesian thresholds that decide on
//! their own for the SMTP server.
//!
//! Split out of `run.rs` to keep the connection loop's code-line count
//! under the CI hard limit (500). Two checks live here:
//!
//! - The uncertain band: the slice of mail where the local Bayesian
//!   classifier is not confident in either direction; on an
//!   unauthenticated message the server consults the LLM hook (if any)
//!   and, when configured, the SubjectPass signed-token path. The token
//!   path refuses with `550 5.7.1` and a freshly minted token the sender
//!   can paste in the `Subject:`; the resend that carries it is accepted
//!   as ham.
//! - The Bayesian thresholds (`bayes_junk_at`, `bayes_reject_at`):
//!   delivered to the recipient's Junk mailbox or refused at DATA
//!   before the LLM is even asked, because a high-confidence score is
//!   its own decision. Authenticated sessions never get scored;
//!   an under-trained corpus never decides.
//!
//! Both checks run after DNSBL, SPF, DMARC and the scanner hook in the
//! caller, so a hard rejection from any of those still wins.

use tokio::io::AsyncWrite;

use super::{Reply, Server, send};
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

/// What the caller should do after the score-threshold pass: the message
/// either continues through the rest of the SMTP pipeline, lands in the
/// recipient's Junk mailbox with `X-Spam-Status: Yes`, or has already
/// been refused with a `550 5.7.1`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BayesOutcome {
	/// Below every configured threshold: hand the message to the next
	/// stage of the SMTP pipeline (the LLM band, the reputation hook,
	/// delivery).
	Continue,
	/// The Bayesian score sits at or above `bayes_junk_at` but below
	/// `bayes_reject_at`. The caller delivers the message to the
	/// recipient's Junk mailbox after stamping `X-Spam-Status: Yes` and
	/// `X-Spam-Score: <value>` headers on it.
	SendToJunk,
	/// The Bayesian score sits at or above `bayes_reject_at`. A
	/// `550 5.7.1` line was sent; the message must not be stored or
	/// trained on.
	Rejected,
}

impl Server {
	/// Apply the two Bayesian thresholds: a score at or above
	/// `bayes_junk_at` lands in the Junk mailbox (with the spam-marking
	/// headers stamped on it); a score at or above `bayes_reject_at` is
	/// refused at DATA with `550 5.7.1`. The minimum-training guard is
	/// the same one the per-account scope already enforces:
	/// [`MIN_TRUSTED_MESSAGES`](crate::antispam::trainer::MIN_TRUSTED_MESSAGES)
	/// ham AND spam messages on the resolved scope. Below that bar, the
	/// function returns `Continue` so a fresh corpus cannot junk or
	/// reject anything.
	///
	/// Authenticated sessions are never scored (the directory has
	/// already proven identity), and bounces (`MAIL FROM:<>`) are also
	/// skipped so the verdict never lands on a verification DSN.
	pub(super) async fn handle_bayes_thresholds<W>(
		&self,
		message: &mut AcceptedMessage,
		is_authenticated: bool,
		stream: &mut W,
	) -> Result<BayesOutcome, std::io::Error>
	where
		W: AsyncWrite + Unpin,
	{
		let Some(bayes) = &self.bayes else {
			return Ok(BayesOutcome::Continue);
		};
		if is_authenticated {
			return Ok(BayesOutcome::Continue);
		}
		// A bounce has no token, no subject, and a recipient the relay
		// server sends to automatically; the verdict can only ever land
		// in the recipient's Junk folder, which is the wrong place for a
		// delivery-failure DSN. Skip.
		if message.reverse_path.is_empty() {
			return Ok(BayesOutcome::Continue);
		}
		// An upstream screening hook already routed the message. The
		// Bayes thresholds would second-guess a clamd verdict or the
		// poor-reputation path and risk undoing the in-process training
		// they already did. Stay out of the way.
		if message.mailbox.is_some() {
			return Ok(BayesOutcome::Continue);
		}

		// Same scope the uncertain band picks: the only local account of
		// the envelope, or the shared scope for anything else (see
		// `scoring_account`). The trusted-or-not check looks at that
		// scope's totals so the minimum-training guard is the one the
		// band already validated.
		let account = scoring_account(&self.directory.current(), &message.recipients);
		let scope = account
			.as_deref()
			.unwrap_or(crate::antispam::corpus::SHARED);

		if !bayes.is_trusted(scope).await {
			return Ok(BayesOutcome::Continue);
		}

		// If both thresholds are unreachable, the function could only
		// ever return `Continue`. Skip the score call so the existing
		// single-call contracts the SMTP server's wiring relies on do
		// not silently drift.
		let reject_active = self
			.bayes_reject_at
			.is_some_and(|reject_at| reject_at <= 1.0);
		if self.bayes_junk_at >= 1.0 && !reject_active {
			return Ok(BayesOutcome::Continue);
		}

		let score = match bayes.score_for_account(scope, &message.data).await {
			Some(score) => score,
			None => {
				// Score failure (DB hiccup). Fail open: continue down
				// the band rather than blocking mail or junking every
				// message because the corpus is unreachable.
				self.metrics.llm_failed();
				tracing::warn!("bayes score unavailable; continuing without a threshold decision");
				return Ok(BayesOutcome::Continue);
			}
		};

		if let Some(reject_at) = self.bayes_reject_at
			&& score >= reject_at
		{
			tracing::info!(score, reject_at, "bayes: rejecting at DATA with 550 5.7.1");
			send(
				stream,
				&Reply::single(550, "5.7.1 message rejected as spam"),
			)
			.await?;
			return Ok(BayesOutcome::Rejected);
		}
		if score >= self.bayes_junk_at {
			tracing::info!(
				score,
				junk_at = self.bayes_junk_at,
				"bayes: routing to Junk"
			);
			message.data = crate::smtp::trace::inject_spam_headers(&message.data, score);
			// "Junk" maps to the IMAP `\Junk` special-use mailbox via
			// the helper in `imap/session/helpers.rs`. The historical
			// "Rejects" alias still works; the threshold-based path uses
			// "Junk" so the prefix lines up with what the user sees.
			message.mailbox = Some("Junk".to_string());
			return Ok(BayesOutcome::SendToJunk);
		}
		Ok(BayesOutcome::Continue)
	}

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

		// Per-account scope only when one account is the whole local
		// audience of the message (see `scoring_account`). A scope with no
		// own training falls back to the shared corpus inside
		// `score_for_account`, so an account that has never marked a
		// message still gets the server's general training. Otherwise the
		// band consults the shared corpus directly.
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
		let day = unix_day_now();
		// Every envelope recipient needs its own authorization. Challenge
		// the first uncovered recipient so a retry can add the missing token.
		let recipient = message.recipients.iter().find(|recipient| {
			!pass.accepts(subject.as_deref(), &message.reverse_path, recipient, day)
		});
		if !message.recipients.is_empty() && recipient.is_none() {
			self.metrics.subjectpass_passed();
			return Ok(BandOutcome::Continue);
		}
		let recipient = recipient.map(String::as_str).unwrap_or("");

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

/// Pick the account whose own corpus may score a message, or `None` when
/// only the shared corpus may.
///
/// A message is scored once and the verdict (Junk, a `550` at DATA, the
/// destination mailbox) applies to every recipient of the transaction. An
/// account's corpus is whatever its owner taught it, so using it for mail
/// that other accounts receive would let one user decide what the others
/// see: an account that teaches its own corpus a spammer's text as ham
/// would let that spam through to anyone addressed alongside it. The rule:
/// - exactly one local account among the recipients, and it was addressed
///   as itself (`Resolution::Account`): that account;
/// - two or more distinct local accounts, or any recipient that is an
///   alias or a list (`Resolution::Alias`, which fans the verdict out to
///   its members): `None`, the shared corpus scores it;
/// - `Resolution::NotLocal`, `Resolution::UnknownUser`, an address that
///   fails `Address::parse` and an alias with no member are skipped: they
///   are not an account the verdict can reach.
///
/// The same account addressed twice (two of its addresses, a domain alias)
/// is still one account. The envelope order never matters. `None` also
/// covers "no local recipient at all", and the caller scores against the
/// shared corpus (see [`crate::antispam::corpus::SHARED`]).
fn scoring_account(directory: &Directory, recipients: &[String]) -> Option<String> {
	let mut account: Option<String> = None;
	for recipient in recipients {
		let Ok(address) = Address::parse(recipient) else {
			continue;
		};
		match directory.resolve(&address) {
			Resolution::Account(name) => match &account {
				Some(first) if *first != name => return None,
				Some(_) => {}
				None => account = Some(name),
			},
			Resolution::Alias(targets) if !targets.is_empty() => return None,
			Resolution::Alias(_) | Resolution::NotLocal | Resolution::UnknownUser => {}
		}
	}
	account
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

#[cfg(test)]
#[path = "run_band_tests_bayes.rs"]
mod tests_bayes;
