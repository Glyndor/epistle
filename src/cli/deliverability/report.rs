//! The report: what was sent, what happened to it, and what the outside
//! will read about it.

use std::io::Write;

use serde::Serialize;
use uuid::Uuid;

use super::Signing;
use super::checks::{Item, Level};
use super::delivery::Delivery;
use super::plan::Plan;
use crate::cli::term::sanitize;

/// The one thing a first test cannot say.
const REPUTATION_NOTE: &str = "A new address has no reputation yet, so what a first test shows says little about steady state; see `epistle warmup`.";

/// The whole result of one run.
#[derive(Debug, Serialize)]
pub(super) struct Report {
	pub account: String,
	pub from: String,
	pub to: String,
	/// The queue id of the message, the one `epistle delivery show` takes.
	pub message: Uuid,
	/// How the message was signed.
	pub signing: Signing,
	pub delivery: Delivery,
	pub checks: Vec<Item>,
}

impl Report {
	pub(super) fn new(
		plan: &Plan,
		message: Uuid,
		signing: Signing,
		delivery: Delivery,
		checks: Vec<Item>,
	) -> Self {
		Self {
			account: plan.account.clone(),
			from: plan.from.clone(),
			to: plan.to.clone(),
			message,
			signing,
			delivery,
			checks,
		}
	}

	/// A check failed, the message was refused for good, or it went out
	/// unsigned although a key is configured.
	pub(super) fn failed(&self) -> bool {
		self.delivery.is_failure()
			|| self.signing == Signing::Failed
			|| self.checks.iter().any(|item| item.level == Level::Fail)
	}

	/// The report as text, every value that came from outside escaped.
	pub(super) fn write_text(&self, out: &mut impl Write) -> std::io::Result<()> {
		writeln!(out, "account   {}", sanitize(&self.account))?;
		writeln!(out, "from      {}", sanitize(&self.from))?;
		writeln!(out, "to        {}", sanitize(&self.to))?;
		writeln!(out, "message   {}", self.message)?;
		writeln!(out, "signing   {}", self.signing.sentence())?;
		writeln!(out, "delivery  {}", self.delivery.state)?;
		if let Some(remote) = &self.delivery.remote {
			writeln!(out, "  remote   {remote}")?;
		}
		if let Some(reply) = &self.delivery.reply {
			writeln!(out, "  reply    {reply}")?;
		}
		writeln!(out, "  meaning  {}", self.delivery.explanation)?;
		writeln!(out, "checks")?;
		for item in &self.checks {
			let level = match item.level {
				Level::Pass => "pass",
				Level::Warn => "warn",
				Level::Fail => "FAIL",
				Level::Unknown => "unknown",
			};
			writeln!(
				out,
				"  {:<6} {:<8} {}",
				item.check,
				level,
				sanitize(&item.detail)
			)?;
		}
		writeln!(out, "{REPUTATION_NOTE}")
	}
}

/// What a run without `--yes` shows, and stops.
pub(super) fn write_plan(plan: &Plan, out: &mut impl Write) -> std::io::Result<()> {
	writeln!(out, "would send one test message")?;
	writeln!(out, "account   {}", sanitize(&plan.account))?;
	writeln!(out, "from      {}", sanitize(&plan.from))?;
	writeln!(out, "to        {}", sanitize(&plan.to))?;
	writeln!(
		out,
		"It goes out through this server's own queue, DKIM-signed, from its sending address.\nOne test is allowed per minute per server. Run again with --yes to send it."
	)
}

/// What a run without `--yes` shows with `--json`: one document, so a
/// consumer that parses stdout does not choke on the text.
pub(super) fn write_plan_json(plan: &Plan, out: &mut impl Write) -> std::io::Result<()> {
	serde_json::to_writer(
		&mut *out,
		&serde_json::json!({
			"would_send": true,
			"account": plan.account,
			"from": plan.from,
			"to": plan.to,
		}),
	)
	.map_err(std::io::Error::other)?;
	writeln!(out)
}
