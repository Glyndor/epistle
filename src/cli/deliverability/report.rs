//! The report: what was sent, what happened to it, and what the outside
//! will read about it.

use std::io::Write;

use serde::Serialize;
use uuid::Uuid;

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
	pub delivery: Delivery,
	pub checks: Vec<Item>,
}

impl Report {
	pub(super) fn new(plan: &Plan, message: Uuid, delivery: Delivery, checks: Vec<Item>) -> Self {
		Self {
			account: plan.account.clone(),
			from: plan.from.clone(),
			to: plan.to.clone(),
			message,
			delivery,
			checks,
		}
	}

	/// A check failed or the message was refused for good.
	pub(super) fn failed(&self) -> bool {
		self.delivery.is_failure() || self.checks.iter().any(|item| item.level == Level::Fail)
	}

	/// The report as text, every value that came from outside escaped.
	pub(super) fn write_text(&self, out: &mut impl Write) -> std::io::Result<()> {
		writeln!(out, "account   {}", sanitize(&self.account))?;
		writeln!(out, "from      {}", sanitize(&self.from))?;
		writeln!(out, "to        {}", sanitize(&self.to))?;
		writeln!(out, "message   {}", self.message)?;
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
