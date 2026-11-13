//! What `rotate --all` asks before it starts and prints when it is done.

use std::io::{self, Write};

use serde_json::{Value, json};

use super::journal::{Journal, Kind, State, Step};
use super::secrets::Secrets;
use crate::cli::json_out::Reload;
use crate::cli::rotate::plan::{describe, handling_json};
use crate::cli::rotate::registry::entries;

/// The registry rows a run carries out. Every other row is left to the
/// operator and listed at the end.
pub(in crate::cli::rotate) const HANDLED: &[(Kind, &str)] = &[
	(Kind::ApiKey, "api-key"),
	(Kind::AppPassword, "app-password"),
	(Kind::WebhookSecret, "webhook-secret"),
	(Kind::SrsSecret, "srs-secret"),
	(Kind::DkimKey, "dkim-signing-key"),
	(Kind::DkimDomainKey, "dkim-signing-key"),
];

fn count(journal: &Journal, kind: Kind) -> usize {
	journal
		.steps
		.iter()
		.filter(|step| step.kind == kind)
		.count()
}

/// The question asked before the run changes anything.
pub(in crate::cli::rotate) fn question(journal: &Journal, resumed: bool) -> String {
	if resumed {
		let left = journal
			.steps
			.iter()
			.filter(|step| step.state != State::Done)
			.count();
		return format!(
			"Continue the rotation started at {}? {left} of {} steps are left; the ones done stay \
			 done. [y/N] ",
			crate::clock::rfc3339_or_epoch(journal.started_at),
			journal.steps.len()
		);
	}
	let mut parts = vec![format!(
		"{} API keys and {} app passwords get a new secret, and the old one stops working at once",
		count(journal, Kind::ApiKey),
		count(journal, Kind::AppPassword)
	)];
	if count(journal, Kind::WebhookSecret) > 0 {
		parts.push("the webhook receiver must be given the new secret".to_string());
	}
	let srs = count(journal, Kind::SrsSecret);
	if srs > 0 {
		parts.push(format!(
			"the SRS secret of {srs} domains is replaced, the old one verifying for 14 days"
		));
	}
	let dkim = count(journal, Kind::DkimKey) + count(journal, Kind::DkimDomainKey);
	if dkim > 0 {
		parts.push(format!("the server rotates and publishes {dkim} DKIM keys"));
	}
	if count(journal, Kind::Restart) > 0 {
		parts.push("the mail service is restarted".to_string());
	}
	format!(
		"Rotate every secret epistle can rotate on this server? {}. The new secrets are printed \
		 once, at the end. [y/N] ",
		parts.join("; ")
	)
}

fn kind_name(kind: Kind) -> String {
	serde_json::to_value(kind)
		.ok()
		.and_then(|value| value.as_str().map(str::to_string))
		.unwrap_or_default()
}

/// How a step is named in the text output and in a refusal.
pub(super) fn label(step: &Step) -> String {
	match (&step.owner, step.item.is_empty()) {
		(Some(owner), _) => format!("{} {owner} {}", kind_name(step.kind), step.item),
		(None, true) => kind_name(step.kind),
		(None, false) => format!("{} {}", kind_name(step.kind), step.item),
	}
}

fn result(step: &Step, reload: Option<Reload>) -> &'static str {
	match step.kind {
		Kind::DkimKey | Kind::DkimDomainKey => "queued",
		Kind::Restart => reload.map_or("restarted", Reload::name),
		_ => "rotated",
	}
}

/// Whether the step's new secret is handed to the operator. An SRS secret
/// never leaves the server.
fn shown(kind: Kind) -> bool {
	matches!(kind, Kind::ApiKey | Kind::AppPassword | Kind::WebhookSecret)
}

/// The registry rows this run did not carry out, and what the operator
/// still does after the rows it did.
fn remaining() -> (Vec<Value>, Vec<String>) {
	let handled = |id: &str| HANDLED.iter().any(|(_, row)| *row == id);
	let left = entries()
		.filter(|entry| !handled(entry.id))
		.map(|entry| {
			json!({
				"id": entry.id, "name": entry.name,
				"rotate": handling_json(&entry.rotate), "text": describe(&entry.rotate),
			})
		})
		.collect();
	let after = entries()
		.filter(|entry| handled(entry.id))
		.flat_map(|entry| {
			entry
				.operator_after
				.iter()
				.map(|step| format!("{}: {step}", entry.id))
		})
		.collect();
	(left, after)
}

/// Print what the run did, the new secrets and what is left.
pub(in crate::cli::rotate) fn print(
	out: &mut impl Write,
	journal: &Journal,
	secrets: &Secrets,
	(resumed, reload): (bool, Option<Reload>),
	json: bool,
) -> io::Result<()> {
	let handed: Vec<(&Step, &str)> = journal
		.steps
		.iter()
		.filter(|step| shown(step.kind))
		.filter_map(|step| secrets.get(&step.secret_key()).map(|secret| (step, secret)))
		.collect();
	let (left, after) = remaining();
	if json {
		let steps: Vec<Value> = journal
			.steps
			.iter()
			.map(|step| {
				json!({ "kind": step.kind, "item": step.item, "owner": step.owner, "result": result(step, reload) })
			})
			.collect();
		let handed: Vec<Value> = handed
			.iter()
			.map(|(step, secret)| {
				json!({ "kind": step.kind, "item": step.item, "owner": step.owner, "secret": secret })
			})
			.collect();
		let shown = json!({
			"result": "rotated", "resumed": resumed, "started_at": journal.started_at,
			"steps": steps, "secrets": handed, "reload": reload.map(Reload::name),
			"notes": journal.notes, "then": after, "remaining": left,
		});
		serde_json::to_writer(&mut *out, &shown)?;
		return writeln!(out);
	}
	if resumed {
		writeln!(
			out,
			"Finished the rotation started at {}.",
			crate::clock::rfc3339_or_epoch(journal.started_at)
		)?;
	}
	for step in &journal.steps {
		writeln!(out, "{:<40} {}", label(step), result(step, reload))?;
	}
	if journal
		.steps
		.iter()
		.any(|step| matches!(step.kind, Kind::DkimKey | Kind::DkimDomainKey))
	{
		writeln!(
			out,
			"The running server rotates the queued DKIM keys within a minute and publishes their \
			 records; follow them with `epistle dkim show`."
		)?;
	}
	if !handed.is_empty() {
		writeln!(out, "\nNew secrets, shown once:")?;
		for (step, secret) in &handed {
			writeln!(out, "  {}: {secret}", label(step))?;
		}
	}
	writeln!(out, "\nStill to do:")?;
	for line in journal.notes.iter().chain(after.iter()) {
		writeln!(out, "  - {line}")?;
	}
	for row in &left {
		writeln!(
			out,
			"  - {}: {}",
			row["id"].as_str().unwrap_or_default(),
			row["text"].as_str().unwrap_or_default()
		)?;
	}
	Ok(())
}
