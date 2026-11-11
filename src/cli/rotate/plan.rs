//! What `rotate --all --dry-run` prints: one block per registry entry.

use std::io::{self, Write};

use serde_json::{Value, json};

use super::registry::{Entry, Handling, TRACKING_ISSUE, entries, issue_url};

/// How a handling reads in the text output.
fn describe(handling: &Handling) -> String {
	match handling {
		Handling::Epistle(how) => format!("epistle: {how}"),
		Handling::Operator(how) => format!("operator: {how}"),
		Handling::Unsupported { issue, meanwhile } => format!(
			"not supported yet ({}); meanwhile: {meanwhile}",
			issue_url(*issue)
		),
	}
}

fn handling_json(handling: &Handling) -> Value {
	match handling {
		Handling::Epistle(how) | Handling::Operator(how) => {
			json!({ "by": handling.actor(), "how": how })
		}
		Handling::Unsupported { issue, meanwhile } => json!({
			"by": handling.actor(),
			"issue": issue,
			"issue_url": issue_url(*issue),
			"meanwhile": meanwhile,
		}),
	}
}

fn count(pick: impl Fn(&Entry) -> &Handling, actor: &str) -> usize {
	entries()
		.filter(|entry| pick(entry).actor() == actor)
		.count()
}

/// The plan as text for a person.
pub(super) fn text(out: &mut impl Write) -> io::Result<()> {
	let total = entries().count();
	writeln!(
		out,
		"Dry run: nothing was changed. {total} kinds of secret and credential.\n"
	)?;
	for entry in entries() {
		writeln!(out, "{}  {}", entry.id, entry.name)?;
		writeln!(out, "  stored in  {}", entry.stored_in)?;
		writeln!(out, "  rotate     {}", describe(&entry.rotate))?;
		writeln!(out, "  revoke     {}", describe(&entry.revoke))?;
		for step in entry.operator_after {
			writeln!(out, "  then you   {step}")?;
		}
		writeln!(out)?;
	}
	for (verb, pick) in [
		("rotate", (|e: &Entry| &e.rotate) as fn(&Entry) -> &Handling),
		("revoke", |e: &Entry| &e.revoke),
	] {
		writeln!(
			out,
			"{verb}: {} by epistle, {} by the operator, {} not supported yet",
			count(pick, "epistle"),
			count(pick, "operator"),
			count(pick, "unsupported"),
		)?;
	}
	writeln!(
		out,
		"\nAlso outside the server: the DNS records to publish, the credentials to change at the \
		 DNS provider and the database, and the certificate to renew. Everything above is \
		 generated on a clean machine after the server is rebuilt; rotating on a host that is \
		 still compromised achieves nothing. Tracked in {}.",
		issue_url(TRACKING_ISSUE)
	)
}

/// The plan as one JSON object.
pub(super) fn json(out: &mut impl Write) -> io::Result<()> {
	let rows: Vec<Value> = entries()
		.map(|entry| {
			json!({
				"id": entry.id,
				"name": entry.name,
				"stored_in": entry.stored_in,
				"config_fields": entry.config_fields,
				"rotate": handling_json(&entry.rotate),
				"revoke": handling_json(&entry.revoke),
				"operator_after": entry.operator_after,
			})
		})
		.collect();
	let shown =
		json!({ "dry_run": true, "entries": rows, "tracking_issue": issue_url(TRACKING_ISSUE) });
	serde_json::to_writer(&mut *out, &shown)?;
	writeln!(out)
}
