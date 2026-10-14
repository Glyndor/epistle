//! The DMARC part of the lockdown: the policy moves one step per run
//! (`none`, then `quarantine`, then `reject`), `sp=` follows `p=`, and
//! `np=reject` (DMARCbis, draft-ietf-dmarc-dmarcbis) is set at once
//! because it only covers names that do not exist. Every other tag the
//! operator wrote (`rua`, `ruf`, `adkim`, `aspf`, `fo`, `ri`, anything
//! newer) is kept as written; `pct` is dropped because DMARCbis removed it.
//! A record this module cannot read is left alone and reported.

use serde::{Deserialize, Serialize};

use super::{Journal, PlanEntry, TTL, canonical_name};
use crate::dns::provider::{DnsRecord, RecordKind, txt_purpose};

/// A DMARC policy (`p=`), ordered from the weakest to the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcStep {
	/// `p=none`: receivers only report.
	None,
	/// `p=quarantine`: receivers file failing mail as spam.
	Quarantine,
	/// `p=reject`: receivers refuse failing mail. The last step.
	Reject,
}

impl DmarcStep {
	/// The tag value: `none`, `quarantine` or `reject`.
	pub fn as_str(self) -> &'static str {
		match self {
			DmarcStep::None => "none",
			DmarcStep::Quarantine => "quarantine",
			DmarcStep::Reject => "reject",
		}
	}

	fn parse(value: &str) -> Option<Self> {
		match value.to_ascii_lowercase().as_str() {
			"none" => Some(DmarcStep::None),
			"quarantine" => Some(DmarcStep::Quarantine),
			"reject" => Some(DmarcStep::Reject),
			_ => None,
		}
	}

	/// The step after this one; `reject` stays `reject`.
	pub fn next(self) -> Self {
		match self {
			DmarcStep::None => DmarcStep::Quarantine,
			DmarcStep::Quarantine | DmarcStep::Reject => DmarcStep::Reject,
		}
	}
}

/// A sending source that failed DMARC in the recent aggregate reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailingSource {
	/// The source IP the receivers reported.
	pub source_ip: String,
	/// How many messages from it failed, summed over the reports.
	pub messages: u64,
}

/// What the plan reads about DMARC besides the zone.
#[derive(Debug, Clone, Default)]
pub struct DmarcInputs {
	/// `--dmarc reject`: go straight to `reject`.
	pub jump_to: Option<DmarcStep>,
	/// Whether any aggregate report for the domain was found in the window.
	pub has_reports: bool,
	/// The sources that failed DMARC in those reports.
	pub failing_sources: Vec<FailingSource>,
}

/// What this run does with the DMARC record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DmarcAction {
	/// The plan writes the record in its entries.
	Publish,
	/// The record already says what this run would write.
	Unchanged,
	/// The record cannot be read or rewritten safely; nothing is written.
	LeftAlone {
		/// Why.
		reason: String,
	},
}

/// The DMARC part of the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcPlan {
	/// `_dmarc.<domain>`.
	pub name: String,
	/// The published policy, or `None` when there is no DMARC record.
	pub current: Option<DmarcStep>,
	/// The policy after this run.
	pub next: DmarcStep,
	/// Whether `--dmarc reject` asked for the jump.
	pub jumped: bool,
	/// What this run does.
	pub action: DmarcAction,
	/// Whether any aggregate report for the domain was found.
	pub has_reports: bool,
	/// The sources that failed DMARC in those reports.
	pub failing_sources: Vec<FailingSource>,
}

impl DmarcPlan {
	/// Whether this run makes the policy stricter, the moment the failing
	/// sources are a warning.
	pub fn steps_up(&self) -> bool {
		self.action == DmarcAction::Publish && self.next > self.current.unwrap_or(DmarcStep::None)
	}
}

/// A DMARC record read into its tags, in the order written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcTags {
	tags: Vec<(String, String)>,
}

impl DmarcTags {
	fn get(&self, tag: &str) -> Option<&str> {
		self.tags
			.iter()
			.find(|(name, _)| name.eq_ignore_ascii_case(tag))
			.map(|(_, value)| value.as_str())
	}

	/// The `p=` policy.
	pub fn policy(&self) -> DmarcStep {
		self.get("p")
			.and_then(DmarcStep::parse)
			.unwrap_or(DmarcStep::None)
	}
}

/// Read a DMARC value (RFC 7489 section 6.3) into its tags. Refused: a
/// part without `=`, an empty tag name, a tag written twice, a first tag
/// other than `v=DMARC1`, a missing `p=`, and a `p=` or `sp=` that is not
/// `none`, `quarantine` or `reject`. The error names the problem.
pub fn parse_dmarc(value: &str) -> Result<DmarcTags, String> {
	let logical = crate::dns::txt::txt_logical(value);
	let mut tags: Vec<(String, String)> = Vec::new();
	for part in logical.split(';') {
		let part = part.trim();
		if part.is_empty() {
			continue;
		}
		let Some((name, value)) = part.split_once('=') else {
			return Err(format!("\"{part}\" has no ="));
		};
		let (name, value) = (name.trim(), value.trim());
		if name.is_empty() {
			return Err(format!("\"{part}\" has no tag name"));
		}
		if tags.iter().any(|(seen, _)| seen.eq_ignore_ascii_case(name)) {
			return Err(format!("the {name} tag is written twice"));
		}
		tags.push((name.to_string(), value.to_string()));
	}
	match tags.first() {
		Some((name, value))
			if name.eq_ignore_ascii_case("v") && value.eq_ignore_ascii_case("DMARC1") => {}
		_ => return Err("it does not start with v=DMARC1".to_string()),
	}
	let tags = DmarcTags { tags };
	let Some(policy) = tags.get("p") else {
		return Err("it has no p= tag".to_string());
	};
	for (tag, value) in [("p", Some(policy)), ("sp", tags.get("sp"))] {
		if let Some(value) = value
			&& DmarcStep::parse(value).is_none()
		{
			return Err(format!("{tag}={value} is not none, quarantine or reject"));
		}
	}
	Ok(tags)
}

/// The DMARC value for `step`: `v=DMARC1; p=<step>; sp=<step>;
/// np=reject`, then every other tag of `existing` as written, without
/// `pct`.
pub fn rewrite_dmarc(existing: Option<&DmarcTags>, step: DmarcStep) -> String {
	let mut value = format!(
		"v=DMARC1; p={step}; sp={step}; np=reject",
		step = step.as_str()
	);
	for (name, tag_value) in existing.map(|t| t.tags.as_slice()).unwrap_or_default() {
		if ["v", "p", "sp", "np", "pct"]
			.iter()
			.any(|skip| name.eq_ignore_ascii_case(skip))
		{
			continue;
		}
		value.push_str(&format!("; {name}={tag_value}"));
	}
	value
}

/// Plan the DMARC record at `_dmarc.<domain>`: the plan's DMARC block and,
/// when this run writes, the entry to publish.
pub fn plan_dmarc(
	domain: &str,
	existing: &[DnsRecord],
	journal: &Journal,
	inputs: &DmarcInputs,
) -> (DmarcPlan, Option<PlanEntry>) {
	let name = format!("_dmarc.{domain}");
	let published: Vec<&DnsRecord> = existing
		.iter()
		.filter(|r| {
			r.kind == RecordKind::Txt
				&& canonical_name(&r.name) == name
				&& txt_purpose(&r.value) == Some("v=DMARC1")
		})
		.collect();
	let mut plan = DmarcPlan {
		name: name.clone(),
		current: None,
		next: inputs.jump_to.unwrap_or(DmarcStep::Quarantine),
		jumped: inputs.jump_to.is_some(),
		action: DmarcAction::Publish,
		has_reports: inputs.has_reports,
		failing_sources: inputs.failing_sources.clone(),
	};
	let cname = existing
		.iter()
		.any(|r| r.kind == RecordKind::Cname && canonical_name(&r.name) == name);
	if cname {
		plan.action = DmarcAction::LeftAlone {
			reason: format!(
				"{name} is a CNAME (the DMARC policy is published where it points), and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); change it there"
			),
		};
		return (plan, None);
	}
	let (tags, replaces) = match published.as_slice() {
		[] => (None, None),
		[record] => match parse_dmarc(&record.value) {
			Ok(tags) => (Some(tags), Some((*record).clone())),
			Err(problem) => {
				plan.action = DmarcAction::LeftAlone {
					reason: format!(
						"{name} is not a DMARC record this command can rewrite ({problem}); fix it by hand"
					),
				};
				return (plan, None);
			}
		},
		many => {
			plan.action = DmarcAction::LeftAlone {
				reason: format!(
					"{name} has {} DMARC records, and receivers ignore all of them (RFC 7489 section 6.6.3); remove all but one by hand",
					many.len()
				),
			};
			return (plan, None);
		}
	};
	if let Some(tags) = &tags {
		let current = tags.policy();
		plan.current = Some(current);
		plan.next = inputs.jump_to.unwrap_or(current.next()).max(current);
		let target = |tag: &str| tags.get(tag).and_then(DmarcStep::parse);
		if current == plan.next
			&& target("sp") == Some(plan.next)
			&& target("np") == Some(DmarcStep::Reject)
			&& tags.get("pct").is_none()
		{
			plan.action = DmarcAction::Unchanged;
			return (plan, None);
		}
	}
	let value = rewrite_dmarc(tags.as_ref(), plan.next);
	let reason = match plan.current {
		None => format!(
			"{name} has no DMARC record; publish p={next} with sp={next} and np=reject",
			next = plan.next.as_str()
		),
		Some(current) => format!(
			"move {name} from p={current} to p={next}; sp follows p; np=reject; the other tags stay as written; pct is dropped (DMARCbis)",
			current = current.as_str(),
			next = plan.next.as_str()
		),
	};
	// A DMARC record this command already rewrote is not the operator's:
	// the journal keeps the one it replaced the first time.
	let replaces = replaces.filter(|record| !journal.owns(record));
	let entry = PlanEntry {
		record: DnsRecord::new(name, RecordKind::Txt, value, TTL),
		reason,
		replaces,
	};
	(plan, Some(entry))
}
