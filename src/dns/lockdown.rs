//! Plan helpers behind `epistle dns lockdown`: make sure nobody can send
//! mail as the domain or any name under it from somewhere else. The plan
//! builder, the journal of what the command published, and the shape
//! `--json` prints live here; publishing and undoing are in
//! [`publish_plan`] and [`undo_journal`], the DMARC policy ramp in
//! [`plan_dmarc`], and the CLI handler in `crate::cli::dns_provider`.
//!
//! The plan only ever adds records at names that have nothing of the same
//! kind, plus the one DMARC rewrite the operator asked for. A name epistle
//! serves, a service name (`_dmarc`, `_domainkey`, `_mta-sts`,
//! `_smtp._tls`, a DKIM selector), a CNAME, and a name with an SPF or MX
//! of its own are reported as left as is, with the reason.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dns::provider::{DnsRecord, RecordKind, txt_purpose};

#[path = "lockdown_apply.rs"]
mod apply;
#[path = "lockdown_cuts.rs"]
mod cuts;
#[path = "lockdown_dmarc.rs"]
mod dmarc;
#[path = "lockdown_names.rs"]
mod names;
#[path = "lockdown_reports.rs"]
mod reports;

pub use apply::{PublishFailure, UndoChanged, UndoFailure, UndoReport, publish_plan, undo_journal};
pub use cuts::{MAX_LABEL_LEN, MAX_NAME_LEN, is_valid_name};
pub use dmarc::{
	DmarcAction, DmarcInputs, DmarcPlan, DmarcStep, FailingSource, parse_dmarc, plan_dmarc,
	rewrite_dmarc,
};
pub use names::{ServedNames, canonical_name, in_domain, is_null_mx, same_record};
pub use reports::{REPORT_WINDOW_DAYS, recent_dmarc_failures};

/// The TTL of every record the lockdown writes.
pub const TTL: u32 = 3600;

/// The null SPF (RFC 7208 section 5.1 with no mechanism but `-all`): the
/// name sends no mail.
pub const NULL_SPF: &str = "v=spf1 -all";

/// The null MX (RFC 7505): the name accepts no mail.
pub const NULL_MX: &str = "0 .";

/// A record the plan adds or rewrites, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanEntry {
	/// The record the plan writes.
	pub record: DnsRecord,
	/// Why this record is part of the plan.
	pub reason: String,
	/// The record this one replaces, for the DMARC rewrite. `--undo` puts
	/// it back. `None` for a record added where there was none.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub replaces: Option<DnsRecord>,
}

/// A name the plan leaves alone, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipEntry {
	/// The DNS name.
	pub name: String,
	/// Why the plan does not touch it.
	pub reason: String,
}

/// The lockdown plan for one domain. `--json` prints this structure and
/// the text output renders the same fields, so the two never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
	/// The domain the plan is for.
	pub domain: String,
	/// What happens to the DMARC policy on this run.
	pub dmarc: DmarcPlan,
	/// The records the plan writes, the DMARC rewrite first.
	pub entries: Vec<PlanEntry>,
	/// The names the plan leaves alone, with the reason.
	pub skipped: Vec<SkipEntry>,
	/// Whether the wildcard null SPF is added, and why.
	pub wildcard: WildcardDecision,
}

/// What the plan decided about `*.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WildcardDecision {
	/// The zone has no wildcard: the plan adds `*.<domain>` `v=spf1 -all`.
	Added {
		/// The reason printed in the plan.
		reason: String,
	},
	/// The zone has a wildcard of its own: nothing is added.
	Skipped {
		/// The reason printed in the plan.
		reason: String,
	},
	/// The wildcard null SPF a previous run published is still there.
	AlreadyPresent {
		/// The reason printed in the plan.
		reason: String,
	},
}

impl WildcardDecision {
	/// The reason, whatever the decision.
	pub fn reason(&self) -> &str {
		match self {
			WildcardDecision::Added { reason }
			| WildcardDecision::Skipped { reason }
			| WildcardDecision::AlreadyPresent { reason } => reason,
		}
	}
}

/// The journal under `<data_dir>/dns-lockdown/<domain>.json`: every record
/// the lockdown published, so `--undo` removes exactly those and nothing
/// else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
	/// The domain the journal is for.
	pub domain: String,
	/// Every record the lockdown published, in the order it published them.
	pub entries: Vec<JournalEntry>,
}

/// One record the lockdown published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
	/// The record as published.
	pub record: DnsRecord,
	/// The record it replaced (the operator's DMARC before the first
	/// rewrite), which `--undo` restores. `None` when the lockdown added
	/// the record where there was none.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub replaced: Option<DnsRecord>,
}

impl Journal {
	/// An empty journal for `domain`.
	pub fn new(domain: impl Into<String>) -> Self {
		Journal {
			domain: domain.into(),
			entries: Vec::new(),
		}
	}

	/// Whether the journal holds `record`: same name, kind and value.
	pub fn owns(&self, record: &DnsRecord) -> bool {
		self.entries
			.iter()
			.any(|entry| same_record(&entry.record, record))
	}
}

/// Everything [`build_plan`] reads.
pub struct PlanInput<'a> {
	/// The zone the provider manages, in [`canonical_name`] form: the
	/// domain itself, or a name above it. Its NS records name its own
	/// servers; an NS below it is a delegation.
	pub zone: &'a str,
	/// The domain to lock down, in [`canonical_name`] form.
	pub domain: &'a str,
	/// The names epistle serves; never touched.
	pub served: &'a ServedNames,
	/// Every record the provider listed for the zone.
	pub existing: &'a [DnsRecord],
	/// What earlier runs published.
	pub journal: Option<&'a Journal>,
	/// The DMARC override and the aggregate reports.
	pub dmarc: &'a DmarcInputs,
	/// Whether `existing` is the zone as a provider listed it. Without a
	/// provider only the live DMARC record is known, and the wildcard
	/// reason says so.
	pub zone_listed: bool,
}

/// Build the lockdown plan. Pure: it reads `input` and writes nothing.
pub fn build_plan(input: &PlanInput<'_>) -> Plan {
	let empty = Journal::new(input.domain);
	let journal = input.journal.unwrap_or(&empty);
	let cuts = cuts::Cuts::new(input.zone, input.existing);
	let (mut dmarc, mut dmarc_entry) =
		plan_dmarc(input.domain, input.existing, journal, input.dmarc);
	// A domain inside a delegation is served by other nameservers: nothing
	// the lockdown writes into this zone for it would ever be answered.
	let domain_cut = cuts.above(input.domain);
	if let Some(cut) = domain_cut.or_else(|| cuts.above(&dmarc.name)) {
		dmarc.action = DmarcAction::LeftAlone {
			reason: delegated_reason(cut),
		};
		dmarc_entry = None;
	}
	// Each delegation is reported once, and everything under it is left
	// out of the plan without a line of its own.
	let mut skipped: Vec<SkipEntry> = cuts
		.relevant_to(input.domain)
		.into_iter()
		.map(|cut| SkipEntry {
			name: cut.to_string(),
			reason: delegated_reason(cut),
		})
		.collect();
	let mut entries: Vec<PlanEntry> = dmarc_entry.into_iter().collect();
	let exchanges = mx_owners(input.existing);
	for (name, records) in address_names(input.domain, input.existing) {
		if !is_valid_name(&name) {
			skipped.push(SkipEntry {
				name: cuts::shortened(&name),
				reason: format!(
					"{} is not a valid DNS name (ASCII letters, digits, hyphens and underscores, at most {MAX_NAME_LEN} characters and {MAX_LABEL_LEN} per label); left as is",
					cuts::shortened(&name)
				),
			});
			continue;
		}
		if cuts.above(&name).is_some() {
			continue;
		}
		match classify(&name, &records, input.served, &exchanges, journal) {
			Verdict::Skip(reason) => skipped.push(SkipEntry { name, reason }),
			Verdict::Add { spf, mx } => {
				if spf {
					entries.push(PlanEntry {
						record: DnsRecord::new(name.clone(), RecordKind::Txt, NULL_SPF, TTL),
						reason: format!(
							"{name} has an address record and no SPF; v=spf1 -all says it sends no mail"
						),
						replaces: None,
					});
				}
				if mx {
					entries.push(PlanEntry {
						record: DnsRecord::new(name.clone(), RecordKind::Mx, NULL_MX, TTL),
						reason: format!(
							"{name} has an address record and no MX; MX 0 . (RFC 7505) says it accepts no mail"
						),
						replaces: None,
					});
				}
			}
		}
	}
	let wildcard = match domain_cut {
		Some(cut) => WildcardDecision::Skipped {
			reason: delegated_reason(cut),
		},
		None => wildcard_decision(
			input.domain,
			input.existing,
			journal,
			input.zone_listed,
			&cuts,
		),
	};
	if let WildcardDecision::Added { reason } = &wildcard {
		entries.push(PlanEntry {
			record: DnsRecord::new(
				format!("*.{}", input.domain),
				RecordKind::Txt,
				NULL_SPF,
				TTL,
			),
			reason: reason.clone(),
			replaces: None,
		});
	}
	Plan {
		domain: input.domain.to_string(),
		dmarc,
		entries,
		skipped,
		wildcard,
	}
}

/// The names at or under `domain` that carry an A, AAAA or CNAME, with
/// every record each one holds, sorted, without wildcards (the wildcard has
/// its own decision). One pass over the zone: the cost does not depend on
/// how many names there are.
fn address_names<'a>(
	domain: &str,
	existing: &'a [DnsRecord],
) -> BTreeMap<String, Vec<&'a DnsRecord>> {
	let mut names: BTreeMap<String, Vec<&DnsRecord>> = BTreeMap::new();
	for record in existing {
		let name = canonical_name(&record.name);
		if in_domain(&name, domain) && !name.starts_with("*.") {
			names.entry(name).or_default().push(record);
		}
	}
	names.retain(|_, records| {
		records
			.iter()
			.any(|r| matches!(r.kind, RecordKind::A | RecordKind::Aaaa | RecordKind::Cname))
	});
	names
}

/// Why a name inside a delegation is left alone.
fn delegated_reason(cut: &str) -> String {
	format!("{cut} is delegated to other nameservers; left as is")
}

/// Every MX target in the zone, with the first name that points at it.
fn mx_owners(existing: &[DnsRecord]) -> BTreeMap<String, String> {
	let mut owners = BTreeMap::new();
	for record in existing.iter().filter(|r| r.kind == RecordKind::Mx) {
		if let Some(target) = names::mx_target(&record.value).filter(|t| !t.is_empty()) {
			owners
				.entry(target)
				.or_insert_with(|| canonical_name(&record.name));
		}
	}
	owners
}

enum Verdict {
	Skip(String),
	Add { spf: bool, mx: bool },
}

/// Decide what one name with an address record gets. The order matters:
/// a name epistle serves is reported as such even when it is a CNAME.
fn classify(
	name: &str,
	records: &[&DnsRecord],
	served: &ServedNames,
	exchanges: &BTreeMap<String, String>,
	journal: &Journal,
) -> Verdict {
	if let Some(role) = served.role(name) {
		return Verdict::Skip(format!("epistle serves {name} ({role}); left as is"));
	}
	if name.split('.').any(|label| label.starts_with('_')) {
		return Verdict::Skip(format!(
			"{name} is a service name (a label starts with an underscore), not a host that sends mail; left as is"
		));
	}
	if records.iter().any(|r| r.kind == RecordKind::Cname) {
		return Verdict::Skip(format!(
			"{name} is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is"
		));
	}
	let own_spf = records.iter().any(|r| is_spf(r) && !journal.owns(r));
	let own_mx = records
		.iter()
		.any(|r| r.kind == RecordKind::Mx && !journal.owns(r));
	match (own_spf, own_mx) {
		(true, true) => {
			return Verdict::Skip(format!("{name} has its own SPF and MX records; left as is"));
		}
		(true, false) => {
			return Verdict::Skip(format!("{name} has its own SPF record; left as is"));
		}
		(false, true) => {
			return Verdict::Skip(format!("{name} has its own MX record; left as is"));
		}
		(false, false) => {}
	}
	if let Some(owner) = exchanges.get(name) {
		return Verdict::Skip(format!(
			"{name} is an MX target of {owner}, so it is a mail server and may send as itself; left as is"
		));
	}
	let spf = !records.iter().any(|r| is_spf(r));
	let mx = !records.iter().any(|r| r.kind == RecordKind::Mx);
	if !spf && !mx {
		return Verdict::Skip(format!(
			"{name} already has the null SPF and null MX this command published"
		));
	}
	Verdict::Add { spf, mx }
}

fn is_spf(record: &DnsRecord) -> bool {
	record.kind == RecordKind::Txt && txt_purpose(&record.value) == Some("v=spf1")
}

/// Add `*.<domain>` `v=spf1 -all` only when the zone has no wildcard of
/// its own at or under `domain`.
fn wildcard_decision(
	domain: &str,
	existing: &[DnsRecord],
	journal: &Journal,
	zone_listed: bool,
	cuts: &cuts::Cuts,
) -> WildcardDecision {
	let wildcard = format!("*.{domain}");
	if !zone_listed {
		return WildcardDecision::Added {
			reason: format!(
				"{wildcard} v=spf1 -all covers names that do not exist; without a provider the zone cannot be read, so add it only if the zone has no wildcard of its own"
			),
		};
	}
	let mut theirs: Vec<String> = Vec::new();
	let mut ours = false;
	for record in existing {
		let name = canonical_name(&record.name);
		if !(name.starts_with("*.") && in_domain(&name, domain)) {
			continue;
		}
		// A wildcard under a delegation is the other nameservers' own: it
		// never answers for a name of this zone.
		if cuts.above(&name).is_some() {
			continue;
		}
		if name == wildcard && record.kind == RecordKind::Txt && journal.owns(record) {
			ours = true;
		} else {
			theirs.push(format!("{name} {}", record.kind.as_str()));
		}
	}
	if !theirs.is_empty() {
		theirs.sort();
		theirs.dedup();
		return WildcardDecision::Skipped {
			reason: format!(
				"the zone already has a wildcard ({}); {wildcard} v=spf1 -all is not added, so names that do not exist answer with whatever that wildcard says",
				theirs.join(", ")
			),
		};
	}
	if ours {
		return WildcardDecision::AlreadyPresent {
			reason: format!("{wildcard} already has the null SPF this command published"),
		};
	}
	WildcardDecision::Added {
		reason: format!(
			"the zone has no wildcard; {wildcard} v=spf1 -all covers names that do not exist (a wildcard never applies to a name that has records of its own)"
		),
	}
}

#[cfg(test)]
#[path = "lockdown_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "lockdown_tests_cuts.rs"]
mod tests_cuts;
#[cfg(test)]
#[path = "lockdown_tests_dmarc.rs"]
mod tests_dmarc;
#[cfg(test)]
#[path = "lockdown_tests_publish.rs"]
mod tests_publish;
#[cfg(test)]
#[path = "lockdown_tests_reports.rs"]
mod tests_reports;
#[cfg(test)]
#[path = "lockdown_tests_support.rs"]
pub(crate) mod tests_support;
