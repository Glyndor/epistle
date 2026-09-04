//! `mail reports`: read what receivers told us via DMARC and TLS-RPT.
//!
//! Walks the JSONL store under `data_dir/reports/{dmarc,tlsrpt}/` for the
//! last `--days` days (default 7) and prints, per policy domain:
//!
//! - the reporters (org names) that sent anything
//! - total rows
//! - failing rows by `source_ip` (top 20), for DMARC
//! - failing sessions by `result_type` and `sending_mta_ip`, for TLS-RPT
//!
//! Plain text, one section per policy domain. The command reads; it never
//! writes to the report store.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;
use crate::dmarc::aggregate::unix_to_day;
use crate::reports::Kind;

fn dir_name(kind: Kind) -> &'static str {
	match kind {
		Kind::Dmarc => "dmarc",
		Kind::TlsRpt => "tlsrpt",
	}
}

fn label(kind: Kind) -> &'static str {
	match kind {
		Kind::Dmarc => "DMARC aggregate reports",
		Kind::TlsRpt => "TLS-RPT reports",
	}
}

/// Number of days back the summary covers. The operator can raise or
/// lower this with `--days`. The retention window in
/// [`crate::reports::RETENTION_DAYS`] is the ceiling.
pub const DEFAULT_DAYS: u32 = 7;

/// Maximum number of `source_ip` rows (DMARC) or `sending_mta_ip` rows
/// (TLS-RPT) printed per domain. The full list is in the JSONL store;
/// the CLI only shows what the operator is likely to act on.
const TOP_N: usize = 20;

/// One CLI summary kind: pick between DMARC and TLS-RPT and walk the
/// matching bucket under `data_dir/reports/`.
pub(super) fn run(config: &Config, days: u32, out: &mut impl std::io::Write) -> ExitCode {
	let today = today_unix_days();
	let mut errors = 0;
	for kind in [Kind::Dmarc, Kind::TlsRpt] {
		if let Err(error) = summarise(&config.data_dir, kind, today, days, out) {
			errors += 1;
			eprintln!("error: {} summary failed: {error}", label(kind));
		}
	}
	if errors > 0 {
		ExitCode::FAILURE
	} else {
		ExitCode::SUCCESS
	}
}

fn summarise(
	data_dir: &Path,
	kind: Kind,
	today: u32,
	days: u32,
	out: &mut impl std::io::Write,
) -> std::io::Result<()> {
	let bucket = data_dir.join("reports").join(dir_name(kind));
	let entries = match std::fs::read_dir(&bucket) {
		Ok(entries) => entries,
		// Missing bucket = no reports yet; the section header still
		// prints so the operator knows nothing was found, not that
		// something is broken.
		Err(_) => {
			write_section_header(out, kind, 0)?;
			let _ = writeln!(out, "  (no reports yet)");
			return Ok(());
		}
	};
	let mut total_lines = 0usize;
	for entry in entries.flatten() {
		if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
			continue;
		}
		let day = match entry.file_name().into_string() {
			Ok(s) if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => s,
			_ => continue,
		};
		let day_num: u32 = day.parse().unwrap_or(0);
		if today.saturating_sub(day_num) > days {
			continue;
		}
		for org_entry in std::fs::read_dir(entry.path())
			.into_iter()
			.flatten()
			.flatten()
		{
			let path = org_entry.path();
			if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
				continue;
			}
			total_lines += std::fs::read_to_string(&path)
				.map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
				.unwrap_or(0);
		}
	}
	write_section_header(out, kind, total_lines)?;
	let mut domain_aggregates = read_aggregates(&bucket, today, days)?;
	domain_aggregates.sort_by(|a, b| a.domain.cmp(&b.domain));
	for agg in &domain_aggregates {
		write_aggregate(out, kind, agg)?;
	}
	if domain_aggregates.is_empty() {
		let _ = writeln!(out, "  (no reports yet)");
	}
	Ok(())
}

fn write_section_header(
	out: &mut impl std::io::Write,
	kind: Kind,
	total_lines: usize,
) -> std::io::Result<()> {
	let name = match kind {
		Kind::Dmarc => "DMARC aggregate reports",
		Kind::TlsRpt => "TLS-RPT reports",
	};
	writeln!(out, "{name} ({total_lines} ingested):")
}

#[derive(Default, Debug)]
struct Aggregate {
	/// Policy-published domain.
	domain: String,
	/// Set of org names that sent at least one report.
	reporters: std::collections::BTreeSet<String>,
	/// Total count of rows summed across reports (DMARC `count` field).
	total_rows: u64,
	/// Map of failing-row counts per `source_ip` (DMARC) or per
	/// `sending_mta_ip` (TLS-RPT).
	failing_by_ip: HashMap<String, u64>,
	/// Map of failing-session counts per `result_type` (TLS-RPT only).
	failing_by_result: HashMap<String, u64>,
}

impl Aggregate {
	fn add_dmarc(&mut self, report: &crate::reports::dmarc::DmarcReport) {
		self.domain = report.policy_published.domain.clone();
		self.reporters.insert(report.org_name.clone());
		for row in &report.records {
			self.total_rows += row.count;
			if is_dmarc_failing(row) {
				*self.failing_by_ip.entry(row.source_ip.clone()).or_insert(0) += row.count;
			}
		}
	}

	fn add_tlsrpt(&mut self, report: &crate::reports::tlsrpt::TlsReport) {
		self.domain = report
			.policies
			.first()
			.map(|p| p.policy_domain.clone())
			.unwrap_or_default();
		self.reporters.insert(report.organization_name.clone());
		for policy in &report.policies {
			if self.domain.is_empty() {
				self.domain = policy.policy_domain.clone();
			}
			for failure in &policy.failure_details {
				self.total_rows += failure.failed_session_count;
				*self
					.failing_by_ip
					.entry(failure.sending_mta_ip.clone())
					.or_insert(0) += failure.failed_session_count;
				*self
					.failing_by_result
					.entry(failure.result_type.clone())
					.or_insert(0) += failure.failed_session_count;
			}
		}
	}
}

fn is_dmarc_failing(row: &crate::reports::dmarc::Row) -> bool {
	matches!(row.disposition.as_str(), "quarantine" | "reject")
		|| (row.dkim == "fail" && row.spf == "fail")
}

/// Walk the bucket and aggregate every JSONL line under the matching day
/// directories. Lines that fail to deserialize are counted but skipped.
fn read_aggregates(bucket: &Path, today: u32, days: u32) -> std::io::Result<Vec<Aggregate>> {
	let mut out: Vec<Aggregate> = Vec::new();
	let Ok(entries) = std::fs::read_dir(bucket) else {
		return Ok(out);
	};
	for day_entry in entries.flatten() {
		if !day_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
			continue;
		}
		let day = match day_entry.file_name().into_string() {
			Ok(s) if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => s,
			_ => continue,
		};
		let day_num: u32 = day.parse().unwrap_or(0);
		if today.saturating_sub(day_num) > days {
			continue;
		}
		for org_entry in std::fs::read_dir(day_entry.path())
			.into_iter()
			.flatten()
			.flatten()
		{
			let path = org_entry.path();
			if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
				continue;
			}
			let text = match std::fs::read_to_string(&path) {
				Ok(s) => s,
				Err(_) => continue,
			};
			for line in text.lines() {
				if line.trim().is_empty() {
					continue;
				}
				// Try DMARC, then TLS-RPT. The path tells us which one
				// the bucket stores (each bucket is one kind), so we
				// dispatch based on the bucket name.
				if bucket.ends_with("dmarc")
					&& let Ok(report) =
						serde_json::from_str::<crate::reports::dmarc::DmarcReport>(line)
				{
					let domain = report.policy_published.domain.clone();
					let slot = aggregate_for(&mut out, &domain);
					slot.add_dmarc(&report);
				} else if bucket.ends_with("tlsrpt")
					&& let Ok(report) =
						serde_json::from_str::<crate::reports::tlsrpt::TlsReport>(line)
				{
					let domain = report
						.policies
						.first()
						.map(|p| p.policy_domain.clone())
						.unwrap_or_default();
					let slot = aggregate_for(&mut out, &domain);
					slot.add_tlsrpt(&report);
				}
			}
		}
	}
	Ok(out)
}

fn aggregate_for<'a>(list: &'a mut Vec<Aggregate>, domain: &str) -> &'a mut Aggregate {
	let pos = list.iter().position(|a| a.domain == domain);
	if let Some(pos) = pos {
		return &mut list[pos];
	}
	list.push(Aggregate {
		domain: domain.to_string(),
		..Default::default()
	});
	let len = list.len();
	&mut list[len - 1]
}

fn write_aggregate(
	out: &mut impl std::io::Write,
	kind: Kind,
	agg: &Aggregate,
) -> std::io::Result<()> {
	let reporters = if agg.reporters.is_empty() {
		"(none)".to_string()
	} else {
		agg.reporters.iter().cloned().collect::<Vec<_>>().join(", ")
	};
	writeln!(out, "  domain {}", agg.domain)?;
	writeln!(out, "    reporters: {reporters}")?;
	writeln!(out, "    total rows: {}", agg.total_rows)?;
	if matches!(kind, Kind::Dmarc) && !agg.failing_by_ip.is_empty() {
		writeln!(out, "    failing rows by source_ip:")?;
		for (ip, count) in top_n(&agg.failing_by_ip) {
			writeln!(out, "      {count:>8}  {ip}")?;
		}
	}
	if matches!(kind, Kind::TlsRpt) {
		if !agg.failing_by_result.is_empty() {
			writeln!(out, "    failing sessions by result_type:")?;
			for (rt, count) in top_n(&agg.failing_by_result) {
				writeln!(out, "      {count:>8}  {rt}")?;
			}
		}
		if !agg.failing_by_ip.is_empty() {
			writeln!(out, "    failing sessions by sending_mta_ip:")?;
			for (ip, count) in top_n(&agg.failing_by_ip) {
				writeln!(out, "      {count:>8}  {ip}")?;
			}
		}
	}
	Ok(())
}

/// Top-N entries of a count map, sorted by descending count and then by
/// key for deterministic output. Returns the first [`TOP_N`] entries.
fn top_n(counts: &HashMap<String, u64>) -> Vec<(String, u64)> {
	let mut v: Vec<(&String, &u64)> = counts.iter().collect();
	v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
	v.into_iter()
		.take(TOP_N)
		.map(|(k, v)| (k.clone(), *v))
		.collect()
}

fn today_unix_days() -> u32 {
	let ts = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// unix_to_day returns YYYYMMDD; convert that to a comparable integer
	// by stripping the separators (there are none) and treating as a base-10
	// number. That keeps the comparison simple: 20240110 > 20240101.
	let s = unix_to_day(ts);
	s.parse().unwrap_or(0)
}

#[cfg(test)]
#[path = "reports_tests.rs"]
mod tests;
