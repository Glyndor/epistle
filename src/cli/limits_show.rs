//! Render the catalog as `epistle limits show` text and as `--json`.
//!
//! The shape is the one the operator expects: one tab-separated row per
//! limit with the kind and the RFC reference at the end, plus the
//! per-domain and per-tenant overrides that `epistle limits show --json`
//! has always carried. The five-column text format matches what the
//! `tests_catalog` and `tests_budget` tests in `cli/limits.rs` already
//! pin.

use std::io::Write;

use crate::config::Config;

use super::Key;
use super::catalog::{self, Adjustable, Bound, FixedEntry};
use super::values;

/// Render the catalog as one tab-separated row per limit, with the
/// five-column layout: `key, value, source, kind, reference`. The fixed
/// standards the operator cannot change follow the adjustable rows so a
/// single call answers "what is in force for every limit?".
pub fn show(config: &Config, out: &mut impl Write) -> std::io::Result<()> {
	for entry in catalog::ADJUSTABLE {
		write_adjustable_row(entry, config, out)?;
	}
	for fixed in catalog::FIXED {
		write_fixed_row(fixed, out)?;
	}
	Ok(())
}

/// `limits show --json`: `{"<limit>": {"value", "unit", "source", "kind", "bounds", "reference"}, ...}`,
/// where `value` is the effective number (`null` when the limit is off or
/// left to the protocol, an array for `queue-backoff`) and `unit` is
/// `bytes`, `bytes-per-second`, `seconds`, `count` or the catalog's own
/// `octets`/`version`/`boolean` for fixed rules. `kind` is one of
/// `adjustable`, `recommended`, `fixed`; `bounds` is the standard floor
/// or ceiling the RFC puts on the limit, when there is one; `reference`
/// names the RFC and section the rule comes from.
pub fn show_json(config: &Config) -> serde_json::Value {
	let mut limits = serde_json::Map::new();
	for entry in catalog::ADJUSTABLE {
		write_adjustable_json(entry, config, &mut limits);
	}
	for fixed in catalog::FIXED {
		write_fixed_json(fixed, &mut limits);
	}
	let domain_overrides = collect_domain_overrides(config);
	limits.insert(
		"domain-overrides".to_string(),
		serde_json::Value::Object(domain_overrides),
	);
	let tenants = collect_tenants(config);
	limits.insert("tenants".to_string(), serde_json::Value::Object(tenants));
	serde_json::Value::Object(limits)
}

/// Human-readable kind for the catalog columns.
fn kind_name(kind: catalog::Kind) -> &'static str {
	match kind {
		catalog::Kind::Adjustable => "adjustable",
		catalog::Kind::Recommended => "recommended",
		catalog::Kind::Fixed => "fixed",
	}
}

/// JSON encoding of the standard bound on an adjustable key. `null` when
/// the RFC imposes none.
fn bound_json(bound: Option<Bound>) -> serde_json::Value {
	match bound {
		None => serde_json::Value::Null,
		Some(Bound::AtLeast(value)) => serde_json::json!({"at-least": value}),
		Some(Bound::AtMost(value)) => serde_json::json!({"at-most": value}),
	}
}

/// Format the textual value of an adjustable key the same way `show`
/// has always done, including the `disabled` and `protocol defaults`
/// sentinels for limits that take a `0` or are left to the protocol.
fn render_adjustable_value(entry: &Adjustable, configured: Option<u64>) -> String {
	let default = entry.key.default_value();
	match configured.or(default) {
		Some(0) if matches!(entry.key, Key::Quota) => "unlimited".into(),
		Some(0) if entry.key.zero_turns_off() => "disabled".into(),
		Some(value) => match entry.key.unit() {
			values::Unit::Size => format!("{value} bytes"),
			values::Unit::Rate => format!("{value} bytes per second"),
			values::Unit::Duration => format!("{value} seconds"),
			values::Unit::Count => value.to_string(),
		},
		None if matches!(entry.key, Key::MaxConnectionsPerListener) => "protocol defaults".into(),
		None => "disabled".into(),
	}
}

/// Where the row lives. `default` when the configured value matches the
/// built-in default (or none is configured); `configured` when the
/// operator has overridden it.
fn source_for(configured: Option<u64>, default: Option<u64>) -> &'static str {
	if configured.is_none() || configured == default {
		"default"
	} else {
		"configured"
	}
}

/// Emit one text row for an adjustable entry, including the comma-joined
/// `queue-backoff` list and the `derived` message-memory-budget line.
fn write_adjustable_row(
	entry: &Adjustable,
	config: &Config,
	out: &mut impl Write,
) -> std::io::Result<()> {
	if let Some((values, default)) = entry.key.list(config) {
		let joined: Vec<String> = values.iter().map(u64::to_string).collect();
		let source = if default { "default" } else { "configured" };
		writeln!(
			out,
			"{}\t{} seconds\t{source}\t{}\t{}",
			entry.key.name(),
			joined.join(","),
			kind_name(entry.kind),
			entry.reference,
		)?;
		return Ok(());
	}
	if matches!(entry.key, Key::MessageMemoryBudget)
		&& let Some((_, text)) = super::derived_budget(config)
	{
		writeln!(
			out,
			"{}\t{text}\tderived\t{}\t{}",
			entry.key.name(),
			kind_name(entry.kind),
			entry.reference,
		)?;
		return Ok(());
	}
	let configured = entry.key.value(config);
	let source = source_for(configured, entry.key.default_value());
	let value = render_adjustable_value(entry, configured);
	writeln!(
		out,
		"{}\t{value}\t{source}\t{}\t{}",
		entry.key.name(),
		kind_name(entry.kind),
		entry.reference,
	)?;
	Ok(())
}

fn write_fixed_row(fixed: &FixedEntry, out: &mut impl Write) -> std::io::Result<()> {
	writeln!(
		out,
		"{}\t{} {}\tfixed\tfixed\t{}",
		fixed.name, fixed.value, fixed.unit, fixed.reference,
	)?;
	Ok(())
}

/// Emit one JSON entry for an adjustable row. The unit column is the
/// short string the JSON contract has always used (`bytes`,
/// `bytes-per-second`, `seconds`, `count`); the catalog metadata
/// (`kind`, `bounds`, `reference`) is appended after the existing
/// shape so the `--json` consumers reading only the first three
/// fields keep working.
fn write_adjustable_json(
	entry: &Adjustable,
	config: &Config,
	limits: &mut serde_json::Map<String, serde_json::Value>,
) {
	let kind = kind_name(entry.kind);
	let bounds = bound_json(entry.bound);
	if let Some((values, default)) = entry.key.list(config) {
		limits.insert(
			entry.key.name().to_string(),
			serde_json::json!({
				"value": values,
				"unit": "seconds",
				"source": if default { "default" } else { "configured" },
				"kind": kind,
				"bounds": bounds,
				"reference": entry.reference,
			}),
		);
		return;
	}
	if matches!(entry.key, Key::MessageMemoryBudget)
		&& let Some((bytes, _)) = super::derived_budget(config)
	{
		limits.insert(
			entry.key.name().to_string(),
			serde_json::json!({
				"value": bytes,
				"unit": "bytes",
				"source": "derived",
				"kind": kind,
				"bounds": bounds,
				"reference": entry.reference,
			}),
		);
		return;
	}
	let configured = entry.key.value(config);
	let default = configured.is_none() || configured == entry.key.default_value();
	let unit = match entry.key.unit() {
		values::Unit::Size => "bytes",
		values::Unit::Rate => "bytes-per-second",
		values::Unit::Duration => "seconds",
		values::Unit::Count => "count",
	};
	limits.insert(
		entry.key.name().to_string(),
		serde_json::json!({
			"value": configured
				.or(entry.key.default_value())
				.filter(|value| !((matches!(entry.key, Key::Quota) || entry.key.zero_turns_off()) && *value == 0)),
			"unit": unit,
			"source": if default { "default" } else { "configured" },
			"kind": kind,
			"bounds": bounds,
			"reference": entry.reference,
		}),
	);
}

fn write_fixed_json(fixed: &FixedEntry, limits: &mut serde_json::Map<String, serde_json::Value>) {
	limits.insert(
		fixed.name.to_string(),
		serde_json::json!({
			"value": fixed.value,
			"unit": fixed.unit,
			"source": "fixed",
			"kind": "fixed",
			"bounds": null,
			"reference": fixed.reference,
		}),
	);
}

/// Per-domain overrides for quota and submission-rate. Kept in the
/// JSON output so an operator's one call answers the "what is in force
/// for every sender" question without joining text.
fn collect_domain_overrides(config: &Config) -> serde_json::Map<String, serde_json::Value> {
	let mut domain_overrides = serde_json::Map::new();
	for domain in config
		.domains
		.iter()
		.chain(config.domain_quotas.keys())
		.chain(config.domain_submission_limits.keys())
	{
		let entry = serde_json::json!({
			"quota": config.domain_quotas.get(domain).copied(),
			"submission-rate": config.domain_submission_limits.get(domain).copied(),
		});
		domain_overrides.insert(domain.clone(), entry);
	}
	domain_overrides
}

/// Per-tenant aggregate submission-rate. Other per-tenant limits (quota,
/// max_accounts, max_domains) are accounted for under `[[tenant]]` in the
/// config itself; the CLI surfaces only the operator-editable dial here.
fn collect_tenants(config: &Config) -> serde_json::Map<String, serde_json::Value> {
	let mut tenants = serde_json::Map::new();
	for tenant in &config.tenants {
		if let Some(name) = &tenant.name {
			tenants.insert(
				name.clone(),
				serde_json::json!({
					"submission-rate": tenant.submission_rate_limit_per_min,
				}),
			);
		}
	}
	tenants
}
