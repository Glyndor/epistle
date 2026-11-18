//! `epistle domain list` and `epistle domain show`: what is configured for
//! the hosted domains, as a table or as JSON. What each domain is comes from
//! [`crate::domain::catalog`], which the `/api/v1/domains` routes read too.

use std::io::Write;

use crate::cli::term::table::Table;
use crate::config::Config;
use crate::domain::catalog::{Catalog, DomainRow};

/// List every configured domain plus its alias map. JSON-friendly.
pub(in crate::cli) fn list(
	config: &Config,
	json: bool,
	out: &mut impl Write,
) -> std::io::Result<()> {
	let rows = Catalog::from_config(config).rows();
	if json {
		serde_json::to_writer(&mut *out, &rows).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	// A switched-off domain is named as such in the text forms.
	let shown = |row: &DomainRow| {
		if row.enabled {
			row.domain.clone()
		} else {
			format!("{} (disabled)", row.domain)
		}
	};
	if let Some(decor) = crate::cli::term::stdout(json) {
		let mut table = Table::new(&["DOMAIN", "ROLE", "ALIASES TO", "ALIASES FROM"]);
		for row in &rows {
			let joined = |list: &[String]| {
				if list.is_empty() {
					"-".into()
				} else {
					list.join(",")
				}
			};
			table.push(vec![
				shown(row),
				row.role.to_string(),
				joined(&row.aliases_to),
				joined(&row.aliases_from),
			]);
		}
		return table.write(decor, out);
	}
	writeln!(
		out,
		"{:<30} {:<10} ALIASES TO   ALIASES FROM",
		"DOMAIN", "ROLE"
	)?;
	for row in &rows {
		writeln!(
			out,
			"{:<30} {:<10} {:<12} {}",
			shown(row),
			row.role,
			if row.aliases_to.is_empty() {
				"-".into()
			} else {
				row.aliases_to.join(",")
			},
			if row.aliases_from.is_empty() {
				"-".into()
			} else {
				row.aliases_from.join(",")
			},
		)?;
	}
	Ok(())
}

/// Show one domain: alias edges plus the local accounts and aliases that
/// rely on it.
pub(super) fn show(
	config: &Config,
	domain: &str,
	json: bool,
	out: &mut impl Write,
) -> std::io::Result<()> {
	let Some(view) = Catalog::from_config(config).view(domain) else {
		return Err(std::io::Error::other(format!(
			"domain {domain} is not configured"
		)));
	};
	if json {
		serde_json::to_writer(&mut *out, &view).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	writeln!(out, "domain\t{}", view.domain)?;
	writeln!(out, "enabled\t{}", if view.enabled { "yes" } else { "no" })?;
	writeln!(out, "role\t{}", view.role)?;
	let number = |value: Option<String>| value.unwrap_or_else(|| "-".into());
	writeln!(out, "quota\t{}", number(view.quota.map(|v| v.to_string())))?;
	writeln!(
		out,
		"submission_rate\t{}",
		number(view.submission_rate.map(|v| v.to_string()))
	)?;
	writeln!(
		out,
		"aliases_to\t{}",
		if view.aliases_to.is_empty() {
			"-".into()
		} else {
			view.aliases_to.join(",")
		}
	)?;
	writeln!(
		out,
		"aliases_from\t{}",
		if view.aliases_from.is_empty() {
			"-".into()
		} else {
			view.aliases_from.join(",")
		}
	)?;
	writeln!(
		out,
		"accounts\t{}",
		if view.accounts.is_empty() {
			"-".into()
		} else {
			view.accounts.join(",")
		}
	)?;
	writeln!(
		out,
		"aliases\t{}",
		if view.aliases.is_empty() {
			"-".into()
		} else {
			view.aliases.join(",")
		}
	)?;
	Ok(())
}
