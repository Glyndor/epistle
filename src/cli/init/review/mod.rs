//! Plain inline review seam, replaceable by a terminal review screen later.

use std::io::{self, Write};

use super::Answers;
use crate::cli::term::sanitize;

/// Render an explicit allowlist of ordinary fields, never serialized credentials.
pub(super) fn render(answers: &Answers, out: &mut (impl Write + ?Sized)) -> io::Result<()> {
	writeln!(out, "\nSetup review:")?;
	writeln!(
		out,
		"  Mode: {}",
		if answers.mode == super::answers::Mode::Manual {
			"manual"
		} else {
			"automatic"
		}
	)?;
	writeln!(
		out,
		"  Hostname: {}\n  Domains: {}",
		sanitize(&answers.hostname),
		sanitize(&answers.domains.join(", "))
	)?;
	writeln!(
		out,
		"  Public IPv4: {}\n  Public IPv6: {}",
		answers
			.public_ipv4
			.map_or_else(|| "none".into(), |v| v.to_string()),
		answers
			.public_ipv6
			.map_or_else(|| "none".into(), |v| v.to_string())
	)?;
	writeln!(
		out,
		"  Data directory: {}\n  Configuration: {}",
		sanitize(&answers.data_dir.display().to_string()),
		sanitize(&answers.config_path.display().to_string())
	)?;
	if let Some(first) = &answers.first_account {
		writeln!(
			out,
			"  Mailbox: {}\n  Account name: {}\n  Display name: {}\n  Postmaster and abuse aliases: {}",
			sanitize(&first.address),
			sanitize(&first.name()),
			sanitize(first.display_name.as_deref().unwrap_or("none")),
			first.role_aliases
		)?;
	} else {
		writeln!(out, "  First mailbox: none")?;
	}
	if let Some(dns) = &answers.dns {
		writeln!(
			out,
			"  DNS provider: {}\n  DNS zone: {}\n  DNS credential: {}",
			sanitize(&dns.provider),
			sanitize(&dns.zone),
			if dns.token_file.is_some() {
				"private file reference"
			} else {
				"environment reference"
			}
		)?;
	}
	let services = &answers.services;
	for (name, enabled) in [
		("IMAP", services.imap),
		("submission", services.submission),
		("POP3", services.pop3),
		("ManageSieve", services.managesieve),
		("WebDAV", services.webdav),
		("API", services.api),
		("PostgreSQL", services.database),
	] {
		writeln!(
			out,
			"  {name}: {}",
			if enabled { "enabled" } else { "disabled" }
		)?;
	}
	writeln!(
		out,
		"  Image: {}\n  Mail binary: {}",
		sanitize(
			answers
				.image
				.as_deref()
				.unwrap_or(super::images::mail_base())
		),
		if answers.image.is_none() {
			"installed host binary"
		} else {
			"selected container image"
		}
	)
}

#[cfg(test)]
mod tests;
