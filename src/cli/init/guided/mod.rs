//! The seven inline setup steps. The answers-file path does not use this module.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use super::answers::{Answers, DnsAnswers, Mode};
use super::first_account::FirstAccount;
use crate::cli::ui::prompt::Prompt;

pub(super) fn run<R: BufRead, W: Write>(
	ui: &mut Prompt<'_, R, W>,
	detector: &dyn super::detect::Detector,
) -> io::Result<Answers> {
	let mut answers: Answers = toml::from_str(&Answers::template())
		.map_err(|_| io::Error::other("invalid built-in answers template"))?;
	ui.step(1, 7, "Setup mode")?;
	let mode = ui.choice("mode", "Manual mode leaves DNS publishing to you. Automatic mode configures a DNS provider, but publishing is not implemented in this build. Enter chooses manual.", &["manual", "automatic"], 0)?;
	answers.mode = if mode == 0 {
		Mode::Manual
	} else {
		Mode::Automatic
	};
	ui.step(2, 7, "Mail identity")?;
	answers.hostname = ui.validated("hostname", "This is the name used in SMTP greetings and certificates. No default, enter a fully qualified hostname.", "", "mail.example.org", |raw| {
		crate::domain::normalize(raw).map_err(|why| crate::util::address_reason::name_refusal(raw, why, "mail.example.org"))
	})?;
	answers.domains = ui.validated(
		"domains",
		"These domains receive mail here. Enter one or more separated by commas. No default.",
		"",
		"example.org, example.net",
		|raw| {
			let mut candidate = answers.clone();
			candidate.domains = raw.split(',').map(|d| d.trim().to_string()).collect();
			super::guided_rules::check(&candidate, "domains")?;
			candidate.normalise();
			Ok(candidate.domains)
		},
	)?;
	ui.step(3, 7, "First mailbox")?;
	first_account(ui, &mut answers)?;
	ui.step(4, 7, "Addresses and files")?;
	let (v4, v6) = super::detect::detect_or_none(detector);
	answers.public_ipv4 =
		ip(ui, "public IPv4", v4.map(|v| v.to_string()), false)?.and_then(|v| v.parse().ok());
	answers.public_ipv6 =
		ip(ui, "public IPv6", v6.map(|v| v.to_string()), true)?.and_then(|v| v.parse().ok());
	answers.data_dir = ui.validated(
		"data_dir",
		"Mail, keys and the container stack live here. Enter accepts the package data directory.",
		"/var/lib/glyndor/epistle/data",
		"/var/lib/glyndor/epistle/data",
		|raw| {
			let mut candidate = answers.clone();
			candidate.data_dir = PathBuf::from(raw);
			super::guided_rules::check(&candidate, "data_dir")?;
			Ok(candidate.data_dir)
		},
	)?;
	answers.config_path = ui.validated("config_path", "This is where the server configuration will be written. Enter accepts the package configuration path.", "/etc/epistle/mail.toml", "/etc/epistle/mail.toml", |raw| {
		let mut candidate = answers.clone();
		candidate.config_path = PathBuf::from(raw);
		super::guided_rules::check(&candidate, "config_path")?;
		Ok(candidate.config_path)
	})?;
	while let Some(first) = &answers.first_account {
		match super::first_account::precheck(first, &answers.data_dir, &answers.config_path) {
			Ok(()) => break,
			Err(why) => {
				writeln!(
					ui.out,
					"✘ {}. Choose a different first mailbox.",
					crate::cli::term::sanitize(&why)
				)?;
				ui.answers.remove("address");
				first_account(ui, &mut answers)?;
			}
		}
	}
	ui.step(5, 7, "DNS provider")?;
	if answers.mode == Mode::Automatic {
		dns(ui, &mut answers)?;
	} else {
		writeln!(
			ui.out,
			"Manual mode: publish DNS records yourself. No provider credentials are needed."
		)?;
	}
	ui.step(6, 7, "Services")?;
	answers.services.imap = ui.boolean(
		"IMAP",
		"Read and synchronize mail. Enter enables IMAP.",
		true,
	)?;
	answers.services.submission = ui.boolean(
		"submission",
		"Send authenticated outgoing mail. Enter enables submission.",
		true,
	)?;
	answers.services.pop3 = ui.boolean(
		"POP3",
		"Download mail with POP3. Enter leaves it disabled.",
		false,
	)?;
	answers.services.managesieve = ui.boolean(
		"ManageSieve",
		"Manage server-side mail filters. Enter leaves it disabled.",
		false,
	)?;
	answers.services.webdav = ui.boolean(
		"WebDAV",
		"Access contacts and calendars. Enter leaves it disabled.",
		false,
	)?;
	answers.services.api = ui.validated("API", "Manage the server over HTTP. Init cannot create its credential yet. Enter leaves it disabled. Options: 1. yes, 2. no.", "no", "no", |raw| {
		let mut candidate = answers.clone();
		candidate.services.api = boolean(raw)?;
		super::guided_rules::check(&candidate, "API")?;
		Ok(candidate.services.api)
	})?;
	answers.services.database = ui.boolean(
		"PostgreSQL",
		"Create the database container for directory, bans and antispam. Enter leaves it disabled.",
		false,
	)?;
	ui.step(7, 7, "Container image")?;
	let default_image = super::images::mail_base();
	answers.image = ui.validated(
		"image",
		"This image runs the mail server. Enter keeps the package's pinned base image and installed host binary.",
		default_image,
		default_image,
		|raw| {
			let mut candidate = answers.clone();
			candidate.image = (raw != default_image).then(|| raw.to_string());
			super::guided_rules::check(&candidate, "image")?;
			Ok(candidate.image)
		},
	)?;
	answers.normalise();
	answers
		.validate()
		.map_err(|_| io::Error::other("the selected answers did not pass final validation"))?;
	Ok(answers)
}

fn boolean(raw: &str) -> Result<bool, String> {
	match raw.to_ascii_lowercase().as_str() {
		"yes" | "y" | "1" => Ok(true),
		"no" | "n" | "2" => Ok(false),
		_ => Err("choose 1 (yes) or 2 (no)".into()),
	}
}

fn first_account<R: BufRead, W: Write>(
	ui: &mut Prompt<'_, R, W>,
	answers: &mut Answers,
) -> io::Result<()> {
	let address = ui.validated("address", "Create the first mailbox. Its account name comes from the address, with dots changed to hyphens. Enter skips the mailbox.", "", "alice@example.org", |raw| {
		if raw.is_empty() { return Ok(None); }
		let first = FirstAccount { address: raw.to_string(), display_name: None, password_file: None, role_aliases: true };
		first.check(&answers.domains).map_err(|why| why.replace('"', ""))?;
		Ok(Some(first))
	})?;
	answers.first_account = address;
	if let Some(first) = answers.first_account.as_mut() {
		writeln!(
			ui.out,
			"Account name: {}. The password will be requested after confirmation and is never saved in the draft.",
			first.name()
		)?;
		first.display_name = ui.validated(
			"display name",
			"This is the sender name shown to recipients. Enter leaves it unset.",
			"",
			"Alice Liddell",
			|raw| {
				crate::directory_store::display_name::validate(raw)?;
				Ok((!raw.is_empty()).then(|| raw.to_string()))
			},
		)?;
		first.role_aliases = ui.boolean("role aliases", "Deliver postmaster@ and abuse@ for every domain to this mailbox, for delivery problems and abuse reports. Enter creates these aliases.", true)?;
	}
	Ok(())
}

fn ip<R: BufRead, W: Write>(
	ui: &mut Prompt<'_, R, W>,
	key: &str,
	detected: Option<String>,
	ipv6: bool,
) -> io::Result<Option<String>> {
	let default = detected.unwrap_or_else(|| "none".into());
	ui.validated(key, "Public addresses help check DNS reachability. Enter accepts the detected address, or none when no public address was detected. Type none to skip.", &default, if ipv6 { "2606:4700:4700::1111" } else { "1.1.1.1" }, |raw| {
		if raw.eq_ignore_ascii_case("none") { return Ok(None); }
		let address: std::net::IpAddr = raw.parse().map_err(|_| "must be a valid IP address".to_string())?;
		let why = match address {
			std::net::IpAddr::V4(v) if !ipv6 => crate::config::non_global_ipv4_reason(v),
			std::net::IpAddr::V6(v) if ipv6 => crate::config::non_global_ipv6_reason(v),
			_ => return Err("must match the requested IP family".into()),
		};
		if let Some(why) = why { return Err(format!("public unicast required: {why}")); }
		Ok(Some(raw.to_string()))
	})
}

fn dns<R: BufRead, W: Write>(ui: &mut Prompt<'_, R, W>, answers: &mut Answers) -> io::Result<()> {
	answers.dns = Some(DnsAnswers {
		token_env: Some("EPISTLE_DNS_TOKEN".into()),
		..Default::default()
	});
	let providers = crate::config::SUPPORTED_PROVIDERS;
	let default_provider = providers
		.iter()
		.position(|name| *name == "cloudflare")
		.unwrap_or(0);
	let provider = ui.choice(
		"DNS provider",
		"The provider holds the DNS zone. Enter chooses cloudflare.",
		providers,
		default_provider,
	)?;
	answers.dns.as_mut().unwrap().provider = providers[provider].to_string();
	let zone = ui.validated(
		"DNS zone",
		"The zone must contain every served domain. Enter uses the first domain.",
		&answers.domains[0],
		&answers.domains[0],
		|raw| {
			let mut candidate = answers.clone();
			candidate.dns.as_mut().unwrap().zone = raw.to_string();
			super::guided_rules::check(&candidate, "DNS zone")?;
			Ok(raw.to_string())
		},
	)?;
	let source = ui.choice(
		"DNS credential source",
		"Reference a credential instead of typing it here. Enter chooses a private file.",
		&["file", "environment"],
		0,
	)?;
	let reference = credential_reference(ui, source == 0)?;
	let dns = answers.dns.as_mut().unwrap();
	dns.zone = zone;
	dns.token_file = (source == 0).then(|| PathBuf::from(&reference));
	dns.token_env = (source == 1).then_some(reference);
	Ok(())
}

/// References are requested again after interruption and never checkpointed.
fn credential_reference<R: BufRead, W: Write>(
	ui: &mut Prompt<'_, R, W>,
	file: bool,
) -> io::Result<String> {
	writeln!(
		ui.out,
		"Enter a credential reference, never the token. No default. This reference is not saved in the draft."
	)?;
	loop {
		let raw = ui.hidden("DNS credential reference")?;
		let valid = if file {
			std::path::Path::new(&raw).is_absolute()
				&& !raw.chars().any(|c| c.is_control() || c == '$')
		} else {
			let mut chars = raw.chars();
			chars
				.next()
				.is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
				&& chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
		};
		if valid {
			return Ok(raw);
		}
		// A pasted credential must never be copied into a diagnostic.
		writeln!(
			ui.out,
			"✘ Invalid credential reference. {}. Try again.",
			if file {
				"Use an absolute file path, for example /run/secrets/epistle-dns"
			} else {
				"Use an environment variable name, for example EPISTLE_DNS_TOKEN"
			}
		)?;
	}
}

#[cfg(test)]
mod tests;
