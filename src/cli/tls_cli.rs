//! `epistle tls`: show the certificate the server presents and ask for a
//! renewal.
//!
//! The server owns the ACME account key and the challenge listener, so
//! `tls renew` only drops a request file that the server's renewal loop serves
//! within a minute (see `acme::renew_request`).

use std::process::ExitCode;

use clap::Subcommand;
use serde::Serialize;

use crate::config::Config;
use crate::tls::served_tls;

/// Actions of `epistle tls`.
#[derive(Debug, Subcommand)]
pub enum TlsCli {
	/// Show the certificate the server presents.
	///
	/// Show the certificate the server presents: subject, names, issuer, expiry
	/// and where it comes from.
	Show {
		/// Print one JSON object instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Ask the server to renew the ACME certificate now.
	Renew {
		/// Renew even when the certificate is not inside its renewal window.
		#[arg(long)]
		force: bool,
	},
}

/// Everything `tls show` prints.
#[derive(Debug, Serialize)]
pub(super) struct TlsView {
	source: &'static str,
	cert_file: std::path::PathBuf,
	subject: String,
	sans: Vec<String>,
	issuer: String,
	not_before: i64,
	not_after: i64,
	not_after_utc: String,
	/// Whole days until `not_after`; negative once expired.
	days_left: i64,
	renewal_requested_at: Option<u64>,
	last_request_error: Option<String>,
}

/// Run one `tls` action.
pub(super) fn run(
	config: &Config,
	action: TlsCli,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let now = super::dkim::now_epoch();
	match action {
		TlsCli::Show { json: leaf } => match view(config, now) {
			Ok(view) => render(&view, leaf || json, out),
			Err(error) => {
				super::style::error(error);
				ExitCode::FAILURE
			}
		},
		TlsCli::Renew { force } => renew(config, force, now, json, out),
	}
}

/// Read the certificate `serve` presents (through the shared resolver).
pub(super) fn view(config: &Config, now: u64) -> Result<TlsView, String> {
	use rustls_pki_types::CertificateDer;
	use rustls_pki_types::pem::PemObject;
	use x509_parser::extensions::GeneralName;
	use x509_parser::prelude::FromDer;

	let served = served_tls(config).ok_or("no certificate configured ([tls] is missing)")?;
	let path = served.tls.cert_file.clone();
	let der = CertificateDer::from_pem_file(&path)
		.map_err(|error| format!("cannot read {}: {error}", path.display()))?;
	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
		.map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
	let sans = cert
		.subject_alternative_name()
		.ok()
		.flatten()
		.map(|ext| {
			ext.value
				.general_names
				.iter()
				.filter_map(|name| match name {
					GeneralName::DNSName(dns) => Some((*dns).to_string()),
					GeneralName::IPAddress(raw) => ip_text(raw),
					_ => None,
				})
				.collect()
		})
		.unwrap_or_default();
	let not_after = cert.validity().not_after.timestamp();
	let expiry = cert.validity().not_after.to_datetime();
	let not_after_utc = format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
		expiry.year(),
		u8::from(expiry.month()),
		expiry.day(),
		expiry.hour(),
		expiry.minute(),
		expiry.second(),
	);
	Ok(TlsView {
		source: served.source.as_str(),
		cert_file: path,
		subject: cert.subject().to_string(),
		sans,
		issuer: cert.issuer().to_string(),
		not_before: cert.validity().not_before.timestamp(),
		not_after,
		not_after_utc,
		days_left: (not_after - i64::try_from(now).unwrap_or(i64::MAX)).div_euclid(86_400),
		renewal_requested_at: crate::acme::renew_request::pending_request(&config.data_dir)
			.map(|r| r.requested_at),
		last_request_error: crate::acme::renew_request::last_error(&config.data_dir),
	})
}

fn ip_text(raw: &[u8]) -> Option<String> {
	match raw.len() {
		4 => <[u8; 4]>::try_from(raw)
			.ok()
			.map(|b| std::net::Ipv4Addr::from(b).to_string()),
		16 => <[u8; 16]>::try_from(raw)
			.ok()
			.map(|b| std::net::Ipv6Addr::from(b).to_string()),
		_ => None,
	}
}

fn render(view: &TlsView, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	let result = if json {
		serde_json::to_writer_pretty(&mut *out, view)
			.map_err(std::io::Error::other)
			.and_then(|()| writeln!(out))
	} else {
		render_text(view, out)
	};
	if result.is_ok() {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

fn render_text(view: &TlsView, out: &mut impl std::io::Write) -> std::io::Result<()> {
	writeln!(
		out,
		"source: {} ({})",
		view.source,
		view.cert_file.display()
	)?;
	writeln!(out, "subject: {}", view.subject)?;
	writeln!(out, "names: {}", view.sans.join(", "))?;
	writeln!(out, "issuer: {}", view.issuer)?;
	writeln!(
		out,
		"expires: {} ({} days left)",
		view.not_after_utc, view.days_left
	)?;
	if let Some(at) = view.renewal_requested_at {
		writeln!(
			out,
			"renewal requested at {}, waiting for the server",
			crate::clock::rfc3339_or_epoch(at)
		)?;
	}
	if let Some(error) = &view.last_request_error {
		writeln!(out, "last request error: {error}")?;
	}
	Ok(())
}

/// Validate the preconditions the server enforces, then queue the request.
pub(super) fn renew(
	config: &Config,
	force: bool,
	now: u64,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let Some(acme) = &config.acme else {
		super::style::error("tls renew refused: [acme] is not configured");
		return ExitCode::FAILURE;
	};
	if config.tls.is_none() {
		super::style::error(
			"tls renew refused: [tls] is missing; the server runs no ACME renewal without a bootstrap certificate",
		);
		return ExitCode::FAILURE;
	}
	let window = u64::from(acme.renew_before_days);
	let mut report = super::json_out::Report::new(out, json);
	let mut result = serde_json::json!({
		"result": "queued", "action": "renew", "force": force, "renew_before_days": window,
	});
	if !force && !crate::acme::renew::needs_renewal(&config.data_dir, window, now) {
		report.line(format_args!(
			"not due: the certificate is outside its {window} day renewal window; use --force to renew anyway"
		));
		result["result"] = "unchanged".into();
		return report.object(result);
	}
	if let Err(error) = crate::acme::renew_request::request_renewal(&config.data_dir, force, now) {
		super::style::error(format_args!("cannot write the renewal request: {error}"));
		return ExitCode::FAILURE;
	}
	report.line(
		"queued: the running server renews within a minute (at its next start if it is stopped); follow it with `epistle tls show`",
	);
	report.object(result)
}

#[cfg(test)]
#[path = "tls_cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tls_cli_tests_expiry.rs"]
mod tests_expiry;
