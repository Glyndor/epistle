//! `relay test`: a bounded, read-only handshake with the configured smarthost.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use super::{Target, find};
use crate::config::Config;
use crate::queue::client::{DeliveryError, probe};

/// The whole handshake, connection included, must finish within this time.
const LIMIT: Duration = Duration::from_secs(10);

fn reason(error: DeliveryError) -> String {
	match error {
		DeliveryError::Transient(reason) | DeliveryError::Permanent(reason) => reason,
	}
}

pub(super) fn run(
	config: &Config,
	target: &Target,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	run_within(config, target, LIMIT, out, status)
}

pub(super) fn run_within(
	config: &Config,
	target: &Target,
	limit: Duration,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	let rule = find(config, target)?;
	let host = rule.host.clone().unwrap_or_default();
	let port = rule.port.unwrap_or(0);
	let auth = match (&rule.username, &rule.password) {
		(Some(user), Some(pass)) => Some((user.as_str(), pass.as_str())),
		_ => None,
	};
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| format!("cannot start the async runtime: {error}"))?;
	let mut steps = Vec::new();
	let result = runtime.block_on(async {
		tokio::time::timeout(limit, async {
			let stream =
				crate::queue::relay_connect(&host, port, rule.socks_proxy.as_deref()).await?;
			probe(
				stream,
				&host,
				&config.hostname,
				rule.starttls,
				auth,
				&mut steps,
			)
			.await
		})
		.await
	});
	for step in &steps {
		writeln!(out, "ok\t{step}").map_err(|error| error.to_string())?;
	}
	match result {
		Ok(Ok(())) => {
			writeln!(
				status,
				"relay test passed for {host}:{port}; no mail was sent"
			)
			.map_err(|error| error.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		Ok(Err(error)) => Err(format!(
			"relay test failed for {host}:{port}: {}",
			reason(error)
		)),
		Err(_) => Err(format!(
			"relay test failed for {host}:{port}: no answer within {} s",
			limit.as_secs_f32()
		)),
	}
}
