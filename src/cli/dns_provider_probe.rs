//! `dns provider test`: list the zone's records through the provider.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use crate::config::Config;
use crate::dns::provider::DnsProvider;

const LIMIT: Duration = Duration::from_secs(10);

pub(super) fn run(
	config: &Config,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, super::resource::ResourceError> {
	let dns = config.dns.as_ref().ok_or_else(|| {
		super::resource::ResourceError::refused(
			"no DNS provider is configured; run `epistle dns provider set` first",
		)
	})?;
	if dns.provider.eq_ignore_ascii_case("manual") {
		return Err(super::resource::ResourceError::refused(
			"the manual provider has no API to test",
		));
	}
	let provider = dns.build_for_host(&config.hostname).ok_or_else(|| {
		super::resource::ResourceError::Failure(
			"the provider credentials could not be resolved: check that the environment variable or file is available to the service account"
				.to_string(),
		)
	})?;
	run_with(&dns.zone, provider.as_ref(), LIMIT, out, status)
}

pub(super) fn run_with(
	zone: &str,
	provider: &dyn DnsProvider,
	limit: Duration,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, super::resource::ResourceError> {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| {
			super::resource::ResourceError::Failure(format!(
				"cannot start the async runtime: {error}"
			))
		})?;
	let result = runtime.block_on(async { tokio::time::timeout(limit, provider.list(zone)).await });
	match result {
		Ok(Ok(records)) => {
			writeln!(out, "ok\t{} records in {zone}", records.len())
				.map_err(|error| super::resource::ResourceError::Failure(error.to_string()))?;
			writeln!(status, "dns provider test passed; nothing was changed")
				.map_err(|error| super::resource::ResourceError::Failure(error.to_string()))?;
			Ok(ExitCode::SUCCESS)
		}
		Ok(Err(error)) => Err(super::resource::ResourceError::Failure(format!(
			"dns provider test failed for {zone}: {error}"
		))),
		Err(_) => Err(super::resource::ResourceError::Failure(format!(
			"dns provider test failed for {zone}: no answer within {} s",
			limit.as_secs_f32()
		))),
	}
}
