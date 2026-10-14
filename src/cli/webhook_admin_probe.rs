//! `webhook test`: post one documented `test` event and report the answer.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::resource::ResourceError;
use crate::config::Config;

const LIMIT: Duration = Duration::from_secs(10);

pub(super) fn run(
	config: &Config,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	run_within(config, LIMIT, out, status)
}

pub(super) fn run_within(
	config: &Config,
	limit: Duration,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let settings = config.webhook.as_ref().ok_or_else(|| {
		ResourceError::refused("no webhook is configured; run `epistle webhook set` first")
	})?;
	let webhook =
		crate::webhook::Webhook::new(&settings.url, settings.secret.clone()).map_err(|error| {
			ResourceError::Failure(format!("cannot prepare the webhook client: {error}"))
		})?;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| {
			ResourceError::Failure(format!("cannot start the async runtime: {error}"))
		})?;
	let result = runtime.block_on(async { tokio::time::timeout(limit, webhook.send_test()).await });
	match result {
		Ok(Ok(code)) if code.is_success() => {
			writeln!(out, "ok\tHTTP {}", code.as_u16())
				.map_err(|error| ResourceError::Failure(error.to_string()))?;
			writeln!(status, "webhook test passed; a `test` event was delivered")
				.map_err(|error| ResourceError::Failure(error.to_string()))?;
			Ok(ExitCode::SUCCESS)
		}
		Ok(Ok(code)) => Err(ResourceError::Failure(format!(
			"webhook test failed: the endpoint answered HTTP {}",
			code.as_u16()
		))),
		Ok(Err(error)) => Err(ResourceError::Failure(format!(
			"webhook test failed: {}",
			error.without_url()
		))),
		Err(_) => Err(ResourceError::Failure(format!(
			"webhook test failed: no answer within {} s",
			limit.as_secs_f32()
		))),
	}
}
