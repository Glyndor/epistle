//! Runtime setup, tracing, and process exit status.

use super::{Config, ServeRole, serve};
use std::process::ExitCode;

/// Run the server with a validated configuration, as `role`.
pub fn run(config: Config, role: ServeRole) -> ExitCode {
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			crate::cli::style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	// Initialise tracing inside the runtime so the OTLP batch exporter (if any)
	// can spawn its background task. The provider is held for a clean shutdown.
	let _guard = runtime.enter();
	let otel_provider = crate::cli::trace::init_tracing(&config);

	let result = match role {
		ServeRole::Certs => runtime.block_on(super::certs::serve(config)),
		ServeRole::All | ServeRole::Mail => runtime.block_on(serve(config, role)),
	};

	// Flush any buffered spans to the collector before exiting.
	if let Some(provider) = otel_provider
		&& let Err(error) = provider.shutdown()
	{
		tracing::warn!(%error, "otel provider shutdown failed");
	}
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			crate::cli::style::error(error);
			ExitCode::FAILURE
		}
	}
}
