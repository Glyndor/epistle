//! Run the standalone MTA-STS HTTPS listener.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

pub(super) fn run(
	policy_dir: PathBuf,
	cert: PathBuf,
	key: PathBuf,
	listen: SocketAddr,
) -> ExitCode {
	let _ = tracing_subscriber::fmt()
		.with_writer(std::io::stderr)
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
		)
		.try_init();
	let result = (|| {
		let server = crate::mtasts::server::Server::new(
			policy_dir,
			crate::config::Tls {
				cert_file: cert,
				key_file: key,
				client_ca: None,
			},
		)
		.map_err(std::io::Error::other)?;
		tokio::runtime::Runtime::new()?.block_on(async {
			let listener = tokio::net::TcpListener::bind(listen).await?;
			let _ = writeln!(
				super::style::stderr(),
				"MTA-STS HTTPS listening on {}",
				listener.local_addr()?
			);
			tokio::select! {
				result = server.serve(listener) => result,
				result = tokio::signal::ctrl_c() => result,
			}
		})
	})();
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}
