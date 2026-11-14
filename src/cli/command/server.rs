//! Command variants for server.

macro_rules! server_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Serve the public MTA-STS policy over HTTPS.
			MtaStsServe {
				/// Directory containing mta-sts.txt.
				#[arg(long, value_name = "DIR")]
				policy_dir: PathBuf,
				/// PEM certificate chain covering `mta-sts.<domain>`.
				#[arg(long, value_name = "FILE")]
				cert: PathBuf,
				/// PEM private key for the certificate.
				#[arg(long, value_name = "FILE")]
				key: PathBuf,
				/// HTTPS socket address.
				#[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8443")]
				listen: std::net::SocketAddr,
			},
			/// Run the mail server.
			Serve {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The part of the server this process runs: `all` (the default),
				/// `mail` (listeners, certificate read from disk) or `certs`
				/// (certificate renewal only, no listener).
				#[arg(long, value_enum, default_value_t = serve::ServeRole::All)]
				role: serve::ServeRole,
			},
			/// Validate a configuration file and report problems.
			ConfigCheck {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
		}
	};
}

pub(super) use server_commands;
