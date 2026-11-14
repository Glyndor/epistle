//! Command variants for setup.

macro_rules! setup_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Summarise recent DMARC aggregate and TLS-RPT reports.
			///
			/// Summarise what receivers told us via DMARC aggregate reports and TLS-RPT
			/// reports for the last `--days` days (default 7). Reads the JSONL store
			/// under `data_dir/reports/`; never writes to it.
			Reports {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Number of past days to include. Defaults to 7; the retention
				/// ceiling lives in `crate::reports::RETENTION_DAYS`.
				#[arg(long, value_name = "N", default_value_t = reports::DEFAULT_DAYS)]
				days: u32,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Run a self-contained loopback test server.
			///
			/// Self-contained loopback server: a test harness that touches nothing
			/// outside `--dir` and the loopback interface. Generates a working
			/// directory on first run, reuses it byte for byte on later runs, and never
			/// opens an outbound SMTP connection. Not a deployment.
			Local {
				/// Directory the harness writes its state into. Created if missing.
				#[arg(long, value_name = "DIR")]
				dir: PathBuf,
				/// First listener port; the six endpoints are
				/// `port-base + {25, 587, 465, 143, 993, 8025}`. Default `10000` and
				/// must keep every port inside `1024..=65535`.
				#[arg(long, value_name = "N", default_value_t = local::DEFAULT_PORT_BASE)]
				port_base: u16,
			},
			/// First-run setup: check answers, make keys, write the config.
			///
			/// First-run setup: validate the answers, generate the keys, write the
			/// configuration file. Interactive when no `--answers` file is given. DNS
			/// publishing and public-address detection are not implemented in this
			/// build; the plan reports those steps as not implemented so the operator
			/// knows what to expect.
			Init {
				/// Read answers from this TOML file instead of asking interactively.
				#[arg(long, value_name = "FILE")]
				answers: Option<PathBuf>,
				/// Print the plan and exit without touching anything.
				#[arg(long)]
				dry_run: bool,
				/// Print the answers template to stdout and exit.
				#[arg(long)]
				print_answers: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
		}
	};
}

pub(super) use setup_commands;
