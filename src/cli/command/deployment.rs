//! Command variants for deployment.

macro_rules! deployment_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Drive `podup` against the compose file `epistle init` writes.
			///
			/// Drive the `podup` command-line against the compose file `epistle init`
			/// writes under `<data_dir>/compose/compose.yaml`. Subcommands: `up`,
			/// `down`, `ps [--json]`, `logs [--follow] [<service>]`, `restart
			/// [<service>]`, `update`. Runs `podup` underneath; never replaces it.
			Stack {
				/// Configuration file, defaults to the path written by packaged init.
				/// Global so it can appear before or after the stack subcommand.
				#[arg(
					long,
					value_name = "FILE",
					global = true,
					default_value = DEFAULT_CONFIG
				)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// The stack sub-action.
				#[command(subcommand)]
				action: stack::StackCli,
			},
			/// Database maintenance for the stack's PostgreSQL.
			Db {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Database action (`upgrade`).
				#[command(subcommand)]
				action: db_upgrade::DbCli,
			},
			/// Show the DKIM key in service, rotate it or split a shared key.
			///
			/// Rotation and cleanup are queued for the running server, which stays
			/// the only writer of keys and DNS records. `split` gives each domain that
			/// shares the `[dkim]` key a key of its own and switches signing only after
			/// the new records resolve.
			Dkim {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// DKIM action (`show`, `rotate`, `cleanup`, `split`).
				#[command(subcommand)]
				action: dkim::DkimCli,
			},
			/// Show the server's TLS certificate or renew it now.
			///
			/// Show the TLS certificate the server presents or ask it to renew the ACME
			/// certificate now.
			Tls {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// TLS action (`show`, `renew`).
				#[command(subcommand)]
				action: crate::cli::tls::cli::TlsCli,
			},
			/// Manage the management API keys.
			ApiKey {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// API key action (`list`, `create`, `revoke`, `rotate`).
				#[command(subcommand)]
				action: api_keys::ApiKeyCli,
			},
			/// Probe each enabled listener and report whether it answers.
			///
			/// Dials every `[[listeners]]` entry on its loopback equivalent
			/// (`127.0.0.1` for `0.0.0.0`, `::1` for `::`), reads the
			/// greeting the protocol advertises (SMTP `220`, IMAP `* OK`,
			/// POP3 `+OK`, ManageSieve `OK`, or HTTP for the API / WebDAV /
			/// autoconfig / ACME / metrics endpoints), and exits 0 if every
			/// listener answered. Exits 1 if any listener is down or
			/// answered with the wrong greeting. Designed for the distroless
			/// container's healthcheck: no shell, no curl, no credentials,
			/// no escalation; runs as the same user the listeners bound on.
			Probe {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print one JSON object per listener instead of the
				/// human-readable `ok <kind> <addr>` / `fail <kind> <addr>: <reason>`
				/// lines. Each object carries `kind`, `addr`, `ok`, and an
				/// `error` field on failure.
				#[arg(long)]
				json: bool,
			},
			/// Move mail and settings from another mail server into this one.
			///
			/// `imap` copies a remote account's folders over IMAP and can be run
			/// again to copy only what arrived since.
			Migrate(migrate::MigrateArgs),
			/// Print a shell completion script on stdout.
			///
			/// The Debian package already installs all three; this is for a binary
			/// installed by hand, for example
			/// `epistle completions bash > ~/.local/share/bash-completion/completions/epistle`.
			Completions {
				/// The shell to write the script for.
				#[arg(value_enum, value_name = "SHELL")]
				shell: completions::CompletionShell,
			},
			/// Move the service account off a subordinate id block another account
			/// shares. Run by the package on upgrade, as root.
			#[command(hide = true)]
			MoveSubids(subid::MoveArgs),
			/// Write `epistle.1` and one man page per subcommand into DIR.
			///
			/// Run by debian/rules at package build time.
			#[command(hide = true)]
			Manpages {
				/// Directory to write the pages into; created when missing.
				#[arg(value_name = "DIR")]
				dir: PathBuf,
			},
		}
	};
}

pub(super) use deployment_commands;
