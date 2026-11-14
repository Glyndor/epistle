//! Command variants for operations.

macro_rules! operations_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Rotate every secret this server can rotate, after a compromise.
			///
			/// `--dry-run` lists every secret and credential, what epistle does and
			/// what stays with the operator, and changes nothing. Without it the
			/// command gives every API key and app password a new secret, replaces
			/// the webhook secret and each domain's SRS secret, resets the password
			/// and second factor of every account, asks the server to rotate the
			/// DKIM keys, and restarts the mail service. It asks first; a run cut
			/// short is continued by the next one.
			Rotate {
				/// Configuration file; accepted before or after the action. The
				/// listing does not read it.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Go through every secret and credential.
				#[arg(long, conflicts_with = "accounts_only")]
				all: bool,
				/// Only reset the password and second factor of every account; with
				/// `--dry-run`, list the accounts it would reset.
				#[arg(long)]
				accounts_only: bool,
				/// Print the plan without changing anything.
				#[arg(long)]
				dry_run: bool,
				/// Skip the confirmation. Without a terminal the run is refused
				/// with exit code 2 unless this is given.
				#[arg(long, short = 'y')]
				yes: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Manage the outbound event webhook.
			Webhook {
				/// Configuration file; accepted before or after the webhook action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Webhook administration action.
				#[command(subcommand)]
				action: crate::cli::webhook::admin::WebhookCli,
			},
			/// Manage metric alert rules.
			Alert {
				/// Configuration file; accepted before or after the alert action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Alert administration action.
				#[command(subcommand)]
				action: alert::AlertCli,
			},
			/// Manage outbound smarthost (relay) rules.
			Relay {
				/// Configuration file; accepted before or after the relay action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Relay administration action.
				#[command(subcommand)]
				action: relay::RelayCli,
			},
			/// List, enable, or disable individual service listeners.
			Service {
				/// Configuration file; accepted before or after the service action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Listener administration action.
				#[command(subcommand)]
				action: service::ServiceCli,
			},
			/// Report whether the mail server is working, area by area.
			///
			/// Report whether the mail server is working: one line per area (config,
			/// ports, tls, dns, db, antivirus, queue, disk). Exits 1 when any area
			/// fails. Sends no mail and authenticates nothing.
			Status {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print one JSON object keyed by area instead of a table.
				#[arg(long)]
				json: bool,
			},
			/// Run one health check and list what it found.
			Check {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The area to check.
				#[arg(value_enum, value_name = "AREA")]
				area: status::CheckArea,
				/// Print the result as JSON instead of a table.
				#[arg(long)]
				json: bool,
			},
			/// Show or edit the antispam settings.
			///
			/// DNSBL lists, greylist delay, clamd and the LLM classifier.
			Antispam {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Antispam administration action.
				#[command(subcommand)]
				action: antispam::AntispamCli,
			},
			/// Show or edit the attachment policy, or check a message.
			///
			/// What each attachment really is, and what the `[attachments]` policy
			/// does with it.
			Attachments {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Attachments action.
				#[command(subcommand)]
				action: attachments::AttachmentsCli,
			},
			/// Manage multi-target aliases.
			///
			/// Show, add, remove or edit them; enable or disable them.
			Alias {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Alias administration action.
				#[command(subcommand)]
				action: alias::AliasCli,
			},
		}
	};
}

pub(super) use operations_commands;
