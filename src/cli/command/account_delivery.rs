//! Command variants for account delivery.

macro_rules! account_delivery_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Manage the outbound suppression list.
			///
			/// Addresses land on the list when they hard-bounce; mail queued for a
			/// suppressed address is dropped without a bounce. Without an action
			/// the command lists, like `suppression list`.
			Suppression {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as JSON, for the listing without an action and
				/// for whichever action follows.
				#[arg(long)]
				json: bool,
				/// Suppression action (`list`, `add`, `remove`).
				#[command(subcommand)]
				action: Option<suppression::SuppressionCli>,
				/// Older form of `suppression remove ADDRESS`.
				#[arg(long, value_name = "ADDRESS", hide = true)]
				remove: Option<String>,
				/// Older form of `--account` for the list/remove without an action.
				#[arg(long, value_name = "ACCOUNT", hide = true)]
				account: Option<String>,
			},
			/// Turn a message on stdin into an RFC 5965 ARF abuse report.
			///
			/// Read an offending message on stdin and print an RFC 5965 ARF abuse
			/// report (send it to the offending sender's abuse address).
			ReportAbuse {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
			},
			/// The older flat commands (`accounts`, `account-add`, `app-passwords`,
			/// `api-key-create`, ...), kept so existing scripts still parse.
			#[command(flatten)]
			Legacy(legacy::Legacy),
			/// Manage accounts: list, add, remove, and change one in place.
			///
			/// Operate on a single dynamic account in place: change its password,
			/// enable or disable authentication, add or remove a delivery address, set
			/// the storage quota and the protocol allowlist, or print the public view.
			/// Each subcommand refuses a static account with a hint to edit the config
			/// file. The legacy top-level `account-add` and `account-remove` commands
			/// remain available for compatibility.
			Account {
				/// Path to the configuration file. Global so it can appear
				/// before or after the sub-action; the dispatch test passes it
				/// last, which a positional flag would not parse.
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
				/// The action to run on the account.
				#[command(subcommand)]
				action: account::Subcommand,
			},
			/// Inspect and steer the outbound delivery queue.
			///
			/// Without an action it lists the queue, like `queue list`.
			Queue {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Queue action (`list`, `show`, `retry`, `hold`, `release`, `remove`).
				#[command(subcommand)]
				action: Option<queue::QueueCli>,
			},
			/// See and steer the IP warm-up of a new sending address.
			///
			/// A daily cap per receiver group that grows on good days and backs off
			/// on bad ones.
			Warmup {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Warm-up action (`status`, `enable`, `disable`, `pause`, `resume`, `set`, `reset`).
				#[command(subcommand)]
				action: warmup::WarmupCli,
			},
			/// Read the per-recipient delivery log (metadata only).
			///
			/// Without an action it lists the log, like `delivery list`.
			Delivery(delivery::DeliveryConfig),
			/// Evidence of sending, and the bundles that prove it.
			///
			/// Verify the log, export and check bundles, set what is kept, and manage
			/// timestamping and the signing key. `check` runs anywhere, without
			/// configuration or server data.
			Evidence {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Evidence action (`verify`, `export`, `check`, `policy`, `timestamp`, `acknowledge`).
				#[command(subcommand)]
				action: evidence::EvidenceCli,
			},
			/// Manage authentication bans and the allow list.
			///
			/// Manage authentication bans and the allow list (needs `[database]`).
			/// Changes apply to the running server immediately.
			Ban {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Ban action (`list`, `add`, `remove`, `allow`).
				#[command(subcommand)]
				action: ban::BanCli,
			},
			/// What each account's corpus learned from its user.
			///
			/// A message moved into Junk, or out of it, teaches the account's
			/// corpus (needs `[database]`). Changes apply to the running server at
			/// its next lesson, with no restart.
			Learning {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Learning action (`status`, `enable`, `disable`, `reset`).
				#[command(subcommand)]
				action: learning::LearningCli,
			},
			/// Manage an account's masked addresses.
			///
			/// Changes apply to the running server within a couple of seconds, with no
			/// restart.
			Masked {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Masked action (`list`, `add`, `remove`, `enable`, `disable`).
				#[command(subcommand)]
				action: masked::MaskedCli,
			},
			/// Manage app passwords (extra IMAP/SMTP credentials).
			AppPassword {
				/// Path to the configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// App password action (`list`, `create`, `revoke`).
				#[command(subcommand)]
				action: crate::cli::app::passwords::AppPasswordCli,
			},
			/// Hash a bearer token for use in `[api] token_hash`.
			///
			/// Reads the plaintext token from stdin (one line). Prints a
			/// `sha256:<hex>` string to stdout, ready to paste into the config file.
			TokenHash {
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Inspect and restore an account's expunged-message archive.
			///
			/// Inspect and operate on the per-account expunged-message archive
			/// (`<account>/.archive/`), enabled by `[storage] deleted_retention_days`.
			/// Each subcommand targets one account.
			Archive {
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// The archive sub-action (`list`, `restore`, `purge`).
				#[command(subcommand)]
				action: archive::Subcommand,
			},
		}
	};
}

pub(super) use account_delivery_commands;
