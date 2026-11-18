//! Command variants for administration.

macro_rules! administration_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Manage the configured mail domains and domain aliases.
			///
			/// Operate on the configured mail domains: list, show, add, remove, or edit
			/// the `domain_aliases` map.
			Domain {
				/// Configuration file; accepted before or after the action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Domain administration action.
				#[command(subcommand)]
				action: domain::DomainCli,
			},

			/// Show, set, or unset numeric server and domain limits.
			Limits {
				/// Configuration file; accepted before or after the limits action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Limits administration action.
				#[command(subcommand)]
				action: limits::Action,
			},

			/// Manage the DNS provider used for record automation.
			Dns {
				/// Configuration file; accepted before or after the dns action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// DNS administration area.
				#[command(subcommand)]
				action: dns_provider::DnsCli,
			},
			/// Manage where uploaded blobs are stored.
			Storage {
				/// Configuration file; accepted before or after the storage action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// Storage administration area.
				#[command(subcommand)]
				action: crate::cli::storage::blobs::StorageCli,
			},
			/// Manage the SRS secret of each hosted domain.
			Srs {
				/// Configuration file; accepted before or after the srs action.
				#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Print the validated diff without writing or restarting.
				#[arg(long, global = true)]
				dry_run: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long, global = true)]
				json: bool,
				/// SRS secret administration action.
				#[command(subcommand)]
				action: crate::cli::srs::SrsCli,
			},
		}
	};
}

pub(super) use administration_commands;
