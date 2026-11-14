//! Command variants for mail data.

macro_rules! mail_data_commands {
	($next:ident $(, $rest:ident)*; $($variants:tt)*) => {
		$next! { $($rest),*;
			$($variants)*
			/// Export an account's mail as mbox on stdout or as Maildir.
			///
			/// Export an account's mailboxes to an mbox stream on stdout (backup), or
			/// to a Maildir tree with `--maildir`.
			Export {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The account name to export.
				#[arg(long, value_name = "NAME")]
				account: String,
				/// Export to a Maildir directory tree instead of an mbox stream.
				#[arg(long, value_name = "DIR")]
				maildir: Option<PathBuf>,
			},
			/// Import mail into an account from mbox on stdin or a Maildir.
			///
			/// Import mail into an account (migration): an mbox stream from stdin, or a
			/// Maildir tree with `--maildir`.
			Import {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// The account name to import into.
				#[arg(long, value_name = "NAME")]
				account: String,
				/// Import from a Maildir directory tree (incl. nested Dovecot folders)
				/// instead of an mbox stream on stdin.
				#[arg(long, value_name = "DIR")]
				maildir: Option<PathBuf>,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Write a consistent backup snapshot (gzip tar) to stdout.
			///
			/// Write a consistent backup snapshot (gzip tar) to stdout: the filesystem
			/// mail store plus a pg_dump when a database is configured.
			Backup {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
			},
			/// Restore a backup tar.gz read from stdin.
			///
			/// Replay a backup tar.gz (read from stdin) over the data directory and,
			/// when a database is configured, into the database. The hard rule matches
			/// `backup`: a `database.sql` in the archive that cannot be loaded is a
			/// restore error, not a silent skip. Refuses to overwrite an existing
			/// `data_dir` or run against a live mail service unless `--force` is set;
			/// `--dry-run` lists the entries that would be written and changes nothing.
			/// `--yes` skips the interactive confirmation that restore prompts on a
			/// terminal; it does not imply `--force`.
			Restore {
				/// Path to the configuration file.
				#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
				config: PathBuf,
				/// Allow overwriting a non-empty data dir or restoring while the
				/// mail service is running. Without this flag, the restore
				/// refuses so a stray command cannot destroy live data.
				#[arg(long)]
				force: bool,
				/// List the entries the restore would write, then exit without
				/// touching `data_dir` or restarting the service.
				#[arg(long)]
				dry_run: bool,
				/// Skip the interactive confirmation. A non-interactive run
				/// without `--yes` is refused with exit code 2; on a terminal
				/// the operator is asked to type `y`.
				#[arg(long, short = 'y')]
				yes: bool,
				/// Print the result as one JSON object on stdout.
				#[arg(long)]
				json: bool,
			},
			/// Verify on-disk data integrity (run before an upgrade).
			Verify {
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

pub(super) use mail_data_commands;
