//! The `epistle` subcommands, one variant per top-level entry in
//! `epistle --help`. Kept apart from `cli/mod.rs` so the module index stays
//! small.

use super::*;

/// Every subcommand the `epistle` binary understands. Each variant
/// corresponds to a top-level entry in `epistle --help`, with its own
/// arguments; the `Cli::run` dispatch in `mod dispatch` pairs each
/// variant with the right handler module.
#[derive(Debug, Subcommand)]
pub enum Command {
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
	},
	/// Validate a configuration file and report problems.
	ConfigCheck {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
	},
	/// Generate a DKIM key and print the DNS record value.
	DkimKeygen {
		/// Where to write the private key (PKCS#8 PEM).
		#[arg(long, value_name = "FILE")]
		out: PathBuf,
		/// Generate an RSA key (via `openssl genpkey`) instead of the default
		/// ed25519 key. The TXT record then uses `k=rsa` and is split across
		/// 255-octet strings per RFC 1035 §3.3.14.
		#[arg(long)]
		rsa: bool,
		/// RSA modulus size in bits, only meaningful with `--rsa`. Accepts
		/// 2048 (default) or 4096.
		#[arg(long, value_name = "BITS", default_value_t = 2048)]
		bits: u32,
	},
	/// Generate an at-rest message-encryption key and print it.
	///
	/// Generate a base64 32-byte at-rest message-encryption key and print it to
	/// stdout. Store it off the data disk (an env var or a key file), then
	/// point `[storage]` at it; never written into data_dir.
	StorageKeygen,
	/// Generate the ES256 key pair for the built-in OAuth server.
	///
	/// Generate an ES256 key pair for the built-in OAuth authorization server
	/// and write it to a file only the owner can read: the base64 PKCS#8
	/// private key for `[oauth] signing_key` and the matching base64 public
	/// point for `[oauth] public_key`. The private key is never printed.
	OauthKeygen {
		/// Where to write the key pair (mode 0600; an existing file is refused).
		#[arg(long, value_name = "FILE")]
		out: PathBuf,
	},
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
	},
	/// Verify on-disk data integrity (run before an upgrade).
	Verify {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
	},
	/// Check published DNS records against what epistle expects.
	///
	/// Check published DNS records against what epistle expects and report
	/// drift (read-only; queries DNS, changes nothing).
	VerifyDns {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
	},
	/// Print the DNS records this deployment should publish.
	///
	/// Print the DNS records this deployment should publish (SPF, DKIM, DMARC,
	/// MTA-STS, MX and a DANE TLSA record when a certificate is present).
	DnsRecords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
	},
	/// Print an Apple `.mobileconfig` profile for an account.
	///
	/// Print an Apple `.mobileconfig` profile for an account (for the user to
	/// install on iOS/macOS to auto-configure Mail).
	Mobileconfig {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// The account name.
		#[arg(long, value_name = "NAME")]
		account: String,
	},
	/// Print the RFC 6186 SRV records to publish in DNS.
	SrvRecords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
	},
	/// Print the Thunderbird autoconfig XML for a domain.
	///
	/// Print the Thunderbird autoconfig XML for a domain (host it at
	/// `autoconfig.<domain>/mail/config-v1.1.xml`).
	Autoconfig {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// The domain (defaults to the first configured domain).
		#[arg(long, value_name = "DOMAIN")]
		domain: Option<String>,
	},
	/// Print the Microsoft Autodiscover v1 XML for a domain.
	///
	/// Print the Microsoft Autodiscover v1 XML for a domain (host it at
	/// `autodiscover.<domain>/autodiscover/autodiscover.xml`).
	Autodiscover {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// The domain (defaults to the first configured domain).
		#[arg(long, value_name = "DOMAIN")]
		domain: Option<String>,
	},
	/// Manage the outbound suppression list.
	///
	/// Addresses land on the list when they hard-bounce; mail queued for a
	/// suppressed address is dropped without a bounce. Without an action
	/// the command lists, like `suppression list`.
	Suppression {
		/// Path to the configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
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
	/// Manage authentication bans and the allow list.
	///
	/// Manage authentication bans and the allow list (needs `[database]`).
	/// Changes apply to the running server immediately.
	Ban {
		/// Path to the configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// Ban action (`list`, `add`, `remove`, `allow`).
		#[command(subcommand)]
		action: ban::BanCli,
	},
	/// Manage an account's masked addresses.
	///
	/// Changes apply to the running server within a couple of seconds, with no
	/// restart.
	Masked {
		/// Path to the configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// Masked action (`list`, `add`, `remove`, `enable`, `disable`).
		#[command(subcommand)]
		action: masked::MaskedCli,
	},
	/// Manage app passwords (extra IMAP/SMTP credentials).
	AppPassword {
		/// Path to the configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// App password action (`list`, `create`, `revoke`).
		#[command(subcommand)]
		action: app_passwords::AppPasswordCli,
	},
	/// Hash a bearer token for use in `[api] token_hash`.
	///
	/// Reads the plaintext token from stdin (one line). Prints a
	/// `sha256:<hex>` string to stdout, ready to paste into the config file.
	TokenHash,
	/// Inspect and restore an account's expunged-message archive.
	///
	/// Inspect and operate on the per-account expunged-message archive
	/// (`<account>/.archive/`), enabled by `[storage] deleted_retention_days`.
	/// Each subcommand targets one account.
	Archive {
		/// The archive sub-action (`list`, `restore`, `purge`).
		#[command(subcommand)]
		action: archive::Subcommand,
	},
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
	},
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
		action: storage_blobs::StorageCli,
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
		action: webhook_admin::WebhookCli,
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
		/// The stack sub-action.
		#[command(subcommand)]
		action: stack::StackCli,
	},
	/// Database maintenance for the stack's PostgreSQL.
	Db {
		/// Configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// Database action (`upgrade`).
		#[command(subcommand)]
		action: db_upgrade::DbCli,
	},
	/// Show the DKIM key in service, rotate it or clean up old keys.
	///
	/// Rotation and cleanup are queued for the running server, which stays
	/// the only writer of keys and DNS records.
	Dkim {
		/// Configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// DKIM action (`show`, `rotate`, `cleanup`).
		#[command(subcommand)]
		action: dkim_cli::DkimCli,
	},
	/// Show the server's TLS certificate or renew it now.
	///
	/// Show the TLS certificate the server presents or ask it to renew the ACME
	/// certificate now.
	Tls {
		/// Configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
		/// TLS action (`show`, `renew`).
		#[command(subcommand)]
		action: tls_cli::TlsCli,
	},
	/// Manage the management API keys.
	ApiKey {
		/// Configuration file; accepted before or after the action.
		#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG)]
		config: PathBuf,
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
