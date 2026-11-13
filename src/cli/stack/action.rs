//! The `stack` subcommand as clap parses it, and the action each one becomes.

use clap::Subcommand;

use super::certs::CertsCli;
use super::resources;

/// The clap subcommand enum the dispatcher hands to [`run`]. The
/// shape mirrors the operator-facing verbs on the wire and is
/// translated one-to-one into the inner [`StackAction`] (kept
/// separate so the tests can build the action without clap).
#[derive(Debug, Subcommand)]
pub enum StackCli {
	/// Render compose.yaml again with this release, then recreate what changed.
	Update,
	/// Start the stack in the background.
	Up,
	/// Apply what `--no-restart` left waiting.
	///
	/// Recreates what changed, then restarts mail once.
	Apply,
	/// Stop the stack.
	///
	/// The compose volumes are not removed: the database lives in one of them.
	Down,
	/// List the running services (table by default, JSON with
	/// `--json`).
	Ps {
		/// Re-serialise the parsed list as JSON instead of a table.
		#[arg(long)]
		json: bool,
	},
	/// Stream the service logs.
	Logs {
		/// Follow the log output as it is produced.
		#[arg(long)]
		follow: bool,
		/// Optional service name to filter on.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Restart the whole stack, or a single service.
	Restart {
		/// Optional service name to restart.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Stop the whole stack, or one service, without removing containers.
	///
	/// Stop the whole stack, or a single service (for example `mail` before a
	/// restore, keeping `db` up), without removing containers.
	Stop {
		/// Optional service name to stop.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Start what `stop` stopped.
	Start {
		/// Optional service name to start.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Go back to the binary the last upgrade replaced; run as root.
	///
	/// When the new release already migrated the schema, the database dump
	/// `stack update` took before the restart is restored too. dpkg still
	/// records the newer version; see docs/cli.md for the limits.
	Rollback {
		/// The kept version to go back to; the newest one below this release
		/// by default.
		#[arg(long, value_name = "VERSION")]
		to: Option<String>,
		/// Do not ask for confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// The database half of `rollback`, run as the service account.
	#[command(hide = true)]
	RollbackDb,
	/// Move certificate renewal and the DNS credential to a certs container.
	///
	/// `disable` puts them back in mail. `enable` needs `[acme] challenge = "dns-01"` and a `[dns]` provider. See
	/// docs/operations/container-split.md.
	Certs {
		/// `enable` or `disable`.
		#[command(subcommand)]
		action: CertsCli,
	},
	/// List each service's memory and process limits, or change one with `set`.
	Resources {
		/// Print JSON instead of a table.
		#[arg(long, global = true)]
		json: bool,
		/// `set <SERVICE> --memory <SIZE>`; without it the limits are listed.
		#[command(subcommand)]
		action: Option<resources::ResourcesCli>,
	},
}

impl From<StackCli> for StackAction {
	fn from(value: StackCli) -> Self {
		match value {
			StackCli::Update => StackAction::Update,
			StackCli::Up => StackAction::Up,
			StackCli::Apply => StackAction::Apply,
			StackCli::Down => StackAction::Down,
			StackCli::Ps { json } => StackAction::Ps { as_json: json },
			StackCli::Logs { follow, service } => StackAction::Logs { follow, service },
			StackCli::Restart { service } => StackAction::Restart { service },
			StackCli::Stop { service } => StackAction::Passthrough {
				verb: "stop",
				service,
			},
			StackCli::Start { service } => StackAction::Passthrough {
				verb: "start",
				service,
			},
			StackCli::Rollback { .. } => StackAction::Rollback,
			StackCli::RollbackDb => StackAction::RollbackDb,
			StackCli::Certs { action } => action.action(),
			StackCli::Resources { json, action } => StackAction::Resources { action, json },
		}
	}
}

/// The stack subcommand the operator picked, with the operator's
/// `epistle` arguments already extracted by clap. The body here is a
/// straight `podup` wrapper, so each variant holds the trailing
/// arguments verbatim.
#[derive(Debug)]
pub(crate) enum StackAction {
	/// Render the compose file again, then recreate changed services and restart mail.
	Update,
	/// `podup -f <compose> up -d`, start the stack in the background.
	Up,
	/// `podup -f <compose> up -d`, then `restart mail`: what a run of
	/// commands with `--no-restart` left waiting, applied once.
	Apply,
	/// `podup -f <compose> down`, stop the stack. Volumes are never
	/// removed (`-v`/`--volumes` are deliberately not exposed): the
	/// PostgreSQL data lives in a named volume and the operator must
	/// not lose it.
	Down,
	/// `podup -f <compose> ps --format json`, print the running
	/// services as a small table, or as JSON with `--json`.
	Ps {
		/// Re-serialise the parsed list as JSON instead of the table.
		as_json: bool,
	},
	/// `podup -f <compose> logs [--follow] [<service>]`, stream the
	/// logs, optionally following and optionally filtered to one
	/// service.
	Logs {
		/// Pass `--follow` to podup.
		follow: bool,
		/// Optional service name to filter on; passed as a positional.
		service: Option<String>,
	},
	/// `podup -f <compose> restart [<service>]`, restart the whole
	/// stack or one service.
	Restart {
		/// Optional service name to restart; passed as a positional.
		service: Option<String>,
	},
	/// `podup -f <compose> <verb> [<service>]` for `stop` and `start`.
	Passthrough {
		/// The podup subcommand.
		verb: &'static str,
		/// Optional service name; passed as a positional.
		service: Option<String>,
	},
	/// Dispatched as root before the stack is reached; here only to keep
	/// the conversion total.
	Rollback,
	/// Stop mail and restore the pre-update dump if the schema moved.
	RollbackDb,
	/// Turn the certificates container on or off.
	Certs {
		/// `true` to run it.
		on: bool,
		/// Skip the confirmation.
		yes: bool,
	},
	/// Show or change the limits in the compose file; podup is not run.
	Resources {
		/// `set`, or `None` to list.
		action: Option<resources::ResourcesCli>,
		/// Print JSON.
		json: bool,
	},
	/// `podup -f <compose> up -d <service>`, recreate one service from
	/// the current compose file. A restart keeps the container as it was
	/// created, so a change to its published ports needs this.
	Recreate {
		/// The service to recreate.
		service: String,
	},
	/// `podup -f <compose> up -d <service>`, once for each service: a
	/// change that touches more than one of them has to reach both, and a
	/// container that keeps the mount it had still has the credential.
	RecreateServices {
		/// The services to recreate, in the order they are recreated.
		services: Vec<String>,
	},
}
