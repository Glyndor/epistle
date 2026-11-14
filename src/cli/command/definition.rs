//! Assemble one public enum so variant paths and clap ordering stay stable.
//!
//! Rust macros cannot expand into individual enum variants. Each private
//! responsibility macro appends its unchanged tokens and passes them on;
//! only the final callback emits the complete enum.

use super::super::*;
use super::account_delivery::account_delivery_commands;
use super::administration::administration_commands;
use super::deployment::deployment_commands;
use super::discovery::discovery_commands;
use super::keys::keys_commands;
use super::mail_data::mail_data_commands;
use super::operations::operations_commands;
use super::server::server_commands;
use super::setup::setup_commands;

macro_rules! define_command {
	(; $($variants:tt)*) => {
		/// Every subcommand the `epistle` binary understands. Each variant
		/// corresponds to a top-level entry in `epistle --help`, with its own
		/// arguments; the `Cli::run` dispatch in `mod dispatch` pairs each
		/// variant with the right handler module.
		#[derive(Debug, Subcommand)]
		pub enum Command {
			$($variants)*
		}
	};
}

server_commands! {
	keys_commands,
	mail_data_commands,
	discovery_commands,
	account_delivery_commands,
	setup_commands,
	administration_commands,
	operations_commands,
	deployment_commands,
	define_command;
}
