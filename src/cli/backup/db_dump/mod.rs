//! The database half of `epistle backup` and `epistle restore`.
//!
//! This module owns:
//!
//! - [`BackupError`] and its `Display` impl. The variants name the
//!   concrete failure cause (binary missing, command failed, empty
//!   output, compose file missing) and never carry the password or
//!   the SQL bytes themselves; an operator looking at the error
//!   does not see the secret they typed into `password_file`.
//! - [`CommandSpec`], the pure data struct that captures one process
//!   invocation (argv, environment additions, stdin payload). The
//!   tests inspect it for the password-leak invariant; the runtime
//!   hands it to `Command::new`.
//! - The host-side spec builders ([`host_pg_dump_spec`],
//!   [`host_psql_load_spec`]) and the container-side ones
//!   ([`container_pg_dump_spec`], [`container_psql_load_spec`],
//!   [`container_cp_into_spec`]). The two halves share the
//!   invariant that the password never appears in argv; the host
//!   path uses `PGPASSWORD` env, and the container shell reads the
//!   mounted secret into `PGPASSWORD` before executing the client.
//! - The actual spawn-and-capture path. A `program_resolver` lets
//!   the test path point at a stub in a tempdir without mutating
//!   the process `PATH` (which would race other parallel tests).
//!
//! The split keeps `mod.rs` focused on the archive builder and
//! the data_dir walk; the database code here is the only place
//! that needs to know about `podup exec`, `pg_dump`, and
//! `psql`.

mod db_dump_container;
mod db_dump_host_temp;
mod db_dump_marker;
mod db_dump_target;
mod dispatch;
mod error;
mod host;
mod run;
mod spec;

#[cfg(test)]
use crate::config::Database;
use db_dump_container::load_dump_container_with;
pub(crate) use db_dump_container::{
	container_cp_into_spec, container_pg_dump_spec, container_psql_load_spec, load_dump_container,
};
#[cfg(test)]
use db_dump_container::{container_rm_temp_spec, leftover_note};
#[cfg(test)]
use db_dump_host_temp::{RestoreHostTemp, SQL_FILE_NAME};
pub(in crate::cli::backup) use db_dump_marker::output_ends_with_pg_dump_complete;
use db_dump_target::ensure_stack_database;
pub(crate) use dispatch::{
	collect_dump, collect_dump_with, load_dump, load_dump_with, pg_dump_spec, psql_load_spec,
};
pub use error::BackupError;
#[cfg(test)]
pub use host::split_url_password;
pub(crate) use host::{host_pg_dump_spec, host_psql_load_spec};
use run::run_command_capturing_stdout_with;
pub(crate) use run::{CapturedOutput, default_program_resolver, run_command_capturing_stdout};
pub use spec::CommandSpec;

#[cfg(test)]
mod tests;

/// The path of `database.sql` inside the backup archive.
pub(crate) const DATABASE_SQL_NAME: &str = "database.sql";
