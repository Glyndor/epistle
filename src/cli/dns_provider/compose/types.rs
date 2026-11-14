//! Token source and generated compose change descriptions.

use std::path::Path;

use crate::cli::config_edit::Companion;

/// Where the container reads the provider token from.
#[derive(Debug, Clone, Copy)]
pub(in crate::cli::dns_provider) enum TokenSource<'a> {
	/// An environment variable, forwarded to the container as `${NAME}`.
	Env(&'a str),
	/// A file, mounted read-only at the same path it has on the host.
	File(&'a Path),
}

/// The generated compose file with the credential inside, and what that
/// changes in it.
pub(in crate::cli::dns_provider) struct TokenUpdate {
	/// The file to write beside the configuration.
	pub(in crate::cli::dns_provider) companion: Companion,
	/// The lines that say what changes in it.
	pub(in crate::cli::dns_provider) lines: Vec<String>,
	/// The services whose definition in the file this change touches. The
	/// container of each one has to be recreated for the change to take
	/// effect: a container that keeps the mount it had still has the
	/// credential.
	pub(in crate::cli::dns_provider) changed: Vec<&'static str>,
}

/// What a change to the credential does to the generated compose file.
pub(in crate::cli::dns_provider) struct TokenChange {
	/// The file to write, `None` when the change leaves it as it is.
	pub(in crate::cli::dns_provider) update: Option<TokenUpdate>,
	/// What the operator has to know about it. The override the operator
	/// keeps beside the generated file is merged with it, so a credential
	/// it hands back to `mail` is a credential the container that takes
	/// SMTP still has, and nothing in the generated file says so.
	pub(in crate::cli::dns_provider) warnings: Vec<String>,
	/// The service of the generated stack that holds the credential, when
	/// the install has a generated compose file.
	pub(in crate::cli::dns_provider) service: Option<&'static str>,
}
