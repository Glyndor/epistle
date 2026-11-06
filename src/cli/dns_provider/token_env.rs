//! The environment variable that holds the DNS token: whether this command
//! sees it, and where it has to be visible for the container to read it.
//!
//! `dns provider set` knows the name of the variable the operator gave, so
//! it can report a variable this command does not see while the operator is
//! still watching, instead of leaving the failure to `dns provider test`
//! ("the provider credentials could not be resolved"). The configuration is
//! written either way: the operator may set the variable afterwards.
//!
//! The value of the variable is never read into a message. Only its name
//! is, because a token printed in a terminal is a token in a log.

/// Whether `name` is set in this process's environment and carries
/// something: an empty variable resolves no credential either, the same way
/// the token reader in `crate::config::dns` reads it.
pub(super) fn is_set(name: &str) -> bool {
	std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

/// The warning for a token variable this command does not see: it names the
/// variable and says where it has to be visible.
///
/// `service` is the service of the generated stack that holds the
/// credential, when the install has a generated compose file: that file
/// forwards the variable to it as `${NAME}`, and the value is taken from
/// the environment of the account that runs the container. Without a
/// generated compose file the variable is read by epistle itself, so it has
/// to be visible to the account that runs it.
pub(super) fn warning(name: &str, service: Option<&str>) -> String {
	match service {
		Some(service) => format!(
			"{name} is not set or is empty in the environment of this command; the generated compose file forwards it to the {service} container as ${{{name}}}, and the service account that runs the container has to see it, or `dns provider test` cannot resolve the provider credentials"
		),
		None => format!(
			"{name} is not set or is empty in the environment of this command; the service account that runs epistle has to see it, or `dns provider test` cannot resolve the provider credentials"
		),
	}
}
