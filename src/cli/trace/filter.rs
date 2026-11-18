//! The log level filter of the server.

use tracing_subscriber::EnvFilter;

/// What runs when `RUST_LOG` says nothing: `info` for everything, and the
/// DNSSEC validator of the resolver silent. That library logs the whole parsed
/// response and its raw buffer, as a warning or an error, for every lookup into
/// a zone that is not signed (no NSEC, no DS). That is the normal state of most
/// zones, not a failure, so epistle reports the outcome of each lookup itself,
/// in one line, from `crate::spf::dns`.
const DEFAULT_DIRECTIVES: &str = "info,hickory_net::dnssec=off,hickory_proto::dnssec=off";

/// The filter for the value of `RUST_LOG`, or the default when it is unset
/// or does not parse. A value that is set is the operator's to the letter, so
/// `RUST_LOG=info,hickory_net::dnssec=warn` brings the library's lines back.
pub(super) fn log_filter(spec: Option<&str>) -> EnvFilter {
	spec.filter(|spec| !spec.trim().is_empty())
		.and_then(|spec| EnvFilter::try_new(spec).ok())
		.unwrap_or_else(|| EnvFilter::new(DEFAULT_DIRECTIVES))
}

#[cfg(test)]
mod tests;
