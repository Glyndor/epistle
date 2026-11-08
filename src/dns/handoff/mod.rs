//! The hand-off between the two containers of a split stack.
//!
//! With the certificates container on, `mail` holds no DNS credential and
//! `certs` holds no DKIM private key. The DKIM rotation needs both: it makes
//! the key and it publishes the key's public record. So the rotation asks
//! for the write and `certs` performs it, through a directory both
//! containers mount read-write:
//!
//! ```text
//! <data_dir>/dns-handoff/
//! |-- requests/<id>   written by mail: what to write
//! `-- results/<id>    written by certs: whether it was written
//! ```
//!
//! `mail` writes the request, waits for the result, and continues the
//! rotation exactly as if the provider had answered. `certs` polls the
//! directory, performs the write with the provider it already holds, and
//! answers. Neither side trusts the other: everything read from the other
//! side is bounded and checked before it is used (see `validate.rs`), and a
//! request that is not a DKIM record of a domain this installation serves is
//! refused with a result that says so.
//!
//! The split off changes nothing: the rotation calls the provider directly,
//! and none of this is built.

use std::path::{Path, PathBuf};
use std::time::Duration;

mod format;
mod provider;
mod server;
mod validate;
mod writer;

pub use format::{Operation, Outcome, Request, Write};
pub use provider::HandoffProvider;
pub use server::Server;
pub use validate::check;
pub use writer::Writer;

/// The directory the hand-off lives in, under the data directory.
pub const DIR: &str = "dns-handoff";

/// The directory the requests live in, under the hand-off directory.
pub const REQUESTS: &str = "requests";

/// The directory the results live in, under the hand-off directory.
pub const RESULTS: &str = "results";

/// How long the asking side waits for the answer of one request.
///
/// A DNS write through a provider API takes seconds; the bound is generous
/// so a slow provider is not read as a broken one. A request that is not
/// answered in this time is a write that did not happen: the rotation takes
/// it back and the key in service keeps signing.
pub const RESULT_TIMEOUT: Duration = Duration::from_secs(60);

/// How old a request may be when the serving side picks it up.
///
/// The same bound as [`RESULT_TIMEOUT`]: a request the asking side has
/// already given up on must not be written, or a rotation that withdrew
/// would see its record published again behind its back.
pub const MAX_REQUEST_AGE: Duration = Duration::from_secs(60);

/// How far a request's clock may be ahead of the serving side's.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The longest request the serving side reads.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The longest result the asking side reads.
pub const MAX_RESULT_BYTES: usize = 16 * 1024;

/// The longest error text a result carries.
pub const MAX_ERROR_BYTES: usize = 4 * 1024;

/// The longest record value a request carries.
pub const MAX_VALUE_BYTES: usize = 4 * 1024;

/// The longest record name a request carries.
pub const MAX_NAME_BYTES: usize = 253;

/// The longest TTL a request may ask for, in seconds.
pub const MAX_TTL: u32 = 86_400;

/// The hand-off directory under `data_dir`.
pub fn dir(data_dir: &Path) -> PathBuf {
	data_dir.join(DIR)
}

/// The directory the requests live in.
pub fn requests_dir(root: &Path) -> PathBuf {
	root.join(REQUESTS)
}

/// The directory the results live in.
pub fn results_dir(root: &Path) -> PathBuf {
	root.join(RESULTS)
}

/// Whether `id` is a name the hand-off uses for a request and its result.
///
/// The ids are UUID v7 (lowercase hex and dashes), so a name that is
/// anything else cannot be a file this hand-off wrote, and cannot name a
/// file outside the directory it is looked for in.
pub fn valid_id(id: &str) -> bool {
	!id.is_empty()
		&& id.len() <= 64
		&& id
			.bytes()
			.all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase() || byte == b'-')
}

#[cfg(test)]
mod tests;
