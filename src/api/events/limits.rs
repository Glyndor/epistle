//! The bounds of the event stream.

use std::time::Duration;

/// Open streams one credential may hold.
pub(crate) const DEFAULT_PER_KEY: usize = 4;
/// Open streams the server holds in all.
pub(crate) const DEFAULT_PER_SERVER: usize = 64;
/// How long one stream lives before the client has to reconnect.
pub(crate) const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(3600);
/// How often a comment keeps an idle connection from being dropped by a proxy.
pub(crate) const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(15);
/// How often the sampler reads the fingerprints, and so the coalescing window.
pub(crate) const DEFAULT_SAMPLE: Duration = Duration::from_secs(1);
/// How often a stream looks at the ring and at its credential.
pub(crate) const DEFAULT_LOOK: Duration = Duration::from_millis(500);
/// Notifications kept for a reconnecting client, and the distance a stream may
/// fall behind before it is dropped.
pub(crate) const DEFAULT_RING: usize = 256;

/// The bounds one server applies. The first three are the operator's, in
/// `[api]`; the rest is fixed outside the tests.
#[derive(Debug, Clone, Copy)]
pub struct EventLimits {
	/// Open streams one key may hold.
	pub per_key: usize,
	/// Open streams the server holds in all.
	pub per_server: usize,
	/// How long one stream lives.
	pub max_lifetime: Duration,
	/// Interval of the keep-alive comment.
	pub heartbeat: Duration,
	/// Notifications kept in memory.
	pub ring: usize,
	/// Interval of the sampler, which is the coalescing window.
	pub sample: Duration,
	/// Interval at which a stream looks at the ring and its credential.
	pub look: Duration,
}

impl Default for EventLimits {
	fn default() -> Self {
		Self {
			per_key: DEFAULT_PER_KEY,
			per_server: DEFAULT_PER_SERVER,
			max_lifetime: DEFAULT_MAX_LIFETIME,
			heartbeat: DEFAULT_HEARTBEAT,
			ring: DEFAULT_RING,
			sample: DEFAULT_SAMPLE,
			look: DEFAULT_LOOK,
		}
	}
}
