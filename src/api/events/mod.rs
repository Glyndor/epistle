//! `GET /api/v1/events`: a stream of notifications for the panel's live
//! dashboards, so they update when something changes instead of polling.
//!
//! A `text/event-stream` for a key with the `read` scope. Each event names
//! what changed and nothing else: `queue`, `deliveries`, `suppression`,
//! `status`, `accounts` or `domains`, with an opaque `id`. No address, no
//! subject, no message content and no credential is ever in one; the client
//! fetches the detail from the route it already uses, so every authorization
//! check stays where it is.
//!
//! - **Source.** The server has no bus of changes, and none is added: while
//!   at least one stream is open a single task reads a cheap fingerprint of
//!   the queue, the delivery log, the suppression lists, the hosted domains
//!   and the accounts every second, and appends a notification
//!   when one moved. A burst inside the window is one notification. With no
//!   stream open the task is not running.
//! - **Scope.** A key confined to some domains is told only about `status`,
//!   `accounts` and `domains`, and only when the change touched a domain or
//!   an account it reaches, decided by [`crate::api::Principal`] the way the routes
//!   decide it. The queue, the delivery log and the shared suppression list
//!   are not offered to it: they need a read of each entry to be filtered,
//!   which a stream refuses to do every second. A key bound to one account
//!   is refused, as on every administrative route.
//! - **Resume.** Every event carries an id. The last 256
//!   notifications are kept in memory, and a client that reconnects with
//!   `Last-Event-ID` gets what it missed, one event per topic. An id the
//!   server cannot replay from (another run of the server, or one the ring no
//!   longer holds) gets one event per topic the key may be told about, which
//!   means "refetch".
//! - **Bounds.** A cap of open streams per key and per server (`429`), a
//!   heartbeat comment, a maximum lifetime, and no queue per stream: a stream
//!   holds a position in the ring, and one that falls behind the ring is
//!   closed rather than buffered for. The credential is checked again every
//!   half second, so a revoked, expired or narrowed key ends the
//!   stream.

mod handler;
mod hub;
mod limits;
mod sampler;
mod stream;
mod topic;

pub use handler::get;
pub use hub::Hub;
pub use limits::EventLimits;

#[cfg(test)]
mod tests;
