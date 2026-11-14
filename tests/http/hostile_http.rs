//! Hostile requests against the production HTTP routers and loopback listener.
//! No external server, database, or environment switch is required.

#[path = "hostile_http/api.rs"]
mod api;
#[path = "hostile_http/desync.rs"]
mod desync;
#[path = "hostile_http/framing_matrix.rs"]
mod framing_matrix;
#[path = "hostile_http/harness.rs"]
mod harness;
#[path = "hostile_http/headers.rs"]
mod headers;
#[path = "hostile_http/jmap.rs"]
mod jmap;
#[path = "hostile_http/jmap_set_limits.rs"]
mod jmap_set_limits;
#[path = "hostile_http/jmap_wire.rs"]
mod jmap_wire;
#[path = "hostile_http/webdav.rs"]
mod webdav;
#[path = "hostile_http/webdav_create_race.rs"]
mod webdav_create_race;
#[path = "hostile_http/webdav_race.rs"]
mod webdav_race;
#[path = "hostile_http/webdav_wire.rs"]
mod webdav_wire;
#[path = "hostile_http/websocket_exhaustion.rs"]
mod websocket_exhaustion;
