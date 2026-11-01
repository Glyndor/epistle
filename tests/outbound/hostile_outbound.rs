//! Hostile outbound peers and message analysis against production components.
//! No external services, configuration changes or persistent fixtures.

#[path = "hostile_outbound/archives.rs"]
mod archives;
#[path = "hostile_outbound/authentication.rs"]
mod authentication;
#[path = "hostile_outbound/bounces.rs"]
mod bounces;
#[path = "hostile_outbound/deadlines.rs"]
mod deadlines;
#[path = "hostile_outbound/harness.rs"]
mod harness;
#[path = "hostile_outbound/headers.rs"]
mod headers;
#[path = "hostile_outbound/mime.rs"]
mod mime;
#[path = "hostile_outbound/smtp.rs"]
mod smtp;
#[path = "hostile_outbound/webhooks.rs"]
mod webhooks;
