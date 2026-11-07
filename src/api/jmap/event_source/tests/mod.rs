//! Hostile tests for the JMAP event source, over real HTTP on a loopback
//! port: the cap on open streams, the query parameters a hostile client
//! sends, a client that never reads, and the credentials the route refuses.

mod auth_gate;
mod backpressure;
mod base;
mod hostile_params;
mod stream_cap;
