//! Hostile public HTTP requests through the production accept loops.
//! Duplex streams preserve HTTP/TLS bytes without requiring sandbox sockets.

mod acme;
mod discovery;
mod harness;
mod mtasts;
