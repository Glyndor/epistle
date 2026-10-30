//! Raw-wire attacks against an isolated production ManageSieve listener.

#[path = "hostile_managesieve/abuse.rs"]
mod abuse;
#[path = "hostile_managesieve/auth_tls.rs"]
mod auth_tls;
#[path = "hostile_managesieve/framing.rs"]
mod framing;
#[path = "hostile_managesieve/harness.rs"]
mod harness;
#[path = "hostile_managesieve/names.rs"]
mod names;
#[path = "hostile_managesieve/scripts.rs"]
mod scripts;
#[path = "hostile_pop3/wire.rs"]
mod wire;
