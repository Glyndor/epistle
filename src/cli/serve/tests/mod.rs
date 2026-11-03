pub use super::*;

/// The whole server in one process, as `epistle serve` runs it by default.
pub(super) async fn serve(config: Config) -> std::io::Result<()> {
	super::serve(config, ServeRole::All).await
}

mod acme_stop;
mod base;
mod limits;
mod mta_sts;
mod oauth;
mod ratelimit;
mod ratelimit_charge;
mod ratelimit_cross_protocol;
mod ratelimit_per_recipient;
mod roles;
