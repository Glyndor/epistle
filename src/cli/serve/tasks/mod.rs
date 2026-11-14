//! Background maintenance tasks spawned by `serve`, kept out of the main
//! startup flow.

use tokio::net::TcpListener;

/// A listener's serving future, boxed so the different concrete servers can
/// share one vector.
///
/// The future is built where the socket is bound but spawned later: `serve`
/// holds every listener until the privileges are dropped, and only then
/// starts them, so no connection is ever accepted or served as root.
pub(super) type ListenerTask =
	std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;

/// Bind a listener's socket and log it. Thin wrapper over the
/// `bind` module so the existing callers stay unchanged; the
/// dual-stack switch for the IPv6-unspecified address lives in
/// [`bind::bind_listener`].
pub(super) async fn bind(
	listener: &crate::config::Listener,
	ipv4_any_ports: &std::collections::HashSet<u16>,
) -> std::io::Result<TcpListener> {
	bind::bind_listener(listener, ipv4_any_ports).await
}

/// The future that serves an axum router on a bound listener. Shared
/// by the plain-HTTP listener arms (autoconfig, ACME, WebDAV, metrics).
///
/// It is not spawned here: the caller holds it until the privileges are
/// dropped and starts it after.
pub(super) fn serve_http(
	listener: TcpListener,
	router: axum::Router,
	limits: crate::net::http_serve::Limits,
) -> ListenerTask {
	Box::pin(crate::net::http_serve::serve_with(listener, router, limits))
}

#[cfg(test)]
mod tests;

mod alerts;
mod bans;
mod directory;
mod oauth;
mod sweeps;

pub(in crate::cli) use alerts::single_signature_dkim_warning;
pub(super) use alerts::{build_arc_sealer, log_single_signature_dkim_warning, spawn_alert_engine};
#[cfg(test)]
pub(super) use bans::run_ban_sweep_once;
pub(super) use bans::{build_greylist, spawn_ban_sweep};
pub(in crate::cli) use directory::connect_database;
pub(super) use directory::{build_ldap_authenticator, spawn_ldap_directory, spawn_sql_directory};
pub(super) use oauth::build_authz_server;
pub(in crate::cli) use oauth::build_oauth_verifier;
pub(super) use sweeps::{
	dmarc_journal_dir, retention_days, spawn_dmarc_flush, spawn_storage_maintenance,
	spawn_tlsrpt_reports,
};

mod bayes;

pub(in crate::cli) use bayes::open_bayes;

mod bind;

mod dkim_rotation;

pub(crate) mod dns_reconcile;

mod domain_rotation;

pub(super) use domain_rotation::spawn_domain_rotations;
pub(in crate::cli) use domain_rotation::{decide_domain_rotation, dns_publishes_for};

pub(super) use dkim_rotation::spawn_dkim_rotation;
pub(in crate::cli) use dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};

mod dns_write;

pub(in crate::cli) use dns_write::DnsWrite;
