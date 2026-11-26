//! The client address behind a front.
//!
//! A front sees the real client and the core, behind a Unix socket, sees none.
//! The front writes the address in one `X-Epistle-Peer` header, and on a front
//! socket the core reads it into the `ConnectInfo` everything else uses, so the
//! `--ip-cidr` check, the bearer limiter and `trusted_proxies` work unchanged.
//! On TCP the header means nothing, and is removed before anything reads it.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The header a front writes.
pub const PEER_HEADER: &str = "x-epistle-peer";

/// The one valid address in `headers`, or `None` when the header is absent,
/// repeated or not an address.
fn one_peer(headers: &HeaderMap) -> Option<IpAddr> {
	let mut values = headers.get_all(PEER_HEADER).iter();
	let value = values.next()?;
	if values.next().is_some() {
		return None;
	}
	value.to_str().ok()?.trim().parse().ok()
}

/// On a front socket: take the client address from `X-Epistle-Peer` and remove
/// the header. A request without exactly one is `400`: a front always writes
/// one, so its absence means something else is on the socket.
pub async fn from_header(mut request: Request, next: Next) -> Response {
	let Some(peer) = one_peer(request.headers()) else {
		tracing::warn!("a request on a front socket carries no single valid X-Epistle-Peer");
		return StatusCode::BAD_REQUEST.into_response();
	};
	request.headers_mut().remove(PEER_HEADER);
	request
		.extensions_mut()
		.insert(ConnectInfo(SocketAddr::new(peer, 0)));
	next.run(request).await
}

/// On TCP: remove every `X-Epistle-Peer`, so a client cannot choose the
/// address the core sees.
pub async fn strip(mut request: Request, next: Next) -> Response {
	request.headers_mut().remove(PEER_HEADER);
	next.run(request).await
}
