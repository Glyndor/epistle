//! Read-only reachability probe for a configured smarthost.
//!
//! Walks the same handshake `deliver` performs before it starts a mail
//! transaction (greeting, EHLO, STARTTLS, AUTH) and stops with QUIT, so no
//! envelope or message is ever sent.

use tokio::io::{AsyncRead, AsyncWrite};

use super::{Conn, DeliveryError, tls_connect};
use crate::queue::timeouts::Phase;

/// Handshake `stream` as a relay client and report each completed step in
/// `steps`. STARTTLS, when requested, is authenticated against the web PKI the
/// way relay delivery does it. AUTH is only attempted over TLS.
pub async fn probe<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	starttls: bool,
	auth: Option<(&str, &str)>,
	steps: &mut Vec<&'static str>,
) -> Result<(), DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	probe_with(
		stream,
		server_name,
		ehlo_hostname,
		starttls,
		auth,
		true,
		steps,
	)
	.await
}

async fn probe_with<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	starttls: bool,
	auth: Option<(&str, &str)>,
	authenticate_pkix: bool,
	steps: &mut Vec<&'static str>,
) -> Result<(), DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let mut conn = Conn::new(Box::new(stream));
	conn.expect(220, Phase::Greeting).await?;
	steps.push("connect");
	conn.command(&format!("EHLO {ehlo_hostname}"), 250, Phase::Command)
		.await?;
	steps.push("EHLO");
	if starttls {
		if !conn.last_reply_contains("STARTTLS") {
			return Err(DeliveryError::Permanent(
				"smarthost does not offer STARTTLS".into(),
			));
		}
		conn.command("STARTTLS", 220, Phase::Command).await?;
		let (tls, _chain) = tls_connect(conn.into_inner(), server_name, authenticate_pkix)
			.await
			.map_err(|(error, _)| error)?;
		conn = Conn::new(Box::new(tls));
		conn.command(&format!("EHLO {ehlo_hostname}"), 250, Phase::Command)
			.await?;
		steps.push("STARTTLS");
	}
	if let Some((username, password)) = auth {
		if !starttls {
			return Err(DeliveryError::Permanent(
				"relay AUTH requires STARTTLS".into(),
			));
		}
		use base64::Engine;
		let token =
			base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
		conn.command(&format!("AUTH PLAIN {token}"), 235, Phase::Command)
			.await?;
		steps.push("AUTH");
	}
	// The server may drop the connection right after QUIT; the probe already
	// has everything it needs.
	let _ = conn.command("QUIT", 221, Phase::Quit).await;
	steps.push("QUIT");
	Ok(())
}

#[cfg(test)]
mod tests;
