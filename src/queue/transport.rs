//! Runtime side of outbound transports: opening a connection to a smarthost,
//! optionally through a SOCKS5 proxy. Route selection lives in
//! [`crate::config::transport`]; this module only does the connecting.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::client::DeliveryError;
use super::resolver::BoxedStream;

/// Connect to a smarthost `host:port`, directly or via a SOCKS5 proxy
/// (`proxy_host:proxy_port`). Connection failures are transient (retry later).
pub async fn relay_connect(
	host: &str,
	port: u16,
	socks_proxy: Option<&str>,
) -> Result<BoxedStream, DeliveryError> {
	let stream = match socks_proxy {
		Some(proxy) => socks5_connect(proxy, host, port).await?,
		None => TcpStream::connect((host, port))
			.await
			.map_err(|error| DeliveryError::Transient(format!("relay connect: {error}")))?,
	};
	Ok(Box::new(stream))
}

/// Open a TCP connection to `target_host:target_port` through a SOCKS5 proxy
/// (RFC 1928, no-authentication method). The proxy resolves the target name.
async fn socks5_connect(
	proxy: &str,
	target_host: &str,
	target_port: u16,
) -> Result<TcpStream, DeliveryError> {
	let host = target_host.as_bytes();
	if host.len() > 255 {
		return Err(DeliveryError::Permanent(
			"socks: target host too long".into(),
		));
	}
	let mut stream = TcpStream::connect(proxy)
		.await
		.map_err(|error| transient(format!("socks connect: {error}")))?;

	// Greeting: version 5, one method, "no authentication required" (0x00).
	stream
		.write_all(&[0x05, 0x01, 0x00])
		.await
		.map_err(|error| transient(format!("socks greet: {error}")))?;
	let mut method = [0u8; 2];
	stream
		.read_exact(&mut method)
		.await
		.map_err(|error| transient(format!("socks method: {error}")))?;
	if method != [0x05, 0x00] {
		return Err(DeliveryError::Permanent(
			"socks: proxy rejected no-auth method".into(),
		));
	}

	// CONNECT request, address type 3 (domain name); the proxy resolves it.
	let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
	request.extend_from_slice(host);
	request.extend_from_slice(&target_port.to_be_bytes());
	stream
		.write_all(&request)
		.await
		.map_err(|error| transient(format!("socks request: {error}")))?;

	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT. REP 0 == success.
	let mut head = [0u8; 4];
	stream
		.read_exact(&mut head)
		.await
		.map_err(|error| transient(format!("socks reply: {error}")))?;
	if head[0] != 0x05 {
		return Err(DeliveryError::Permanent("socks: bad reply version".into()));
	}
	if head[1] != 0x00 {
		return Err(DeliveryError::Transient(format!(
			"socks: connect failed (code {})",
			head[1]
		)));
	}
	// Drain the bound address so the stream is positioned at the payload.
	let addr_len = match head[3] {
		0x01 => 4,  // IPv4
		0x04 => 16, // IPv6
		0x03 => {
			let mut len = [0u8; 1];
			stream
				.read_exact(&mut len)
				.await
				.map_err(|error| transient(format!("socks bind len: {error}")))?;
			len[0] as usize
		}
		_ => {
			return Err(DeliveryError::Permanent(
				"socks: bad bound address type".into(),
			));
		}
	};
	let mut rest = vec![0u8; addr_len + 2]; // address + 2-byte port
	stream
		.read_exact(&mut rest)
		.await
		.map_err(|error| transient(format!("socks bind addr: {error}")))?;
	Ok(stream)
}

fn transient(reason: String) -> DeliveryError {
	DeliveryError::Transient(reason)
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
