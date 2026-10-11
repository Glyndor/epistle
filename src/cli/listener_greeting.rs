//! Does a listener answer with its protocol greeting? Used by `epistle
//! status`; kept free of the status types so the probe command can share it.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::ListenerKind;

/// How a listener introduces itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Greeting {
	/// SMTP banner: first line starts with `220`.
	Smtp,
	/// IMAP greeting: `* OK`.
	Imap,
	/// POP3 greeting: `+OK`. No plaintext POP3 listener exists today (it is
	/// implicit TLS only), so only the tests build this; it stays so the
	/// shared function covers the protocol when a probe needs it.
	#[cfg_attr(not(test), allow(dead_code))]
	Pop3,
	/// ManageSieve capabilities ending in a line that starts with `OK`.
	ManageSieve,
	/// HTTP: any status line answers a `HEAD /`.
	Http,
	/// TLS from the first byte: only a TCP connect is attempted.
	TcpOnly,
}

/// The greeting a listener kind speaks. STARTTLS listeners greet in clear
/// text; implicit-TLS ones cannot be read without a handshake.
pub(super) fn greeting_for(kind: ListenerKind) -> Greeting {
	match kind {
		ListenerKind::Smtp | ListenerKind::Submission => Greeting::Smtp,
		ListenerKind::Imap => Greeting::Imap,
		ListenerKind::ManageSieve => Greeting::ManageSieve,
		ListenerKind::Submissions | ListenerKind::Imaps | ListenerKind::Pop3s => Greeting::TcpOnly,
		ListenerKind::Api
		| ListenerKind::Metrics
		| ListenerKind::Acme
		| ListenerKind::Autoconfig
		| ListenerKind::WebDav => Greeting::Http,
	}
}

/// Most bytes read from a listener: a banner is short, and a peer that never
/// ends its line must not make the check allocate without bound.
const MAX_READ: u64 = 8 * 1024;

/// ManageSieve capability lines read before giving up on finding `OK`.
const MAX_SIEVE_LINES: usize = 32;

/// Connect to `addr` and check the greeting, all within `timeout`. On success
/// the detail is the greeting line (or `connected` for a TCP-only check); on
/// failure it is one short sentence.
pub(super) async fn expect_greeting(
	addr: SocketAddr,
	greeting: Greeting,
	timeout: Duration,
) -> Result<String, String> {
	match tokio::time::timeout(timeout, exchange(addr, greeting)).await {
		Ok(result) => result,
		Err(_) if greeting == Greeting::TcpOnly => {
			Err(format!("cannot connect: no answer within {timeout:?}"))
		}
		Err(_) => Err(format!("no greeting within {timeout:?}")),
	}
}

async fn exchange(addr: SocketAddr, greeting: Greeting) -> Result<String, String> {
	let mut stream = TcpStream::connect(addr)
		.await
		.map_err(|error| format!("cannot connect: {error}"))?;
	let (prefix, farewell): (&str, &[u8]) = match greeting {
		Greeting::TcpOnly => return Ok("connected".to_string()),
		Greeting::Smtp => ("220", b"QUIT\r\n"),
		Greeting::Imap => ("* OK", b"a LOGOUT\r\n"),
		Greeting::Pop3 => ("+OK", b"QUIT\r\n"),
		Greeting::ManageSieve => ("OK", b"LOGOUT\r\n"),
		Greeting::Http => ("HTTP/1.", b""),
	};
	if greeting == Greeting::Http {
		stream
			.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			.await
			.map_err(|error| format!("cannot send the request: {error}"))?;
	}
	let mut reader = BufReader::new(stream.take(MAX_READ));
	let mut line = read_line(&mut reader).await?;
	if greeting == Greeting::ManageSieve {
		// Capability lines come first; the answer is the first OK/NO/BYE line.
		let mut lines = 1;
		while !["OK", "NO", "BYE"]
			.iter()
			.any(|word| line.starts_with(word))
		{
			lines += 1;
			if lines > MAX_SIEVE_LINES {
				return Err("no OK line after the ManageSieve capabilities".to_string());
			}
			line = read_line(&mut reader).await?;
		}
	}
	let verdict = if line.starts_with(prefix) {
		Ok(line)
	} else {
		Err(format!("unexpected greeting: {line}"))
	};
	if !farewell.is_empty() {
		// Leave politely; the verdict does not depend on it.
		let _ = reader.get_mut().get_mut().write_all(farewell).await;
	}
	verdict
}

/// One line without its terminator, made safe to print.
async fn read_line<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<String, String> {
	let mut line = String::new();
	let mut bytes = Vec::new();
	let read = reader
		.read_until(b'\n', &mut bytes)
		.await
		.map_err(|error| format!("cannot read the greeting: {error}"))?;
	if read == 0 {
		return Err("connection closed without a greeting".to_string());
	}
	line.push_str(&String::from_utf8_lossy(&bytes));
	let clean: String = line
		.trim_end_matches(['\r', '\n'])
		.chars()
		.map(|c| if c.is_control() { '?' } else { c })
		.take(80)
		.collect();
	Ok(clean)
}

#[cfg(test)]
#[path = "listener_greeting_tests.rs"]
mod tests;
