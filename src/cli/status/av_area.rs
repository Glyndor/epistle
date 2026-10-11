//! The `antivirus` check: when `[antispam] clamd_socket` is set, clamd
//! answers `PING` with `PONG`, and its `VERSION` reply tells how old the
//! signature database is. Neither command scans anything or touches mail.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::clock::{epoch, parse_clamd_date};
use super::report::{AreaReport, Item, Level};
use super::{Ctx, NET_TIMEOUT};

/// A clamd reply to a one-line command is short; this bounds what a
/// misbehaving peer can make the check read.
const MAX_REPLY: u64 = 4096;

/// Check the configured clamd.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	match &config.antispam.clamd_socket {
		Some(socket) => evaluate(socket, epoch(ctx.now), NET_TIMEOUT).await,
		None => AreaReport::ok("no [antispam] clamd_socket is configured"),
	}
}

async fn evaluate(socket: &Path, now: i64, limit: Duration) -> AreaReport {
	let ping = match command(socket, "PING", limit).await {
		Ok(reply) if reply == "PONG" => Item::new("ping", Level::Ok, "clamd answered PONG"),
		Ok(reply) => Item::new(
			"ping",
			Level::Fail,
			format!("unexpected reply: {}", printable(&reply)),
		),
		Err(error) => return AreaReport::fail(error),
	};
	let version = match command(socket, "VERSION", limit).await {
		Ok(reply) => version_item(&reply, now),
		Err(error) => Item::new("version", Level::Warn, error),
	};
	let summary = match ping.status {
		Level::Ok => format!("clamd answers; {}", version.detail),
		_ => ping.detail.clone(),
	};
	AreaReport::from_items(vec![ping, version], summary)
}

/// Send one `n`-prefixed (newline-terminated) command and return the reply
/// line, all within `limit`.
async fn command(socket: &Path, word: &str, limit: Duration) -> Result<String, String> {
	let exchange = async {
		let mut stream = UnixStream::connect(socket)
			.await
			.map_err(|error| format!("cannot connect to {}: {error}", socket.display()))?;
		stream
			.write_all(format!("n{word}\n").as_bytes())
			.await
			.map_err(|error| format!("cannot send {word}: {error}"))?;
		let mut reply = Vec::new();
		stream
			.take(MAX_REPLY)
			.read_to_end(&mut reply)
			.await
			.map_err(|error| format!("cannot read the {word} reply: {error}"))?;
		Ok(String::from_utf8_lossy(&reply)
			.trim_end_matches(['\n', '\0', '\r'])
			.to_string())
	};
	match tokio::time::timeout(limit, exchange).await {
		Ok(result) => result,
		Err(_) => Err(format!("no {word} reply within {limit:?}")),
	}
}

/// `ClamAV 1.0.1/27000/Mon Oct  9 08:00:00 2026`: program version, database
/// version, database date. Older or custom builds may omit the last two.
fn version_item(reply: &str, now: i64) -> Item {
	let mut parts = reply.splitn(3, '/');
	let program = parts.next().unwrap_or_default();
	let date = parts.nth(1).and_then(parse_clamd_date);
	match date {
		Some(built) => {
			let days = (now - built).max(0) / 86_400;
			Item::new(
				"version",
				Level::Ok,
				format!(
					"{program}, signature database {days} day{} old",
					if days == 1 { "" } else { "s" }
				),
			)
		}
		None => Item::new(
			"version",
			Level::Ok,
			format!(
				"{}, signature database age not reported",
				printable(program)
			),
		),
	}
}

fn printable(text: &str) -> String {
	text.chars()
		.map(|c| if c.is_control() { '?' } else { c })
		.take(80)
		.collect()
}

#[cfg(test)]
#[path = "av_area_tests.rs"]
mod tests;
