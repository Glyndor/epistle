//! Configuration for the external clock probe: the three independent
//! sources and thresholds applied to the largest absolute valid offset.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::assessment::{Outcome, SignedOffset};

pub(super) const EXPECTED_SOURCES: usize = 3;

/// Default source list the area uses when nothing else is configured: three
/// NTS sources run by three different operators in three countries, each
/// one measured to complete the whole NTS exchange, so every offset in the
/// default run is authenticated.
///
/// `nts.netnod.se` is Netnod (Sweden), `nts.time.nl` is SIDN Labs
/// (Netherlands) and `ptbtime2.ptb.de` is the Physikalisch-Technische
/// Bundesanstalt (Germany). `time.cloudflare.com` answers plain NTPv4 but
/// its key exchange returns cookies the authenticated poll never answers
/// from the networks measured, and `time.google.com` publishes no NTS-KE
/// endpoint, so neither is in the default list; either can be added as a
/// plain `ntp` source.
///
/// The median is diagnostic; every valid offset affects the verdict. The
/// list is a default, not a rule: an operator can change the hosts and
/// the protocol per source, and a host that answers NTS on their network
/// can be configured as `nts`.
pub fn default_sources() -> Vec<Source> {
	vec![
		Source::nts("nts.netnod.se"),
		Source::nts("nts.time.nl"),
		Source::nts("ptbtime2.ptb.de"),
	]
}

/// Default warn threshold (seconds, inclusive).
pub const DEFAULT_WARN_SECONDS: f64 = 1.0;

/// Default fail threshold (seconds, inclusive).
pub const DEFAULT_FAIL_SECONDS: f64 = 5.0;

/// Default port for NTS-KE (RFC 8915).
pub const NTS_KE_PORT: u16 = 4460;

/// Default port for NTP (RFC 5905).
pub const NTP_PORT: u16 = 123;

/// The role of a configured source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
	/// Network Time Security over TLS 1.3 (RFC 8915) plus authenticated NTPv4.
	Nts,
	/// Plain NTPv4 (RFC 5905), unauthenticated.
	Ntp,
}

/// One entry in the source list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
	/// Hostname (punycode/ASCII) the probe targets.
	pub host: String,
	/// Authentication role.
	#[serde(rename = "kind")]
	pub kind: SourceKind,
	/// Override the default port (NTS-KE 4460, NTP 123).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub port: Option<u16>,
}

impl Source {
	/// Build an NTS source at the default port.
	pub fn nts(host: impl Into<String>) -> Self {
		Self {
			host: host.into(),
			kind: SourceKind::Nts,
			port: None,
		}
	}

	/// Build an NTP source at the default port.
	pub fn ntp(host: impl Into<String>) -> Self {
		Self {
			host: host.into(),
			kind: SourceKind::Ntp,
			port: None,
		}
	}

	/// The port the probe dials for this source.
	pub fn dial_port(&self) -> u16 {
		match (self.kind, self.port) {
			(SourceKind::Nts, None) => NTS_KE_PORT,
			(SourceKind::Ntp, None) => NTP_PORT,
			(_, Some(port)) => port,
		}
	}

	/// Short, log-safe label: `kind:host`.
	pub fn label(&self) -> String {
		format!("{}:{}", self.kind, self.host)
	}

	/// True when the source is NTS-authenticated.
	pub fn is_nts(&self) -> bool {
		matches!(self.kind, SourceKind::Nts)
	}
}

impl fmt::Display for SourceKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			SourceKind::Nts => f.write_str("nts"),
			SourceKind::Ntp => f.write_str("ntp"),
		}
	}
}

/// The configured block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockExternal {
	/// Run the probe at all. `false` turns it off: `epistle status` says the
	/// probe is switched off and makes no network call, for a host with no
	/// route to 123/udp or 4460/tcp. The rest of the block is still validated.
	#[serde(default = "default_enabled")]
	pub enabled: bool,
	/// Permit internal destinations: private, loopback and link-local
	/// addresses. Multicast, unspecified and limited broadcast destinations
	/// remain forbidden. It grants no permission over ports.
	#[serde(default)]
	pub allow_private_networks: bool,
	/// Ports the probe may dial besides the standard one for the protocol
	/// (NTS-KE 4460/tcp, NTP 123/udp). Each entry is a port number; none may
	/// be zero and none may repeat.
	#[serde(default)]
	pub allowed_ports: Vec<u16>,
	/// Inclusive warn threshold (seconds), applied to the largest absolute
	/// valid offset. Missing readings produce at least `Warn`. The median
	/// and smear candidate remain diagnostic values.
	#[serde(default = "default_warn_seconds")]
	pub warn_seconds: f64,
	/// Inclusive fail threshold (seconds).
	#[serde(default = "default_fail_seconds")]
	pub fail_seconds: f64,
	/// Source list. Absent or empty uses [`default_sources`]. Exactly three
	/// entries, no duplicate hosts, and at least one of them authenticated
	/// over NTS.
	#[serde(default = "default_source_list")]
	pub sources: Vec<Source>,
}

impl Default for ClockExternal {
	fn default() -> Self {
		Self {
			enabled: true,
			allow_private_networks: false,
			allowed_ports: Vec::new(),
			warn_seconds: DEFAULT_WARN_SECONDS,
			fail_seconds: DEFAULT_FAIL_SECONDS,
			sources: default_sources(),
		}
	}
}

fn default_enabled() -> bool {
	true
}

fn default_warn_seconds() -> f64 {
	DEFAULT_WARN_SECONDS
}

fn default_fail_seconds() -> f64 {
	DEFAULT_FAIL_SECONDS
}

fn default_source_list() -> Vec<Source> {
	default_sources()
}

impl ClockExternal {
	/// Validate the configuration. The check returns the first failure so a
	/// config loader can refuse to start with a single error message.
	///
	/// The protocol mix is the operator's: three sources with at least one
	/// NTS entry, in any distribution. The list is not pinned to the
	/// defaults, and a source may be configured as NTS when its
	/// authenticated exchange answers on the operator's network.
	pub fn validate(&self) -> Result<(), String> {
		if !self.warn_seconds.is_finite() || self.warn_seconds <= 0.0 {
			return Err(
				"[clock_external] warn_seconds must be a positive finite number".to_string(),
			);
		}
		if !self.fail_seconds.is_finite() || self.fail_seconds <= 0.0 {
			return Err(
				"[clock_external] fail_seconds must be a positive finite number".to_string(),
			);
		}
		if self.warn_seconds >= self.fail_seconds {
			return Err(
				"[clock_external] warn_seconds must be strictly less than fail_seconds".to_string(),
			);
		}
		if self.sources.len() != EXPECTED_SOURCES {
			return Err("[clock_external] sources must hold exactly three entries".to_string());
		}
		self.validate_allowed_ports()?;
		let policy = self.policy();
		let mut nts = 0usize;
		let mut hosts: Vec<String> = Vec::with_capacity(self.sources.len());
		for source in &self.sources {
			if source.host.trim().is_empty() {
				return Err("[clock_external] sources[].host is empty".to_string());
			}
			if source.host.len() > 253 {
				return Err("[clock_external] sources[].host exceeds 253 octets".to_string());
			}
			if !source.host.is_ascii() {
				return Err("[clock_external] sources[].host is not ASCII".to_string());
			}
			if source
				.host
				.chars()
				.any(|c| c.is_control() || c.is_whitespace())
			{
				return Err(
					"[clock_external] sources[].host contains a control or whitespace character"
						.to_string(),
				);
			}
			super::endpoint::validate_host(
				&source.host,
				source.dial_port(),
				if source.is_nts() {
					NTS_KE_PORT
				} else {
					NTP_PORT
				},
				&policy,
			)
			.map_err(|why| format!("[clock_external] {why}"))?;
			hosts.push(source.host.to_ascii_lowercase());
			match source.kind {
				SourceKind::Nts => nts += 1,
				SourceKind::Ntp => {}
			}
		}
		if nts == 0 {
			return Err(
				"[clock_external] sources must include at least one NTS source".to_string(),
			);
		}
		hosts.sort();
		for pair in hosts.windows(2) {
			if pair[0] == pair[1] {
				return Err("[clock_external] sources contain duplicate hosts".to_string());
			}
		}
		Ok(())
	}

	/// Resolve configured sources with defaults applied. Used at validate time
	/// to render the effective list alongside diagnostics.
	pub fn effective_sources(&self) -> Vec<Source> {
		if self.sources.is_empty() {
			default_sources()
		} else {
			self.sources.clone()
		}
	}

	/// The destination policy the probe applies to every address and port it
	/// dials, built from the two independent opt-ins.
	pub(super) fn policy(&self) -> super::endpoint::Policy {
		super::endpoint::Policy::from_config(self.allow_private_networks, &self.allowed_ports)
	}

	/// A port number is never zero, and a repeated entry widens nothing.
	fn validate_allowed_ports(&self) -> Result<(), String> {
		let mut seen: Vec<u16> = Vec::with_capacity(self.allowed_ports.len());
		for port in &self.allowed_ports {
			if *port == 0 {
				return Err("[clock_external] allowed_ports must not contain port 0".to_string());
			}
			if seen.contains(port) {
				return Err(format!(
					"[clock_external] allowed_ports lists port {port} more than once"
				));
			}
			seen.push(*port);
		}
		Ok(())
	}

	/// Effective warn threshold (the configured value when valid, otherwise
	/// the default). Callers must have validated first.
	pub fn effective_warn(&self) -> f64 {
		if self.warn_seconds > 0.0 && self.warn_seconds.is_finite() {
			self.warn_seconds
		} else {
			DEFAULT_WARN_SECONDS
		}
	}

	/// Effective fail threshold (matches [`Self::effective_warn`]).
	pub fn effective_fail(&self) -> f64 {
		if self.fail_seconds > 0.0 && self.fail_seconds.is_finite() {
			self.fail_seconds
		} else {
			DEFAULT_FAIL_SECONDS
		}
	}
}

/// The outcome that the area renders for the operator.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeSummary {
	/// The configured sources, in the order probed.
	pub sources: Vec<Source>,
	/// Per-source result (signed offset, delay, error string).
	pub readings: Vec<ProbeReading>,
	/// The verdict the area emits.
	pub outcome: Outcome,
	/// Median of three valid readings, when available.
	pub median: Option<SignedOffset>,
	/// Potential smear reading, retained in the verdict despite the field name.
	pub smear_excluded: Option<usize>,
	/// Effective warn threshold (seconds, inclusive).
	pub warn_seconds: f64,
	/// Effective fail threshold (seconds, inclusive).
	pub fail_seconds: f64,
}

/// One source reading.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReading {
	/// The source this reading belongs to.
	pub source: Source,
	/// Remote minus local, in seconds. Positive means the local clock is
	/// behind the remote.
	pub offset_seconds: f64,
	/// Round-trip delay the exchange measured, in seconds.
	pub delay_seconds: f64,
	/// Failure reason when the source refused the round-trip. `None` means
	/// a signed offset and delay are present.
	pub error: Option<String>,
}

impl ProbeReading {
	/// A successful reading of `offset`/`delay`.
	pub fn ok(source: Source, offset_seconds: f64, delay_seconds: f64) -> Self {
		Self {
			source,
			offset_seconds,
			delay_seconds,
			error: None,
		}
	}

	/// A failed reading that carries an explanatory string.
	pub fn failed(source: Source, error: impl Into<String>) -> Self {
		Self {
			source,
			offset_seconds: 0.0,
			delay_seconds: 0.0,
			error: Some(error.into()),
		}
	}
}

#[cfg(test)]
#[path = "tests/source_tests.rs"]
mod tests;
