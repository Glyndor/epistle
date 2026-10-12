//! Journal of the TLS sessions our outbound deliveries had, per recipient
//! domain and UTC day, for the daily TLS-RPT report (RFC 8460 §4).
//!
//! One JSON line per delivery attempt under
//! `data_dir/reports/tlsrpt-outbound/{YYYYMMDD}/{domain}.jsonl`, written with
//! the same append-only, locked, owner-only discipline as the inbound report
//! store. Losing a line costs one session in a report, so a write failure is
//! logged and never holds up delivery.

use std::net::IpAddr;
use std::path::Path;

use crate::mtasts::{Mode, Policy};
use crate::queue::tls_outcome::TlsOutcome;
use crate::reports::store::OUTBOUND_TLSRPT;

use super::report::{RESULT_SUCCESS, TlsSession};

/// What one delivery attempt to a recipient domain's MX knew about policy and
/// addresses when its TLS outcome was decided.
pub struct Attempt<'a> {
	/// The recipient domain, the policy domain of the report.
	pub policy_domain: &'a str,
	/// The MX host name the attempt connected to.
	pub mx_host: &'a str,
	/// The domain's MTA-STS policy, in any mode, when one was fetched.
	pub sts: Option<&'a Policy>,
	/// The domain publishes MTA-STS but its policy could not be parsed.
	pub sts_invalid: bool,
	/// DANE applied: validated TLSA records were found for the MX.
	pub dane: bool,
	/// Our address on the connection.
	pub local_ip: Option<IpAddr>,
	/// The MX's address on the connection.
	pub peer_ip: Option<IpAddr>,
}

/// Append the session for `attempt` ending in `outcome` at `now` (Unix
/// seconds) to that day's journal.
pub fn record(data_dir: &Path, now: u64, attempt: &Attempt<'_>, outcome: TlsOutcome) {
	let session = session(attempt, outcome, now);
	let day = crate::dmarc::aggregate::unix_to_day(now);
	let file = crate::reports::bounds::file_component(&session.policy_domain);
	if let Err(error) =
		crate::reports::store::append_to(data_dir, OUTBOUND_TLSRPT, &day, &file, &session)
	{
		tracing::warn!(%error, domain = %session.policy_domain, "TLS-RPT session not recorded");
	}
}

fn session(attempt: &Attempt<'_>, outcome: TlsOutcome, now: u64) -> TlsSession {
	// DANE takes precedence over MTA-STS when both apply (RFC 8461 §2).
	let policy_type = if attempt.dane {
		"tlsa"
	} else if attempt.sts.is_some() || attempt.sts_invalid {
		"sts"
	} else {
		"no-policy-found"
	};
	let sts = attempt.sts.filter(|_| !attempt.dane);
	TlsSession {
		timestamp: now,
		policy_type: policy_type.to_string(),
		policy_domain: attempt.policy_domain.to_ascii_lowercase(),
		policy_strings: sts.map(policy_strings).unwrap_or_default(),
		mx_host: sts.map(|policy| policy.mx.clone()).unwrap_or_default(),
		sending_mta_ip: attempt
			.local_ip
			.map(|ip| ip.to_string())
			.unwrap_or_default(),
		receiving_mx_hostname: attempt.mx_host.to_string(),
		receiving_ip: attempt.peer_ip.map(|ip| ip.to_string()).unwrap_or_default(),
		result: match outcome {
			TlsOutcome::Success => RESULT_SUCCESS.to_string(),
			TlsOutcome::Failure(result_type) => result_type.to_string(),
		},
	}
}

/// The MTA-STS policy as the `policy-string` lines of RFC 8460 §4.4.
fn policy_strings(policy: &Policy) -> Vec<String> {
	let mode = match policy.mode {
		Mode::Enforce => "enforce",
		Mode::Testing => "testing",
		Mode::None => "none",
	};
	let mut lines = vec!["version: STSv1".to_string(), format!("mode: {mode}")];
	lines.extend(policy.mx.iter().map(|mx| format!("mx: {mx}")));
	lines.push(format!("max_age: {}", policy.max_age));
	lines
}
