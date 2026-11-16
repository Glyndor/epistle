//! What the outside will read about the message as sent: SPF from the
//! sending address, the DKIM signature against the published key, DMARC
//! alignment, and the reverse name against the EHLO name.

use std::net::IpAddr;

use serde::Serialize;

use super::plan::Plan;
use crate::config::Config;
use crate::dkim::{DkimOutcome, verify_message};
use crate::dmarc::{DmarcOutcome, evaluate_with_policy};
use crate::dns::check_host::{PtrOutcome, classify_ptr};
use crate::spf::{DnsLookup, SpfOutcome, check_host};

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Level {
	/// The outside will see it pass.
	Pass,
	/// Not a failure, but worth fixing.
	Warn,
	/// The outside will see it fail.
	Fail,
	/// It could not be established from here.
	Unknown,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Item {
	pub check: &'static str,
	pub level: Level,
	pub detail: String,
}

fn item(check: &'static str, level: Level, detail: impl Into<String>) -> Item {
	Item {
		check,
		level,
		detail: detail.into(),
	}
}

/// The public addresses the message leaves from: the configured ones, or
/// what the host name resolves to.
async fn sending_ips(config: &Config, dns: &dyn DnsLookup) -> Result<Vec<IpAddr>, ()> {
	let configured: Vec<IpAddr> = [
		config.public_ipv4.map(IpAddr::V4),
		config.public_ipv6.map(IpAddr::V6),
	]
	.into_iter()
	.flatten()
	.collect();
	if !configured.is_empty() {
		return Ok(configured);
	}
	dns.addresses(&config.hostname).await.map_err(|_| ())
}

/// Run every check on the signed message `data`. `signed` says whether the
/// signer produced a signature at all.
pub(super) async fn run(
	config: &Config,
	plan: &Plan,
	data: &[u8],
	signed: bool,
	dns: &dyn DnsLookup,
) -> Vec<Item> {
	let ips = sending_ips(config, dns).await;
	let (spf_item, spf) = spf(config, plan, ips.as_deref().ok(), dns).await;
	let dkim = verify_message(dns, data).await;
	let dkim_item = dkim_item(plan, signed, &dkim);
	let dmarc_item = dmarc_item(plan, spf, &dkim, dns).await;
	vec![
		spf_item,
		dkim_item,
		dmarc_item,
		ptr_item(config, ips.as_deref().ok(), dns).await,
		item(
			"tls",
			Level::Unknown,
			"the delivery log keeps no TLS version or certificate, so what the receiver saw is not recorded here",
		),
	]
}

async fn spf(
	config: &Config,
	plan: &Plan,
	ips: Option<&[IpAddr]>,
	dns: &dyn DnsLookup,
) -> (Item, Option<SpfOutcome>) {
	let Some(ips) = ips.filter(|ips| !ips.is_empty()) else {
		return (
			item(
				"spf",
				Level::Unknown,
				"the sending address is unknown: set public_ipv4 in the configuration, or publish an A record for the host name",
			),
			None,
		);
	};
	let mut outcomes = Vec::new();
	for ip in ips {
		let outcome = check_host(dns, *ip, &plan.domain, &plan.from, &config.hostname).await;
		outcomes.push((*ip, outcome));
	}
	let listed = outcomes
		.iter()
		.map(|(ip, outcome)| format!("{ip}: {}", outcome.as_str()))
		.collect::<Vec<_>>()
		.join(", ");
	let level = if outcomes.iter().all(|(_, o)| *o == SpfOutcome::Pass) {
		Level::Pass
	} else if outcomes.iter().any(|(_, o)| *o == SpfOutcome::TempError) {
		Level::Unknown
	} else if outcomes.iter().any(|(_, o)| *o == SpfOutcome::Neutral) {
		Level::Warn
	} else {
		Level::Fail
	};
	let representative = outcomes
		.iter()
		.map(|(_, outcome)| *outcome)
		.find(|outcome| *outcome == SpfOutcome::Pass)
		.or_else(|| outcomes.first().map(|(_, outcome)| *outcome));
	(
		item(
			"spf",
			level,
			format!(
				"for {} as {}, EHLO {}: {listed}",
				plan.domain, plan.from, config.hostname
			),
		),
		representative,
	)
}

fn dkim_item(plan: &Plan, signed: bool, results: &[crate::dkim::DkimResult]) -> Item {
	if !signed {
		return item(
			"dkim",
			Level::Fail,
			format!(
				"the message went out unsigned: no DKIM key is configured for {}",
				plan.domain
			),
		);
	}
	let aligned = |domain: &Option<String>| {
		domain
			.as_deref()
			.is_some_and(|d| d.eq_ignore_ascii_case(&plan.domain))
	};
	if results
		.iter()
		.any(|r| r.outcome == DkimOutcome::Pass && aligned(&r.domain))
	{
		return item(
			"dkim",
			Level::Pass,
			format!(
				"a signature for d={} verifies against the key published in DNS",
				plan.domain
			),
		);
	}
	let seen = results
		.iter()
		.map(|r| r.outcome.as_str())
		.collect::<Vec<_>>()
		.join(", ");
	let level = if results.iter().any(|r| r.outcome == DkimOutcome::TempError) {
		Level::Unknown
	} else {
		Level::Fail
	};
	item(
		"dkim",
		level,
		format!(
			"no signature for d={} verifies ({seen}); the key published in DNS does not match the one that signed",
			plan.domain
		),
	)
}

async fn dmarc_item(
	plan: &Plan,
	spf: Option<SpfOutcome>,
	dkim: &[crate::dkim::DkimResult],
	dns: &dyn DnsLookup,
) -> Item {
	let spf = spf.unwrap_or(SpfOutcome::None);
	let (outcome, policy) =
		evaluate_with_policy(dns, &plan.domain, (spf, Some(&plan.domain)), dkim).await;
	let published = policy.map_or(String::new(), |p| format!(" (published p={})", p.policy));
	let (level, text) = match outcome {
		DmarcOutcome::Pass => (
			Level::Pass,
			"SPF or DKIM passes and aligns with the From domain",
		),
		DmarcOutcome::Reject | DmarcOutcome::Fail => (
			Level::Fail,
			"neither SPF nor DKIM passes aligned with the From domain",
		),
		DmarcOutcome::None => (
			Level::Warn,
			"no DMARC record is published, so receivers apply no policy and several large ones ask for one",
		),
		DmarcOutcome::TempError => (Level::Unknown, "the DMARC record could not be read now"),
		DmarcOutcome::PermError => (Level::Fail, "the published DMARC record is not usable"),
	};
	item("dmarc", level, format!("{text}{published}"))
}

async fn ptr_item(config: &Config, ips: Option<&[IpAddr]>, dns: &dyn DnsLookup) -> Item {
	let Some(ips) = ips.filter(|ips| !ips.is_empty()) else {
		return item(
			"ptr",
			Level::Unknown,
			"the sending address is unknown, so its reverse name was not looked up",
		);
	};
	let host = &config.hostname;
	let mut worst = Level::Pass;
	let mut lines = Vec::new();
	for ip in ips {
		let (level, text) = match classify_ptr(host, *ip, dns).await {
			PtrOutcome::Ok => (
				Level::Pass,
				format!(
					"the name of {ip} is {host} and {host} resolves back to it, the same name the server gives in EHLO"
				),
			),
			PtrOutcome::None => (
				Level::Fail,
				format!(
					"{ip} has no reverse name; ask its provider to point it at {host}, the EHLO name"
				),
			),
			PtrOutcome::PointsElsewhere { found, .. } => (
				Level::Fail,
				format!("the reverse name of {ip} is {found}, not {host}, the EHLO name"),
			),
			PtrOutcome::DoesNotResolveBack => (
				Level::Fail,
				format!(
					"the reverse name of {ip} is {host} but {host} does not resolve back to it"
				),
			),
			PtrOutcome::LookupError => (
				Level::Unknown,
				format!("the reverse name of {ip} could not be read now"),
			),
		};
		worst = match (worst, level) {
			(Level::Fail, _) | (_, Level::Fail) => Level::Fail,
			(Level::Unknown, _) | (_, Level::Unknown) => Level::Unknown,
			_ => Level::Pass,
		};
		lines.push(text);
	}
	item("ptr", worst, lines.join("; "))
}
