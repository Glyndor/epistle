//! `epistle evidence policy show|set`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::evidence::PolicyCli;
use crate::evidence::MailClass;
use crate::evidence::ack::Operator;
use crate::evidence::chain::Chain;
use crate::evidence::policy::{self, Mode, Policy, Rule, Scope};
use crate::evidence::record::{Entry, Setting, bounded};

/// Run one policy action.
pub(super) fn run(root: &Path, action: PolicyCli, out: &mut impl Write) -> ExitCode {
	match action {
		PolicyCli::Show { json } => show(root, json, out),
		PolicyCli::Set {
			class,
			account,
			tenant,
			mode,
			days,
			json,
		} => {
			let class = match class.as_str() {
				"all" => None,
				other => match crate::evidence::class::parse_arg(other) {
					Ok(class) => Some(class),
					Err(error) => return super::exit::refused(error),
				},
			};
			let scope = match (account, tenant) {
				(Some(account), _) => Scope::Account(account.to_ascii_lowercase()),
				(None, Some(tenant)) => Scope::Tenant(tenant),
				(None, None) => Scope::Server,
			};
			let days = if mode == Mode::Off { 0 } else { days };
			set(
				root,
				Rule {
					scope,
					class,
					mode,
					days,
				},
				json,
				out,
			)
		}
	}
}

fn mode_name(mode: Mode) -> &'static str {
	match mode {
		Mode::Off => "off",
		Mode::Metadata => "metadata",
		Mode::Full => "full",
	}
}

fn describe(rule: &Rule) -> String {
	let scope = match &rule.scope {
		Scope::Server => "server".to_string(),
		Scope::Tenant(name) => format!("tenant {name}"),
		Scope::Account(name) => format!("account {name}"),
	};
	let class = rule
		.class
		.map_or("all".to_string(), |class| class.to_string());
	format!(
		"{scope} class={class} mode={} days={}",
		mode_name(rule.mode),
		rule.days
	)
}

fn show(root: &Path, as_json: bool, out: &mut impl Write) -> ExitCode {
	let policy = match policy::load(root) {
		Ok(policy) => policy,
		Err(error) => {
			super::style::error(format_args!("evidence policy unreadable: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	if as_json {
		return super::evidence::json(
			out,
			&json!({
				"rules": policy.rules,
				"defaults": {
					"transactional": { "mode": "metadata", "days": policy::DEFAULT_DAYS },
					"marketing": { "mode": "off" },
					"personal": { "mode": "off" },
				},
			}),
		);
	}
	let _ = writeln!(
		out,
		"defaults: transactional metadata {} days; marketing and personal off",
		policy::DEFAULT_DAYS
	);
	for rule in &policy.rules {
		let _ = writeln!(out, "{}", super::term::sanitize(&describe(rule)));
	}
	ExitCode::SUCCESS
}

fn set(root: &Path, rule: Rule, as_json: bool, out: &mut impl Write) -> ExitCode {
	if rule.mode == Mode::Off && rule.class == Some(MailClass::Transactional) {
		return super::exit::refused("transactional mail always keeps evidence");
	}
	let operator = match Operator::current(root) {
		Ok(operator) => operator,
		Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
			return super::exit::refused(error);
		}
		Err(error) => {
			super::style::error(format_args!("evidence: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	let before = match policy::load(root) {
		Ok(policy) => policy,
		Err(error) => {
			super::style::error(format_args!(
				"evidence policy unreadable ({}): fix or remove policy.json first",
				error.kind()
			));
			return ExitCode::FAILURE;
		}
	};
	let mut after: Policy = before.clone();
	after.set(rule.clone());
	if let Err(why) = after.validate() {
		return super::exit::refused(why);
	}
	let described = describe(&rule);
	if let Err(error) = policy::save(root, &after) {
		super::style::error(format_args!("saving the evidence policy: {}", error.kind()));
		return ExitCode::FAILURE;
	}
	// A change the chain does not record is undone.
	let recorded = Chain::open(root).and_then(|chain| {
		chain.append(Entry::Setting(Setting {
			name: "retention".into(),
			value: bounded(&format!("{described} by {}", operator.as_str())),
		}))
	});
	if let Err(error) = recorded {
		let _ = policy::save(root, &before);
		super::style::error(format_args!(
			"recording the change in the evidence failed ({}); the policy is unchanged",
			error.kind()
		));
		return ExitCode::FAILURE;
	}
	if as_json {
		return super::evidence::json(out, &json!({ "rule": rule }));
	}
	let _ = writeln!(
		out,
		"set: {}\nthe server applies it at its next check (within five minutes)",
		super::term::sanitize(&described)
	);
	ExitCode::SUCCESS
}
