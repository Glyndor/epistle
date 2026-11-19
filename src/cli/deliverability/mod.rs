//! `epistle deliverability test`: send one message from a hosted account to
//! an address the operator names, and report what became of it.
//!
//! The message is DKIM-signed with the server's own key and queued in the
//! spool, where the running server delivers it from its real sending
//! address. The command then reads the delivery log for the result. Nothing
//! in the report is a secret: no key, password or hash is read into it.
//!
//! The destination is always the operator's: the command never picks one,
//! and refuses one on a domain this server hosts. It refuses a sending
//! domain the server does not host, runs only with `--yes`, and allows one
//! run per minute per server.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use serde::Serialize;
use uuid::Uuid;

use super::style;
use crate::cli::term::sanitize;
use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::dkim::PerDomainSigner;
use crate::storage::{DeliveryLog, FsSpool, MessageCrypto, StoreOptions};

mod delivery;
mod guard;
mod message;
mod plan;
#[cfg(test)]
mod tests;

use delivery::Delivery;
use plan::{Plan, Refusal};

/// The longest the command waits for the result.
const MAX_WAIT_SECS: u64 = 600;
/// How often it looks at the delivery log while it waits.
const POLL: Duration = Duration::from_secs(2);

/// `epistle deliverability` actions.
#[derive(Debug, Subcommand)]
pub enum DeliverabilityCli {
	/// Send one test message and report what became of it.
	///
	/// Sends one message from a hosted account to an address you name, such as
	/// the one a deliverability test service gives you, and prints the delivery
	/// result with the remote's answer in plain language. Needs `--yes`,
	/// allows one run per minute per server, and refuses a sending domain this
	/// server does not host. The destination must be outside this server.
	/// Exits 1 when the message is refused for good.
	Test(TestArgs),
}

/// `epistle deliverability test` arguments.
#[derive(Debug, Args)]
pub struct TestArgs {
	/// The account that sends the message.
	#[arg(long, value_name = "NAME")]
	pub account: String,
	/// The address to send to, outside this server.
	#[arg(long, value_name = "ADDRESS")]
	pub to: String,
	/// Send it. Without this the command shows what it would send and stops.
	#[arg(long, short = 'y')]
	pub yes: bool,
	/// Seconds to wait for the delivery result, up to 600. The running
	/// server scans its queue every 30 seconds.
	#[arg(long, value_name = "SECONDS", default_value_t = 90)]
	pub wait: u64,
	/// Print the result as one JSON object on stdout.
	#[arg(long)]
	pub json: bool,
}

/// Everything one run reads from outside itself, so a test can stand in for
/// each.
pub(super) struct Env<'a> {
	pub config: &'a Config,
	pub store: &'a AccountStore,
	pub signer: Option<&'a PerDomainSigner>,
	pub crypto: MessageCrypto,
	/// The time to use; `None` reads the clock each time it is needed, which
	/// a test replaces with a fixed value.
	pub now: Option<u64>,
	pub poll: Duration,
}

impl Env<'_> {
	/// The time now, in epoch seconds.
	fn clock(&self) -> u64 {
		self.now.unwrap_or_else(crate::cli::queue::now_epoch)
	}
}

/// Run the action for the configuration at `config_path`.
pub(super) fn run(config_path: &Path, action: DeliverabilityCli) -> ExitCode {
	let DeliverabilityCli::Test(args) = action;
	if args.wait > MAX_WAIT_SECS {
		return crate::cli::exit::refused(format_args!(
			"--wait is at most {MAX_WAIT_SECS} seconds"
		));
	}
	let store = match crate::cli::account::prepare_show(config_path, &args.account) {
		Ok(store) => store,
		Err(code) => return code,
	};
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return ExitCode::FAILURE;
		}
	};
	let crypto = match crate::cli::util::message_crypto(&config) {
		Ok(crypto) => crypto,
		Err(code) => return code,
	};
	let signer = match message::load_signer(&config) {
		Ok(signer) => signer,
		Err(error) => {
			style::error(format_args!("cannot load the DKIM key: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	else {
		style::error("cannot start the runtime");
		return ExitCode::FAILURE;
	};
	let env = Env {
		config: &config,
		store: &store,
		signer: signer.as_ref(),
		crypto,
		now: None,
		poll: POLL,
	};
	runtime.block_on(execute(&env, &args, &mut std::io::stdout().lock()))
}

fn refused(refusal: Refusal) -> ExitCode {
	style::error(refusal.message);
	ExitCode::from(refusal.code)
}

/// The run itself: every refusal comes before the first write, and the rate
/// record is written only after the message is queued.
pub(super) async fn execute(env: &Env<'_>, args: &TestArgs, out: &mut impl Write) -> ExitCode {
	let plan = match plan::resolve(env.config, env.store, &args.account, &args.to) {
		Ok(plan) => plan,
		Err(refusal) => return refused(refusal),
	};
	if !args.yes {
		let _ = if args.json {
			write_plan_json(&plan, out)
		} else {
			write_plan(&plan, out)
		};
		return crate::cli::exit::refused("--yes is required to send the message");
	}
	// The clock is read once the lock is held: a run that waited for another
	// one is judged, and its message dated, by when it got the lock.
	let guard = match guard::Guard::lock(&env.config.data_dir)
		.and_then(|guard| guard.checked(env.clock()))
	{
		Ok(guard) => guard,
		Err(refusal) => return refused(refusal),
	};
	let id = Uuid::now_v7();
	let built = message::build(&plan, &env.config.hostname, env.clock(), id, env.signer);
	if let Err(error) = queue(env, &plan, &built.data, id) {
		style::error(format_args!("cannot queue the message: {error}"));
		return ExitCode::FAILURE;
	}
	if let Err(error) = guard.record(env.clock()) {
		style::warn(format_args!(
			"the message is queued, but the rate bound could not be recorded: {error}"
		));
	}
	let log_days = env.config.delivery_log_days();
	let log = DeliveryLog::open(&env.config.data_dir, log_days);
	let delivery =
		delivery::await_result(&log, log_days, id, Duration::from_secs(args.wait), env.poll).await;
	let report = Report::new(
		&plan,
		id,
		signing_of(env.signer.is_some(), built.signed),
		delivery,
	);
	let written = if args.json {
		serde_json::to_writer(&mut *out, &report)
			.map_err(std::io::Error::other)
			.and_then(|()| writeln!(out))
	} else {
		report.write_text(out)
	};
	if let Err(error) = written {
		style::error(format_args!("writing the report: {error}"));
		return ExitCode::FAILURE;
	}
	if report.failed() {
		ExitCode::FAILURE
	} else {
		ExitCode::SUCCESS
	}
}

/// How the message was signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Signing {
	/// With the server's DKIM key.
	Signed,
	/// No `[dkim]` key is configured for the sending domain.
	NoKey,
	/// A key is configured, but the signature could not be produced.
	Failed,
}

impl Signing {
	fn sentence(self) -> &'static str {
		match self {
			Self::Signed => "yes, with the server's DKIM key",
			Self::NoKey => "no: no DKIM key is configured for the sending domain",
			Self::Failed => "no: a DKIM key is configured but the signature could not be produced",
		}
	}
}

/// What became of the signature, given whether the server has a signer.
fn signing_of(has_signer: bool, signed: bool) -> Signing {
	match (has_signer, signed) {
		(_, true) => Signing::Signed,
		(true, false) => Signing::Failed,
		(false, false) => Signing::NoKey,
	}
}

/// The whole result of one run.
#[derive(Debug, Serialize)]
struct Report {
	account: String,
	from: String,
	to: String,
	/// The queue id of the message, the one `epistle delivery show` takes.
	message: Uuid,
	/// Whether the message went out with the server's own DKIM signature.
	signing: Signing,
	delivery: Delivery,
}

impl Report {
	fn new(plan: &Plan, message: Uuid, signing: Signing, delivery: Delivery) -> Self {
		Self {
			account: plan.account.clone(),
			from: plan.from.clone(),
			to: plan.to.clone(),
			message,
			signing,
			delivery,
		}
	}

	/// The message was refused for good, or went out unsigned although a key
	/// is configured: the test then measures a message the receiver treats as
	/// unauthenticated, which is the case the command exists to catch.
	fn failed(&self) -> bool {
		self.delivery.is_failure() || self.signing == Signing::Failed
	}

	/// The report as text, every value that came from outside escaped.
	fn write_text(&self, out: &mut impl Write) -> std::io::Result<()> {
		writeln!(out, "account   {}", sanitize(&self.account))?;
		writeln!(out, "from      {}", sanitize(&self.from))?;
		writeln!(out, "to        {}", sanitize(&self.to))?;
		writeln!(out, "message   {}", self.message)?;
		writeln!(out, "signing   {}", self.signing.sentence())?;
		writeln!(out, "delivery  {}", self.delivery.state)?;
		if let Some(remote) = &self.delivery.remote {
			writeln!(out, "  remote   {remote}")?;
		}
		if let Some(reply) = &self.delivery.reply {
			writeln!(out, "  reply    {reply}")?;
		}
		writeln!(out, "  meaning  {}", self.delivery.explanation)?;
		writeln!(out, "{REPUTATION_NOTE}")
	}
}

/// The one thing a first test cannot say.
const REPUTATION_NOTE: &str = "A new address has no reputation yet, so what a first test shows says little about steady state; see `epistle warmup`.";

/// What a run without `--yes` shows with `--json`: one document, so a
/// consumer that parses stdout does not choke on the text.
fn write_plan_json(plan: &Plan, out: &mut impl Write) -> std::io::Result<()> {
	serde_json::to_writer(
		&mut *out,
		&serde_json::json!({
			"would_send": true,
			"account": plan.account,
			"from": plan.from,
			"to": plan.to,
		}),
	)
	.map_err(std::io::Error::other)?;
	writeln!(out)
}

/// What a run without `--yes` shows, and stops.
fn write_plan(plan: &Plan, out: &mut impl Write) -> std::io::Result<()> {
	writeln!(out, "would send one test message")?;
	writeln!(out, "account   {}", sanitize(&plan.account))?;
	writeln!(out, "from      {}", sanitize(&plan.from))?;
	writeln!(out, "to        {}", sanitize(&plan.to))?;
	writeln!(
		out,
		"It goes out through this server's own queue, DKIM-signed, from its sending address.\nOne test is allowed per minute per server. Run again with --yes to send it."
	)
}

/// Put the signed message in the spool under `id`, for the running server's
/// queue to deliver. It is owned by the sending domain's tenant and carries
/// the account, so the delivery log and any bounce find it.
fn queue(env: &Env<'_>, plan: &Plan, data: &[u8], id: Uuid) -> std::io::Result<()> {
	let spool = FsSpool::open_with_crypto(&env.config.data_dir, env.crypto.clone())?;
	let message = crate::smtp::session::AcceptedMessage {
		reverse_path: plan.from.clone(),
		recipients: vec![plan.to.clone()],
		data: data.to_vec(),
		..Default::default()
	};
	let extra = std::collections::BTreeMap::new();
	spool
		.store_with(
			&message,
			id,
			&StoreOptions {
				account: Some(&plan.account),
				extra: &extra,
				owner: Some(&plan.domain),
				class: crate::evidence::MailClass::Personal,
				evidence: None,
				retain_days: 0,
			},
		)
		.map(|_| ())
}
