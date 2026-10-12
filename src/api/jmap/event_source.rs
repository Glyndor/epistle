//! JMAP push over an event source (RFC 8620 §7.3).
//!
//! `GET /jmap/eventsource?types=..&closeafter=..&ping=..` answers a
//! `text/event-stream` that stays open and carries a `state` event, whose data
//! is a `StateChange` (RFC 8620 §7.1), whenever the state of a type the client
//! asked for moves in an account the credential reaches. Changes are read from
//! each account's change journal ([`crate::imap::changelog`]), which IMAP,
//! POP3, SMTP delivery and JMAP all write, so a change made over any protocol
//! is pushed, not only one made over JMAP. The journal is polled every
//! [`POLL`]; nothing has to call into this module when mail changes.
//!
//! - `types`: `*` or a comma-separated list. `Email`, `Mailbox` and `Thread`
//!   have states; any other name is accepted and never pushed.
//! - `closeafter`: `state` ends the response after the first `state` event,
//!   `no` keeps it open.
//! - `ping`: seconds between `ping` events when nothing else was sent, `0` for
//!   none. Clamped to [`MIN_PING`]..=[`MAX_PING`]; the `ping` event's
//!   `interval` reports the value in use.
//!
//! The stream is long-lived, so the credential is checked again on every
//! poll the same way the WebSocket checks it on every frame
//! ([`super::websocket::credential_still_valid`]), plus the `read` scope the
//! connection needed. Once either fails the stream ends.
//!
//! Event ids (and so `Last-Event-ID` replay) are not sent: a reconnecting
//! client catches up with `/changes` from the states it holds.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::Principal;
use super::state::{Kind, account_root};
use crate::api::api_keys::Scope;
use crate::api::state::{ApiState, MatchedAuth};

/// How often the change journals are read.
pub(crate) const POLL: Duration = Duration::from_secs(1);
/// The shortest `ping` interval honoured, in seconds.
pub(crate) const MIN_PING: u64 = 1;
/// The longest `ping` interval honoured, in seconds (RFC 8620 §7.3 lets a
/// server cap it, at no less than 300).
pub(crate) const MAX_PING: u64 = 300;
/// Streams one caller may hold open at once. Each polls the journals every
/// second, so the cap bounds what one credential can cost the server.
pub(crate) const MAX_STREAMS_PER_CALLER: usize = 4;

/// One open stream counted against its caller; released when the stream is
/// dropped, however it ends.
struct StreamSlot {
	streams: std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>,
	owner: String,
}

impl StreamSlot {
	fn take(state: &ApiState, owner: String) -> Option<Self> {
		let streams = state.event_streams();
		{
			let mut open = streams.lock().unwrap_or_else(|p| p.into_inner());
			let count = open.entry(owner.clone()).or_insert(0);
			if *count >= MAX_STREAMS_PER_CALLER {
				return None;
			}
			*count += 1;
		}
		Some(Self { streams, owner })
	}
}

impl Drop for StreamSlot {
	fn drop(&mut self) {
		let mut open = self.streams.lock().unwrap_or_else(|p| p.into_inner());
		if let Some(count) = open.get_mut(&self.owner) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				open.remove(&self.owner);
			}
		}
	}
}

/// The data types with a state, and the kind that encodes each one's state.
const TYPES: [(&str, Kind); 3] = [
	("Email", Kind::Email),
	("Mailbox", Kind::Mailbox),
	("Thread", Kind::Thread),
];

/// `GET /jmap/eventsource` (RFC 8620 §7.3). The bearer middleware already
/// required the `read` scope for this `GET`.
pub async fn event_source(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Query(params): Query<HashMap<String, String>>,
) -> Response {
	let options = match Options::parse(&params) {
		Ok(options) => options,
		Err(detail) => {
			return super::jmap_error(StatusCode::BAD_REQUEST, "invalidArguments", detail);
		}
	};
	let principal = Principal::for_token(&state, &auth);
	let Some(owner) = super::push_subscription::owner_of(&state, &principal) else {
		return super::jmap_error(StatusCode::FORBIDDEN, "forbidden", "no caller identity");
	};
	let Some(slot) = StreamSlot::take(&state, owner) else {
		return super::jmap_error(
			StatusCode::TOO_MANY_REQUESTS,
			"limit",
			"too many open event-source streams for this credential",
		);
	};
	let known = positions(&state, &principal);
	let opened = tokio::time::Instant::now();
	let mut poll = tokio::time::interval_at(opened + POLL, POLL);
	poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	Sse::new(Events {
		state,
		auth,
		principal,
		options,
		known,
		poll,
		quiet_since: opened,
		done: false,
		_slot: slot,
	})
	.into_response()
}

/// The parsed query.
struct Options {
	/// The state types asked for, from [`TYPES`].
	types: Vec<(&'static str, Kind)>,
	close_after_state: bool,
	/// The ping interval in use, `None` for no pings.
	ping: Option<u64>,
}

impl Options {
	fn parse(params: &HashMap<String, String>) -> Result<Self, &'static str> {
		let types = match params.get("types").map(String::as_str) {
			None | Some("*") => TYPES.to_vec(),
			Some(list) => {
				let names: Vec<&str> = list.split(',').collect();
				if names.iter().any(|name| name.is_empty()) {
					return Err("types must be * or a comma-separated list of type names");
				}
				TYPES
					.into_iter()
					.filter(|(name, _)| names.contains(name))
					.collect()
			}
		};
		let close_after_state = match params.get("closeafter").map(String::as_str) {
			None | Some("no") => false,
			Some("state") => true,
			Some(_) => return Err("closeafter must be state or no"),
		};
		let ping = match params.get("ping") {
			None => 0,
			Some(value) => value
				.parse::<u64>()
				.map_err(|_| "ping must be a whole number of seconds")?,
		};
		Ok(Self {
			types,
			close_after_state,
			ping: (ping > 0).then(|| ping.clamp(MIN_PING, MAX_PING)),
		})
	}
}

/// The journal position (epoch, position) of every account `principal`
/// reaches. An account whose journal cannot be read is left out until it can.
fn positions(state: &ApiState, principal: &Principal) -> HashMap<String, (u64, u64)> {
	principal
		.admissible_accounts(&state.accounts())
		.into_iter()
		.filter_map(|account| {
			let root = account_root(state.data_dir(), &account.name)?;
			let position = crate::imap::changelog::current(&root).ok()?;
			Some((account.name.clone(), (position.epoch, position.current)))
		})
		.collect()
}

/// The event stream: on every [`POLL`] tick, re-check the credential, then
/// emit a `state` event for the accounts whose journal moved, or a `ping`
/// when one is due.
struct Events {
	state: ApiState,
	auth: MatchedAuth,
	principal: Principal,
	options: Options,
	known: HashMap<String, (u64, u64)>,
	poll: tokio::time::Interval,
	/// When the last event was sent (or the stream opened).
	quiet_since: tokio::time::Instant,
	done: bool,
	/// Released when the stream is dropped.
	_slot: StreamSlot,
}

impl Events {
	fn still_allowed(&self) -> bool {
		super::websocket::credential_still_valid(&self.state, &self.auth, &self.principal)
			&& self
				.state
				.require_scope_for_principal(&self.principal, Scope::Read)
				.is_ok()
	}

	/// The `StateChange` for every account whose position moved since the
	/// last poll, `None` when none did or no type was asked for. Accounts
	/// that appeared since are taken as they are; ones gone are dropped.
	fn state_change(&mut self) -> Option<Value> {
		let now = positions(&self.state, &self.principal);
		let mut changed = Map::new();
		for (account, &(epoch, position)) in &now {
			if self.known.get(account) == Some(&(epoch, position))
				|| !self.known.contains_key(account)
			{
				continue;
			}
			let states: Map<String, Value> = self
				.options
				.types
				.iter()
				.map(|&(name, kind)| {
					let state = super::state::State {
						kind,
						epoch,
						position,
					};
					(name.to_string(), json!(state.encode()))
				})
				.collect();
			if !states.is_empty() {
				changed.insert(account.clone(), Value::Object(states));
			}
		}
		self.known = now;
		(!changed.is_empty()).then(|| json!({ "@type": "StateChange", "changed": changed }))
	}
}

impl futures_core::Stream for Events {
	type Item = Result<Event, std::convert::Infallible>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.done {
			return Poll::Ready(None);
		}
		while self.poll.poll_tick(cx).is_ready() {
			if !self.still_allowed() {
				self.done = true;
				return Poll::Ready(None);
			}
			if let Some(change) = self.state_change() {
				self.quiet_since = tokio::time::Instant::now();
				self.done = self.options.close_after_state;
				let event = Event::default().event("state").data(change.to_string());
				return Poll::Ready(Some(Ok(event)));
			}
			if let Some(interval) = self.options.ping
				&& self.quiet_since.elapsed() >= Duration::from_secs(interval)
			{
				self.quiet_since = tokio::time::Instant::now();
				let data = json!({ "interval": interval }).to_string();
				return Poll::Ready(Some(Ok(Event::default().event("ping").data(data))));
			}
		}
		Poll::Pending
	}
}
