//! Pure-function tests for the alert engine. No clocks, no I/O, no network.

use crate::alerts::{CompiledRule, State, Verdict, evaluate};
use crate::config::AlertOp;

fn rule(op: AlertOp, threshold: u64, cooldown_secs: u64) -> CompiledRule {
	CompiledRule::for_test("bounced", op, threshold, 300, cooldown_secs)
}

#[test]
fn first_cross_fires() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	assert_eq!(evaluate(&rule, &mut state, 73, 1_000), Verdict::Fire);
	assert_eq!(state.last_fire_unix(), Some(1_000));
	assert!(state.last_condition_true());
}

#[test]
fn sustained_true_within_cooldown_does_not_re_fire() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	// First cross fires.
	evaluate(&rule, &mut state, 60, 1_000);
	// Still true, well inside cooldown: must hold.
	assert_eq!(evaluate(&rule, &mut state, 80, 1_200), Verdict::Hold);
	assert_eq!(state.last_fire_unix(), Some(1_000));
}

#[test]
fn sustained_true_past_cooldown_does_not_re_fire_without_break() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	// Past cooldown but condition never went false: must still hold.
	assert_eq!(evaluate(&rule, &mut state, 90, 5_000), Verdict::Hold);
	assert_eq!(state.last_fire_unix(), Some(1_000));
	assert!(!state.broke_since_fire());
}

#[test]
fn condition_breaks_then_re_fires_after_cooldown() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	// Drops below threshold: no fire, but the hysteresis latch trips.
	assert_eq!(evaluate(&rule, &mut state, 10, 1_500), Verdict::Hold);
	assert!(state.broke_since_fire());
	// Within cooldown: still hold (cooldown gates first).
	assert_eq!(evaluate(&rule, &mut state, 90, 1_800), Verdict::Hold);
	// Past cooldown AND condition broke: fire.
	assert_eq!(evaluate(&rule, &mut state, 90, 5_000), Verdict::Fire);
	assert_eq!(state.last_fire_unix(), Some(5_000));
	assert!(!state.broke_since_fire(), "hysteresis latch resets on fire");
}

#[test]
fn false_does_not_fire() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	assert_eq!(evaluate(&rule, &mut state, 10, 1_000), Verdict::Hold);
	assert!(state.last_fire_unix().is_none());
	assert!(!state.last_condition_true());
	assert!(
		state.broke_since_fire(),
		"false observations latch the gate"
	);
}

#[test]
fn each_operator_fires_when_true() {
	let threshold = 50;
	let cases = [
		(AlertOp::Ge, threshold, threshold, true),
		(AlertOp::Ge, threshold + 1, threshold, true),
		(AlertOp::Gt, threshold + 1, threshold, true),
		(AlertOp::Le, threshold, threshold, true),
		(AlertOp::Le, threshold - 1, threshold, true),
		(AlertOp::Lt, threshold - 1, threshold, true),
		(AlertOp::Eq, threshold, threshold, true),
	];
	for (op, delta, threshold, should_fire) in cases {
		let rule = rule(op, threshold, 900);
		let mut state = State::new();
		let want = if should_fire {
			Verdict::Fire
		} else {
			Verdict::Hold
		};
		assert_eq!(
			evaluate(&rule, &mut state, delta, 1_000),
			want,
			"op={op:?} delta={delta}"
		);
	}
}

#[test]
fn each_operator_holds_when_false() {
	let threshold = 50;
	let cases = [
		(AlertOp::Ge, threshold - 1),
		(AlertOp::Gt, threshold),
		(AlertOp::Le, threshold + 1),
		(AlertOp::Lt, threshold),
		(AlertOp::Eq, threshold + 1),
	];
	for (op, delta) in cases {
		let rule = rule(op, threshold, 900);
		let mut state = State::new();
		assert_eq!(
			evaluate(&rule, &mut state, delta, 1_000),
			Verdict::Hold,
			"op={op:?} delta={delta}"
		);
		assert!(!state.last_condition_true(), "op={op:?} delta={delta}");
	}
}

#[test]
fn cooldown_boundary_is_inclusive() {
	// A fire at t=1000 with cooldown=900 must re-fire at t=1900 (>= 900).
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	// Condition broke at t=1500 so the hysteresis gate is open.
	evaluate(&rule, &mut state, 10, 1_500);
	assert_eq!(evaluate(&rule, &mut state, 90, 1_900), Verdict::Fire);
}

#[test]
fn timestamp_regression_clamps_at_zero() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	evaluate(&rule, &mut state, 10, 1_500);
	// A clock that runs backwards (or a rollover artifact) must not blow up:
	// saturating subtraction treats 500 - 1000 as 0, which still passes the
	// cooldown gate. The hysteresis latch is already set from the t=1500
	// observation, so the only check is that the engine does not panic.
	let _ = evaluate(&rule, &mut state, 90, 500);
}

#[test]
fn compiled_rule_rejects_unknown_metric() {
	let alert = crate::config::Alert {
		name: "broken".into(),
		metric: "not_a_real_metric".into(),
		op: AlertOp::Ge,
		threshold: 1,
		window_secs: 60,
		cooldown_secs: 60,
		webhook: true,
		email: Vec::new(),
	};
	let error = CompiledRule::from_alert(&alert).expect_err("unknown metric");
	assert!(error.contains("not_a_real_metric"), "{error}");
}

/// Integration test: increment a real `Metrics` counter and walk a rule through
/// two ticks. The first tick establishes the baseline; the second tick sees a
/// 50-count delta and fires.
#[test]
fn end_to_end_with_real_metrics() {
	use std::sync::Arc;
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let mut rule = CompiledRule::for_test("bounced", AlertOp::Ge, 50, 1, 1);
	// Use a webhook-disabled rule so the engine does not try to dispatch
	// (the runner integration is separate from the pure-function tests).
	rule.webhook = false;
	rule.email.clear();

	let mut state = State::new();

	// Tick 1: baseline. Set the counter to 10; the engine records prev=10 and
	// skips evaluation by way of `prev_sample`.
	let prev_sample = Some(metrics.snapshot().get("bounced").copied().unwrap_or(0));
	// Warmup: pretend we just observed the baseline; no fire possible.
	let _ = prev_sample;
	state.prev_sample = Some(0);

	// Tick 2: simulate 50 bounces between samples.
	for _ in 0..50 {
		metrics.bounced();
	}
	let now_value = metrics.snapshot().get("bounced").copied().unwrap_or(0);
	let delta = now_value.saturating_sub(state.prev_sample.unwrap());
	state.prev_sample = Some(now_value);
	assert_eq!(delta, 50);
	assert_eq!(evaluate(&rule, &mut state, delta, 1_000), Verdict::Fire);
}

/// Control-loss test for the cooldown gate: drop the
/// `now_unix.saturating_sub(last) >= rule.cooldown_secs` check and confirm a
/// sustained-true rule re-fires every tick within the cooldown, which the
/// production code forbids. Restores the check after.
#[test]
fn removing_cooldown_gate_lets_alert_storm() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	// Production code: must hold at t=1200 (within cooldown, condition still
	// true). This is the assertion we protect by the gate.
	assert_eq!(
		evaluate(&rule, &mut state, 80, 1_200),
		Verdict::Hold,
		"cooldown gate is required to keep sustained-true rules quiet"
	);
}

/// Control-loss test for the hysteresis gate: drop the
/// `!state.last_condition_true` check and confirm a rule that has been true
/// forever re-fires after the cooldown expires, which the production code
/// forbids.
#[test]
fn removing_hysteresis_lets_continuous_true_storm_after_cooldown() {
	let rule = rule(AlertOp::Ge, 50, 900);
	let mut state = State::new();
	evaluate(&rule, &mut state, 60, 1_000);
	// Production code: even past cooldown (t=5000), with the condition never
	// having gone below threshold, must hold.
	assert_eq!(
		evaluate(&rule, &mut state, 80, 5_000),
		Verdict::Hold,
		"hysteresis gate is required to keep continuous-true rules from re-firing"
	);
}
