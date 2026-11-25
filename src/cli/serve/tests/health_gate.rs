//! The limit of the health runs is the server's: its gate is made once,
//! before the listeners are looked at, and every API listener is given it.

#[test]
fn the_health_gate_is_made_once_before_the_listeners_and_handed_to_each() {
	let source = include_str!("../mod.rs");
	let production = source.split("#[cfg(test)]").next().expect("source");
	assert_eq!(production.matches("HealthGate::new()").count(), 1);
	let made = production.find("HealthGate::new()").expect("made");
	let loop_at = production
		.find("for listener_config in &config.listeners")
		.expect("the listener loop");
	assert!(
		made < loop_at,
		"the gate is made inside the loop of listeners"
	);
	assert!(production.contains("health_gate: &health_gate"));
	let listener = include_str!("../api_listener.rs");
	assert!(listener.contains("with_health_gate(health_gate.clone())"));
}
