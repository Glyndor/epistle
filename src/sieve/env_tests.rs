//! The budget of one run.

use super::*;

#[test]
fn a_value_is_cut_to_the_limit_at_a_character_boundary() {
	let mut env = Env::default();
	env.set("a", &"x".repeat(MAX_VAR_BYTES + 100));
	assert_eq!(env.get("a").map(str::len), Some(MAX_VAR_BYTES));
	// A two-octet character straddling the limit is dropped whole.
	let text = format!("{}\u{e9}", "x".repeat(MAX_VAR_BYTES - 1));
	env.set("b", &text);
	assert_eq!(env.get("b").map(str::len), Some(MAX_VAR_BYTES - 1));
}

#[test]
fn all_variables_together_stay_under_the_total() {
	let mut env = Env::default();
	let full = "x".repeat(MAX_VAR_BYTES);
	for n in 0..100 {
		env.set(&format!("v{n}"), &full);
	}
	assert!(
		env.var_bytes() <= MAX_VARS_TOTAL_BYTES,
		"{}",
		env.var_bytes()
	);
	assert_eq!(
		env.var_bytes(),
		MAX_VARS_TOTAL_BYTES,
		"filled to the limit and no further"
	);
	// Rewriting a variable it already holds is not refused for the total.
	env.set("v0", "short");
	assert_eq!(env.get("v0"), Some("short"));
}

#[test]
fn the_number_and_the_name_of_variables_are_bounded() {
	let mut env = Env::default();
	for n in 0..MAX_VARS + 50 {
		env.set(&format!("n{n}"), "1");
	}
	assert_eq!(env.get(&format!("n{}", MAX_VARS - 1)), Some("1"));
	assert_eq!(env.get(&format!("n{MAX_VARS}")), None);
	env.set(&"n".repeat(MAX_VAR_NAME + 1), "1");
	assert_eq!(env.get(&"n".repeat(MAX_VAR_NAME + 1)), None);
}

#[test]
fn an_expansion_is_cut_but_what_the_script_wrote_is_not() {
	let mut env = Env::default();
	env.set("a", &"y".repeat(MAX_VAR_BYTES));
	let template = "${a}".repeat(2000);
	assert_eq!(env.expand(&template).len(), template.len());
	let short = "${a}${a}";
	assert_eq!(env.expand(short).len(), MAX_VAR_BYTES);
	let literal = "z".repeat(10 * MAX_VAR_BYTES);
	assert_eq!(env.expand(&literal), literal);
}

#[test]
fn steps_and_work_run_out() {
	let mut env = Env::default();
	for _ in 0..MAX_STEPS {
		assert!(env.step());
	}
	assert!(!env.step());
	assert!(env.exhausted());
	let mut env = Env::default();
	assert!(env.charge(MAX_WORK));
	assert!(!env.charge(1));
	assert!(env.exhausted());
}
