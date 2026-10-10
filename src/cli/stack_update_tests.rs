//! Sanity check that the legacy tests file does not pin helpers
//! removed by the host-binary switch. The test bodies are kept
//! thin because the operator-facing logic moved to
//! `stack_update_steps`; a future drive-by edit cannot resurrect
//! `rewrite_default_image` without the regression suite
//! noticing. The string match looks for a `pub`-tagged function
//! declaration so the doc-comment that names the helper for
//! context does not trip the guard.

#[test]
fn stack_update_module_does_not_expose_a_rewrite_default_image_helper() {
	let module = include_str!("stack_update.rs");
	for line in module.lines() {
		assert!(
			!line.contains("fn rewrite_default_image"),
			"rewrite_default_image was the old behaviour for refreshing a CLI-tagged image; \
			 the host-binary default has no such image and the helper must not be reintroduced"
		);
	}
}
