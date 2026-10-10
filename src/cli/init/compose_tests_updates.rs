use super::{default_image, render, stack_answers};

#[test]
fn default_image_pins_the_full_cli_release() {
	assert_eq!(
		default_image(),
		format!("ghcr.io/glyndor/epistle:{}", env!("CARGO_PKG_VERSION")),
		"default mail image must use the full CLI release"
	);
}

#[test]
fn compose_records_whether_the_answers_set_an_operator_image() {
	for image in [None, Some("ghcr.io/glyndor/epistle:0.7.1".to_owned())] {
		let mut answers = stack_answers();
		answers.image = image;
		assert_eq!(
			render(&answers, true)["x-epistle-managed-image"],
			answers.image.is_none(),
			"compose must preserve image ownership from the answers for later upgrades"
		);
	}
}
