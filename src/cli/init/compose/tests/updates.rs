use super::{render, stack_answers};

#[test]
fn compose_records_whether_the_answers_set_an_operator_image() {
	// `x-epistle-managed-image` carries the two-mode distinction
	// `stack update` reads on the next upgrade: the host-binary
	// default shape has `true`, the operator-image override has
	// `false`. The marker must reflect what the answers said so a
	// re-rendered compose file goes through the same update path
	// the original would have.
	for image in [None, Some("ghcr.io/glyndor/epistle:0.7.1".to_owned())] {
		let mut answers = stack_answers();
		answers.image = image;
		let rendered = render(&answers, true);
		// When the answers leave `image` unset, the rendered
		// compose is the distroless-base + host-binary shape and
		// the marker is `true`. When the answers set an image,
		// the operator owns the image and the marker is `false`.
		let expected = answers.image.is_none();
		assert_eq!(
			rendered["x-epistle-managed-image"], expected,
			"compose must reflect whether the answers set an operator image"
		);
	}
}
