//! One request to the real default authority. It needs the network, so it only
//! runs when asked for with `cargo test -- --ignored`.

use super::*;
use crate::evidence::record::sha256;
use crate::evidence::tsa::settings::Settings;

#[tokio::test]
#[ignore = "asks the real default timestamp authority over the network"]
async fn the_default_authority_stamps_a_digest_and_the_token_verifies_offline() {
	let digest =
		sha256(format!("epistle live check {:?}", std::time::SystemTime::now()).as_bytes());
	let settings = Settings::default();
	let obtained = obtain(&settings.authorities, &digest)
		.await
		.expect("the default authority answers with a token that verifies");
	assert_eq!(obtained.url, settings.authorities[0].url);
	let anchors = settings.authorities[0].anchor_hashes();
	// The same bytes verify again with no network and no nonce, which is what
	// `epistle evidence check` does with a bundle.
	let again = crate::evidence::tsa::verify::verify(&obtained.response, &digest, None, &anchors)
		.expect("the stored token verifies offline");
	assert_eq!(again.gen_time, obtained.stamp.gen_time);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	assert!(
		now.abs_diff(obtained.stamp.gen_time) < 300,
		"the stamped time is the current time"
	);
}
