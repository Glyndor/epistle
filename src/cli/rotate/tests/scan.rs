//! The reader of the configuration sources finds a new secret field.

use super::source::secret_fields;

const SOURCE: &str = "\
pub struct Thing {
	/// A new secret.
	pub new_thing_secret: Option<String>,
	pub enabled: bool,
	pub retries: u32,
	pub name: String,
	pub(crate) api_token_file: Option<PathBuf>,
}

pub struct Other {
	pub signing_key: String,
}

fn outside() {
	let password = 1;
}
";

#[test]
fn it_finds_secret_looking_fields_by_struct() {
	assert_eq!(
		secret_fields(SOURCE),
		[
			"Thing.new_thing_secret",
			"Thing.api_token_file",
			"Other.signing_key"
		]
	);
}

#[test]
fn it_ignores_flags_counts_and_names_without_a_secret_word() {
	let source = "pub struct A {\n\tpub allow_private_keys: bool,\n\tpub token_ttl: u64,\n\tpub label: String,\n}\n";
	assert!(secret_fields(source).is_empty());
}
