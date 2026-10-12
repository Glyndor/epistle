//! What the API exposes about an account.

/// What the API exposes about an account: never credentials.
#[derive(Clone, serde::Serialize)]
pub struct AccountView {
	pub name: String,
	/// The person's name, as given; `null` when unset.
	pub display_name: Option<String>,
	pub addresses: Vec<String>,
	/// Whether the account is API-managed (deletable) or from the config.
	pub dynamic: bool,
}
