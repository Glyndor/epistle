//! The provider the rotator writes through, and how it is picked up again:
//! the live provider of [`crate::dns::provider::live`], built again at the
//! start of every cycle when a source is set.

pub(super) use crate::dns::provider::live::LiveProvider;
pub use crate::dns::provider::live::ProviderSource;
