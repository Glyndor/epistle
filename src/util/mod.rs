//! Cross-cutting helpers shared across modules.

pub mod account_rule;
pub mod address;
pub mod address_reason;
pub mod blocking;
pub mod constant_time;
pub mod encoded_word;
pub mod header;
pub mod header_block;
pub mod label_rule;
pub mod mailbox_path;
pub mod mailto;
pub mod mutf7;
pub mod path_component;
pub mod path_containment;
pub mod validation;
pub mod warn_limited;

pub(crate) mod fs_walk;
