//! Cross-cutting helpers shared across modules.

pub mod address;
pub mod address_reason;
pub mod constant_time;
pub mod encoded_word;
pub mod header;
pub mod mailbox_path;
pub mod mutf7;
pub mod path_component;
pub mod path_containment;

pub(crate) mod fs_walk;
