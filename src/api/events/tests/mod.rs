//! Tests for the admin event stream, in process through the whole router:
//! who may open it, what a confined key is told, the caps, resuming, a
//! reader that falls behind, a credential that stops holding, and that no
//! event says more than which topic changed.

mod access;
mod base;
mod caps;
mod content;
mod lag;
mod resume;
mod revoke;
mod sampling;
mod scope;
