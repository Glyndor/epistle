//! Trace and authentication headers stamped onto accepted mail.

mod auth_results;
mod block;
mod field;
mod limits;
mod received;
mod rewrite;
mod strip;
mod submission;

#[cfg(test)]
use std::time::SystemTime;

pub(crate) use auth_results::{format_auth_results, spf_domain};
use block::header_block_end;
pub use block::{header_values, inject_spam_headers, prepend_header_block};
use field::{field_name, same_name};
pub(crate) use field::{name_start, split_field, split_field_from};
pub(crate) use limits::{MAX_HEADER_FIELDS, line_error_reply, refuse_padded_headers};
#[cfg(test)]
use received::received_protocol;
pub(crate) use received::{RECEIVED_HOP_LIMIT, received_header, received_hop_count};
use rewrite::{rewrite_header_block, rewrite_header_block_in_place};
pub use strip::{
	keep_first_of_each_in_place, strip_headers, strip_headers_in_place,
	strip_headers_with_namespace,
};
pub use submission::{
	ensure_submission_headers, ensure_submission_headers_in_place, strip_bcc, strip_bcc_in_place,
};

#[cfg(test)]
mod tests;
