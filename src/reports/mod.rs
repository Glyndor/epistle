//! Bounded decompression of report attachments.
//!
//! This module is the bomb gate for the report ingest path. The DMARC
//! aggregate and TLS-RPT reports we receive live as gzip or zip
//! attachments, neither of which `flate2` reads against a hard cap on its
//! own, so the inflation lives in one place and is the one place that
//! enforces [`MAX_COMPRESSED`] on the way in and [`MAX_DECOMPRESSED`] on
//! the way out.
//!
//! The rest of the ingest path can stay simple: it measures the
//! base64-decoded part against `MAX_COMPRESSED` before calling in here.

mod decompress;

pub use decompress::{Encoding, MAX_COMPRESSED, MAX_DECOMPRESSED, ReportError, inflate_attachment};
