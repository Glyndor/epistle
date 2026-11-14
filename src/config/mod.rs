//! Server configuration: loading, validation and secure defaults.
//!
//! The configuration is TOML. Every default is the most restrictive option:
//! listeners bind to localhost, TLS is required wherever a transport supports
//! it, and any validation error aborts loading (fail closed).
//!
//! The schema itself, every field the file may set, is in `schema`; the
//! error type is in `error`; the defaults for the fields a file leaves out
//! are in `defaults`; the format the log is written in is in `log_format`. The
//! remaining modules hold one section of the file each.

mod account;
mod acme;
mod alerts;
mod alias;
mod antispam;
mod api;
mod arc;
mod attachments;
mod auth;
mod clip;
mod database;
mod debug;
mod defaults;
mod dkim;
mod dns;
mod dns_publish;
mod domain_role;
mod env;
mod error;
mod ldap;
mod listener;
mod load;
mod log_format;
mod mta_sts;
mod oauth;
mod oauth_pair;
mod otel;
mod permissions;
mod privileges;
mod queue;
mod read;
mod scanner;
mod schema;
mod srs;
mod storage;
mod tenant;
mod tls;
mod transport;
mod validate;
mod validate_limits;
mod webhook;

pub(crate) use alias::usable_list_id;
pub(crate) use validate::validate_addresses::{
	embedded_ipv4, non_global_ipv4_reason, non_global_ipv6_reason,
};
pub(crate) use validate::validate_dns_name;

pub use account::Account;
pub use acme::{Acme, AcmeChallenge};
pub use alerts::{Alert, AlertOp};
pub use alias::Alias;
pub use antispam::{Llm, SubjectPass};
pub use api::Api;
pub use arc::Arc;
pub use attachments::{
	AttachmentMode, Attachments, ContentAction, MAX_EXTENSION_LEN, MAX_EXTENSIONS,
	normalise_extension, valid_extension,
};
pub use auth::Auth;
pub use database::{Database, DatabaseTls};
pub use dkim::{DKIM_RSA_REQUIRED_FROM, Dkim, DkimDomain};
pub use dns::{Dns, DnsProviders};
pub(crate) use dns::{SUPPORTED_PROVIDERS, is_supported_provider};
pub use dns_publish::{DEFAULT_INTERVAL_SECS as DNS_PUBLISH_DEFAULT_INTERVAL_SECS, DnsPublish};
pub use error::ConfigError;
pub use ldap::Ldap;
pub use listener::{Listener, ListenerKind, Protocol};
pub use log_format::LogFormat;
pub use mta_sts::{MtaSts, MtaStsMode};
pub use oauth::Oauth;
pub use otel::Otel;
pub use privileges::Privileges;
pub use queue::{OutboundTls, Queue};
pub use scanner::{Antispam, ClamdOnError, ClamdOnFound};
pub use schema::Config;
pub use srs::SrsDomain;
pub use storage::{BlobBackendConfig, S3BlobConfig, Storage};
pub use tenant::Tenant;
pub use tls::Tls;
pub use transport::{Transport, TransportKind, select as select_transport};
pub use webhook::Webhook;

#[cfg(test)]
mod tests;

mod legacy_values;
mod normalize;
mod parse;
