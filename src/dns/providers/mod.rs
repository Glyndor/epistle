//! One module per DNS provider epistle can publish records through. Each
//! provider lives in its own directory with its tests; what they share (the
//! `DnsProvider` trait, record types, matching rules) is in
//! [`crate::dns::provider`].

pub mod bunny;
pub mod cloudflare;
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod gcloud;
pub mod godaddy;
pub mod namecheap;
pub mod ovh;
pub mod porkbun;
pub mod rfc2136;
pub mod route53;
pub mod spaceship;
