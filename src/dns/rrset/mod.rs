//! The delegations of a zone, and the equality of the records at a name.
//!
//! An NS rrset at a name below the zone apex hands that name, and every
//! name under it, to other nameservers (a zone cut): whatever the zone
//! holds there is occluded, some providers refuse to store it, and
//! whatever was written there would never be served. The NS rrset at the
//! apex is not a cut: it names the servers of this very zone.
//!
//! `cuts` holds the delegations, and `records` the comparable form of a
//! value and the equality of the records a provider publishes.

mod cuts;
mod records;

pub use cuts::Cuts;
pub use records::{canonical_value, is_null_mx, same_record, same_typed_record};

#[cfg(test)]
mod tests;
