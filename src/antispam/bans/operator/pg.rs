//! The production [`BanAdmin`]: the PostgreSQL ban store.

use super::{AllowPlaced, AllowRoom, Answer, BanAdmin, BanRoom, Placed, StoreError};
use crate::antispam::bans::{BanRow, BanTarget, PgBanStore, UnbanTarget};
use crate::cidr::Cidr;

fn failed(error: sqlx::Error) -> StoreError {
	StoreError(format!("database: {error}"))
}

impl BanAdmin for PgBanStore {
	fn list_bans(&self, now: u64) -> Answer<'_, Vec<BanRow>> {
		Box::pin(async move { PgBanStore::list_bans(self, now).await.map_err(failed) })
	}

	fn add_ban_within(
		&self,
		target: BanTarget,
		now: u64,
		until: u64,
		room: BanRoom,
	) -> Answer<'_, Placed> {
		Box::pin(async move {
			PgBanStore::add_ban_within(self, target, now, until, room)
				.await
				.map_err(failed)
		})
	}

	fn remove_ban(&self, target: UnbanTarget) -> Answer<'_, (u64, u64)> {
		Box::pin(async move { PgBanStore::remove_ban(self, target).await.map_err(failed) })
	}

	fn allow_list(&self) -> Answer<'_, Vec<String>> {
		Box::pin(async move { PgBanStore::allow_list(self).await.map_err(failed) })
	}

	fn allow_add_within(&self, cidr: Cidr, room: AllowRoom) -> Answer<'_, AllowPlaced> {
		Box::pin(async move {
			PgBanStore::allow_add_within(self, cidr, room)
				.await
				.map_err(failed)
		})
	}

	fn allow_remove(&self, cidr: Cidr) -> Answer<'_, bool> {
		Box::pin(async move { PgBanStore::allow_remove(self, cidr).await.map_err(failed) })
	}
}
