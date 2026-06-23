-- SQL directory backend: accounts and their addresses, loaded into the
-- in-memory directory at startup and refreshed periodically. This is a third
-- account source alongside the static config and the dynamic accounts.toml;
-- it never participates in the synchronous auth path directly. Passwords are
-- argon2id PHC strings, exactly as the local accounts store them.

CREATE TABLE directory_account (
	-- Account name; doubles as the mailbox directory name. Lowercased by the
	-- loader to match the case-insensitive authentication lookup.
	name           TEXT PRIMARY KEY,
	-- argon2id PHC hash. NULL leaves the account receive-only (cannot auth).
	password_hash  TEXT,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE directory_address (
	-- Delivered address, already normalized (lowercased) by the caller.
	address     TEXT PRIMARY KEY,
	-- Owning account; deleting an account removes its addresses.
	account     TEXT NOT NULL REFERENCES directory_account(name) ON DELETE CASCADE,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Addresses are loaded grouped by account; the FK lookup wants this index.
CREATE INDEX directory_address_account_idx ON directory_address (account);
