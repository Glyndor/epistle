-- Operator allow list for the authentication ban policy: client addresses
-- and networks that are never banned and whose failures are never counted.
-- Managed with `epistle ban allow add|remove|list`. The ban store reads it on
-- every client-IP check, so a change takes effect on the running server with
-- no restart. It is a new table (expand only): a server that predates it
-- simply never reads it.

CREATE TABLE auth_allow (
	-- The block in canonical `network/prefix` form (`203.0.113.0/24`,
	-- `198.51.100.7/32`, `2001:db8::/32`), host bits zeroed by the CLI so two
	-- spellings of one block are the same row.
	cidr        TEXT PRIMARY KEY,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
