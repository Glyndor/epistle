-- Sender reputation: ham/spam counts keyed by a verified identity
-- (host, domain, sender address, or source IP). The antispam engine
-- consults this before heavier analysis.

CREATE TABLE reputation (
	id          UUID PRIMARY KEY,
	-- What the value identifies: 'host', 'domain', 'sender' or 'ip'.
	scope       TEXT NOT NULL,
	-- The identity itself, already normalized (lowercased) by the caller.
	value       TEXT NOT NULL,
	ham_count   BIGINT NOT NULL DEFAULT 0,
	spam_count  BIGINT NOT NULL DEFAULT 0,
	last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT reputation_scope_value_unique UNIQUE (scope, value)
);

-- Reputation is always looked up by (scope, value); the unique constraint
-- already provides that index.
