-- Networks an account has signed in from successfully within the
-- configured window. When the account is banned and the same account
-- signs in from one of these networks with the right credentials,
-- the ban is bypassed in this workspace; from any other network the
-- response is the same refusal a banned subject sees today.
--
-- The table exists to keep an account reachable from the networks
-- its owner actually uses, without turning the ban into an oracle
-- for anyone who guesses a password from somewhere else. The row is
-- written only after a complete, successful authentication, never on
-- a failed attempt: an attempt is not an admission, and admitting an
-- attempt would let a guessed password register itself.
--
-- The network is the address the listener saw, with one rule: IPv6
-- is collapsed to the /64 (the same keying the ban store uses for
-- the client counter), so a roaming client does not have to re-auth
-- every time its host half changes.

CREATE TABLE auth_known_network (
	-- The account that signed in. Lowercased so case variations
	-- collapse to one row, the same way `subject_account` keys.
	account     TEXT NOT NULL,
	-- The network the sign-in came from: the IPv4 exact address or
	-- the IPv6 /64 in canonical textual form. Stored as TEXT so the
	-- index can do the equality match the lookups require.
	network     TEXT NOT NULL,
	-- Unix seconds of the most recent successful sign-in from this
	-- network. The expire sweep deletes rows older than the
	-- configured window so a network the owner has not used in a
	-- while stops granting bypass.
	last_seen   BIGINT NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (account, network)
);

-- Expire sweep: rows older than the window are dropped on a daily
-- tick. Indexed on `(account, last_seen)` so a per-account eviction
-- is a single index range.
CREATE INDEX auth_known_network_account_last_seen
	ON auth_known_network (account, last_seen);
