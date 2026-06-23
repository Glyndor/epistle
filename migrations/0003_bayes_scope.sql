-- Per-account (scoped) Bayesian corpora. A `scope` key partitions tokens and
-- message totals so each account can train and be scored against its own
-- classifier. Scope '' is the shared corpus (the server's own accept/reject
-- learning); per-account spam/ham marking writes to that account's scope.

ALTER TABLE bayes_token ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE bayes_token DROP CONSTRAINT bayes_token_token_key;
ALTER TABLE bayes_token ADD CONSTRAINT bayes_token_scope_token_key UNIQUE (scope, token);

ALTER TABLE bayes_corpus DROP CONSTRAINT bayes_corpus_singleton;
ALTER TABLE bayes_corpus DROP CONSTRAINT bayes_corpus_pkey;
ALTER TABLE bayes_corpus ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE bayes_corpus DROP COLUMN singleton;
ALTER TABLE bayes_corpus ADD CONSTRAINT bayes_corpus_pkey PRIMARY KEY (scope);
