# The container images the generated stack runs, pinned by tag and digest.
#
# Nothing builds this file. epistle reads it at build time
# (src/cli/init/images.rs), so the compose files `epistle init` and
# `epistle stack update` render use exactly these references, and a
# Dependabot pull request that moves a digest here is what moves it on every
# install at the next release. Keep the name: Dependabot's docker ecosystem
# finds the file by it. Keep one `FROM <image>:<tag>@sha256:<digest> AS
# <service>` line per image and nothing else.
#
# PostgreSQL majors are ignored in .github/dependabot.yml: a new major is not
# a digest swap but a dump and restore, which `epistle db upgrade` does.
#
# The clamav digest is the multi-architecture index the registry served for
# `clamav/clamav:1.4` on 2026-10-12. The mail base must stay the digest the
# Containerfile's runtime stage uses; a test compares the two.

FROM docker.io/library/postgres:18@sha256:06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941 AS postgres
FROM docker.io/clamav/clamav:1.4@sha256:b5b910ce43d595bf8a2fe401e34db56434602b2c755b7c2b07f00c917d04d469 AS clamav
FROM gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d AS mail
