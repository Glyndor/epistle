# The container images the generated stack runs, pinned by tag and digest.
#
# Nothing builds this file. epistle reads it at build time
# (src/cli/init/images/mod.rs), so the compose files `epistle init` and
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
# `clamav/clamav:1.5` on 2026-10-18. The mail base must stay the digest the
# Containerfile's runtime stage uses; a test compares the two.

FROM docker.io/library/postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 AS postgres
FROM docker.io/clamav/clamav:1.5@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d AS clamav
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS mail
