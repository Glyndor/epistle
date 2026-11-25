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

FROM docker.io/library/postgres:18@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc AS postgres
FROM docker.io/clamav/clamav:1.5@sha256:7054e3f34308c384ea43cd786ea17abf899bd44af40af9f1b099853d7a5c214e AS clamav
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS mail
