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

FROM docker.io/library/postgres:18@sha256:b9f6b8ff03b62f3cfd9d9ba3fe56226a9991c79d3fb46fd46536263bf02be553 AS postgres
FROM docker.io/clamav/clamav:1.5@sha256:45fe5149fbee5a46509c9848ef20d0c354b7b2323c9369f285939a37cf33422a AS clamav
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS mail
