# The container images the workflows and the package builders run, one `FROM` line each, so that Dependabot (which reads
# Dockerfiles and not the `image:` of a workflow) moves their digests like the ones of the
# Containerfile. Nothing is built from this file. Each line has to equal the reference the
# workflows and `.github/scripts/distro_packages/images.env` carry, and each of their references has to
# be a line here: `ci_images/test_images.py` says which one disagrees, and
# `python3 .github/scripts/ci_images/images.py sync` copies the digests of this file into them
# after a Dependabot pull request.
#
#   debian-sid     ci.yml: the Debian build of the package
#   debian-trixie  reusable-rust-debian.yml: the default of that build
#   postgres       db.yml: the database the integration tests run against
#   rust-release   release.yml: the container the .deb is built in
#   imaptest       imaptest.yml: the Dovecot conformance tool
#   postfix        interop.yml: the peer the interop tests talk to
#   rpm-build      images.env: the builder of the rpm packages and where they are installed
#   rpm-query      images.env: the rpm that reads them as the channel does
FROM debian:sid@sha256:06889db0e48042b40d026b4505858812e4cb29f5cf7822189bb5be6522b4bee0 AS debian-sid
FROM debian:trixie@sha256:3cda3ca472ce45507a5109c6a3907093e24d9ae67d55954c9a07a45665dafba2 AS debian-trixie
FROM postgres:18@sha256:c699303802144847d238196173655dbbecf7a96aeca1565f2b02eb671a1f0b6b AS postgres
FROM docker.io/library/rust:1.100-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2 AS rust-release
FROM docker.io/dovecot/imaptest:latest@sha256:34e3a745a033e16faccf03e68309b97311cd2a42d0c377b5d983bd2b88dbf918 AS imaptest
FROM boky/postfix:latest@sha256:0632783c64183446c4edeae9092a2e015fdc0c4e8a3976bdf8878a7fc2146361 AS postfix
FROM docker.io/library/almalinux:9@sha256:02df05719ef287ebd0df0a1eedb9172a00bd70703aed7b25660e426b8e0d6047 AS rpm-build
FROM docker.io/library/fedora:45@sha256:a7d72ba2745b100a3351087472e5ee7b2450af7cf331e7673007e3817612839c AS rpm-query
