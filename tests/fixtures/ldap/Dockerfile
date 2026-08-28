# Test-only OpenLDAP image with a fixed user baked in.
#
# Extends osixia/openldap (the only digest-pinned OpenLDAP image
# available on Docker Hub at the time of writing) and seeds the
# directory with the contents of `seed.ldif` from this directory.
#
# The seed path (`bootstrap/ldif/seed.ldif`, a direct child of
# `bootstrap/ldif/`) is what the parent image's startup script loops
# over with `find ... -mindepth 1 -maxdepth 1` to seed slapd the
# first time it boots with an empty database. Putting the LDIF in
# `bootstrap/ldif/initial/` (the path documented in older osixia
# examples) is silently ignored, because the script does not recurse.
#
# A bind mount of the seed file fails with "Device or resource busy":
# the parent script ends each boot by `rm -rf`ing `assets/config`,
# which is why this Dockerfile exists and the workflow builds the
# image rather than bind-mounting the LDIF.
FROM docker.io/osixia/openldap@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28

COPY seed.ldif /container/service/slapd/assets/config/bootstrap/ldif/seed.ldif