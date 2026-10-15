# Nightly SOCTriage database backup. A Railway cron service in the same
# project builds this file (root directory ops/pg-backup/), starts it on
# schedule, and it dumps the database to the project's storage bucket and
# exits. See backup.sh for the variables it needs and RESTORE.md for getting a
# backup back.
#
#   docker build -t soctriage-pg-backup ops/pg-backup
#
# Base: the official Postgres 18 Alpine image, for its pg_dump and pg_restore
# only; no server is started. pg_dump refuses to dump a server newer than
# itself, and production runs Postgres 18, so the major is held at 18 here and
# in Dependabot until the server moves. Pinned by digest so a rebuild cannot
# pick up a different image; Dependabot proposes new digests.
#
# Pulled from Amazon's public mirror of Docker Hub's official images, as
# backend/Dockerfile is, because Docker Hub refuses anonymous pulls from shared
# builders such as Railway's.
FROM public.ecr.aws/docker/library/postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873

# AWS CLI v2 from Alpine's own packages, as Railway's backup guide does.
# curl sends the heartbeat pings (see ALERTING.md); the base image has
# libcurl but not the curl command.
RUN apk add --no-cache aws-cli curl \
 && adduser -D -H -u 10001 -s /sbin/nologin backup

COPY backup.sh /usr/local/bin/backup.sh
RUN chmod 0555 /usr/local/bin/backup.sh

# HOME points somewhere writable because the backup user has no home folder
# and the AWS CLI looks there for its cache. PGCONNECT_TIMEOUT bounds each
# connection attempt; libpq would otherwise wait indefinitely.
ENV HOME=/tmp \
    PGCONNECT_TIMEOUT=15

USER 10001

# Replaces the base image's server entrypoint, which also clears its CMD.
ENTRYPOINT ["/usr/local/bin/backup.sh"]
