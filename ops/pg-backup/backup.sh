#!/bin/sh
# Nightly backup of the SOCTriage Postgres database to an S3-compatible bucket.
#
# Runs once and exits: a Railway cron service starts the container on schedule,
# this dumps the database, checks the dump, uploads it, checks the upload,
# prunes old backups and stops. Any failure exits non-zero so the run shows as
# failed in Railway.
#
# Required: DATABASE_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
#           AWS_DEFAULT_REGION, ENDPOINT, BUCKET
# Optional: BACKUP_PREFIX        folder inside the bucket   (default soctriage/)
#           RETENTION_DAYS       days a backup is kept      (default 30)
#           S3_ADDRESSING_STYLE  virtual or path            (default virtual)
#           HEARTBEAT_URL        healthchecks.io ping URL   (default unset: no pings)
#
# Railway buckets use virtual-hosted style URLs; buckets created before that
# change, and most local S3 stand-ins, need path. The bucket's Credentials tab
# says which one applies.
#
# HEARTBEAT_URL turns on a dead man's switch: the run pings <url>/start once
# the settings are checked, <url> after "finished:", and <url>/<exit status>
# on any other exit, so a missed or failed night sends an alert. The URL must
# be https. A ping that cannot get through is logged and never fails the
# backup. See ALERTING.md.
#
# The log never shows a value from the environment, a URL or a host. Errors
# from pg_dump and the AWS CLI go through redact() first, because both put the
# server address in their messages.

set -eu

log() {
  printf '%s pg-backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

fail() {
  log "FAILED: $*"
  exit 1
}

# ── Heartbeat ────────────────────────────────────────────────────────────────

# Checked before anything else, so that a failure in the settings check below
# is reported too. Only characters a healthchecks.io ping URL uses are
# accepted, which also rules out a query string the suffix would land after.
# HEARTBEAT_ALLOW_HTTP=1 lets the CI test point at a local plain-http
# listener; nothing in the image sets it.
heartbeat=""
heartbeat_proto="=https"
if [ -n "${HEARTBEAT_URL:-}" ]; then
  case $HEARTBEAT_URL in
    *[!A-Za-z0-9._~:/-]*) ;;
    https://?*) heartbeat=${HEARTBEAT_URL%/} ;;
    http://?*)
      if [ "${HEARTBEAT_ALLOW_HTTP:-}" = 1 ]; then
        heartbeat=${HEARTBEAT_URL%/}
        heartbeat_proto="=http,https"
      fi ;;
  esac
  [ -n "$heartbeat" ] || log "heartbeat: HEARTBEAT_URL is not an https URL, ignored"
fi

# Usage: ping LABEL [SUFFIX [BODY]]. Sends <url><SUFFIX>, as a POST with BODY
# when one is given. Never fails: an error is logged by LABEL only, and curl's
# own message is dropped because it names the host.
ping() {
  [ -n "$heartbeat" ] || return 0
  label=$1
  url=$heartbeat${2:-}
  if [ -n "${3:-}" ]; then set -- --data-raw "$3"; else set --; fi
  if curl --silent --show-error --fail --max-time 10 --retry 3 --retry-delay 5 \
       --proto "$heartbeat_proto" --output /dev/null "$@" -- "$url" 2>/dev/null; then
    log "heartbeat: sent ($label)"
  else
    log "heartbeat: could not reach the check ($label)"
  fi
  url=""
}

# Every exit other than a success pings /<exit status> once, with the name of
# the step that was running as the body and nothing else. The temporary
# folder is removed here too, once it exists.
step="settings"
workdir=""
fail_pinged=""
on_exit() {
  status=$?
  [ -z "$workdir" ] || rm -rf "$workdir"
  if [ "$status" -ne 0 ] && [ -z "$fail_pinged" ]; then
    fail_pinged=1
    ping fail "/$status" "failed step: $step"
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'step="$step (stopped by a signal)"; exit 1' HUP INT TERM

# Prints a tool's captured error output with URLs, quoted strings, anything in
# parentheses and IPv4 addresses removed. That is where pg_dump and the AWS CLI
# put host names, addresses, user names and endpoints. What is left (for
# example "password authentication failed" or "Access Denied") is still enough
# to act on.
redact() {
  sed -E \
    -e 's#[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]]*#[url]#g' \
    -e 's/"[^"]*"/"[redacted]"/g' \
    -e "s/'[^']*'/'[redacted]'/g" \
    -e 's/\([^)]*\)/([redacted])/g' \
    -e 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/[address]/g' \
    "$1" | head -n 20 >&2 || true
}

# ── Settings ─────────────────────────────────────────────────────────────────

missing=""
value=""
for name in DATABASE_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION ENDPOINT BUCKET; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || missing="$missing $name"
done
value=""
[ -z "$missing" ] || fail "missing required variable(s):$missing"

PREFIX=${BACKUP_PREFIX:-soctriage/}
RETENTION_DAYS=${RETENTION_DAYS:-30}
ADDRESSING_STYLE=${S3_ADDRESSING_STYLE:-virtual}

case $RETENTION_DAYS in
  '' | 0* | *[!0-9]*) fail "RETENTION_DAYS must be a positive whole number of days" ;;
esac
[ "${#RETENTION_DAYS}" -le 5 ] || fail "RETENTION_DAYS must be at most 99999"

# A non-empty folder name ending in "/", so pruning can never reach the rest of
# the bucket.
case $PREFIX in
  '' | /* | *//* | *..* | *[!A-Za-z0-9._/-]*)
    fail "BACKUP_PREFIX must be a folder name such as soctriage/ (letters, digits, . _ - /)" ;;
  */) ;;
  *) fail "BACKUP_PREFIX must end with /" ;;
esac

case $ADDRESSING_STYLE in
  virtual | path) ;;
  *) fail "S3_ADDRESSING_STYLE must be virtual or path" ;;
esac

step="setup"
ping start /start

workdir=$(mktemp -d)

# The addressing style can only be set in an AWS config file, so write one
# for this run. Credentials and region still come from the AWS_* variables.
export AWS_CONFIG_FILE="$workdir/aws-config"
printf '[default]\ns3 =\n    addressing_style = %s\n' "$ADDRESSING_STYLE" > "$AWS_CONFIG_FILE"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
file="soctriage-$stamp.dump"
dump="$workdir/$file"
key="$PREFIX$file"
err="$workdir/stderr"

log "start: backup $file (prefix $PREFIX, retention $RETENTION_DAYS days)"

# ── Dump ─────────────────────────────────────────────────────────────────────

# Three tries, five seconds apart, for a private network or a database that is
# a moment slow to answer. PGCONNECT_TIMEOUT (set in the Dockerfile) bounds
# each try.
step="dump"
attempt=1
until pg_dump --format=custom --no-owner --file="$dump" --dbname="$DATABASE_URL" 2>"$err"; do
  if [ "$attempt" -ge 3 ]; then
    redact "$err"
    fail "pg_dump failed $attempt times"
  fi
  log "pg_dump try $attempt failed, trying again in 5 seconds"
  attempt=$((attempt + 1))
  sleep 5
done

size=$(wc -c < "$dump" | tr -d ' ')
[ "$size" -gt 0 ] || fail "pg_dump wrote an empty file"

step="archive check"

# The archive must open and must hold the app's table, with its rows, and the
# migration marker. An empty or wrong database would otherwise back up "fine".
if ! pg_restore --list "$dump" > "$workdir/toc" 2>"$err"; then
  redact "$err"
  fail "pg_restore cannot read the dump"
fi
for table in cases alembic_version; do
  grep -Eq "^[0-9]+; [0-9]+ [0-9]+ TABLE [^ ]+ $table( |\$)" "$workdir/toc" \
    || fail "dump has no $table table"
  grep -Eq "^[0-9]+; [0-9]+ [0-9]+ TABLE DATA [^ ]+ $table( |\$)" "$workdir/toc" \
    || fail "dump has no rows section for the $table table"
done

log "dump size: $size bytes, archive valid, lists cases and alembic_version"

# ── Upload ───────────────────────────────────────────────────────────────────

step="upload"

if ! aws s3 cp "$dump" "s3://$BUCKET/$key" --endpoint-url "$ENDPOINT" \
      --only-show-errors --no-progress 2>"$err"; then
  redact "$err"
  fail "upload failed"
fi

step="upload check"

if ! remote_size=$(aws s3api head-object --bucket "$BUCKET" --key "$key" \
      --endpoint-url "$ENDPOINT" --query ContentLength --output text 2>"$err"); then
  redact "$err"
  fail "uploaded object cannot be found"
fi
[ "$remote_size" = "$size" ] \
  || fail "uploaded object is $remote_size bytes but the dump is $size bytes"

log "upload done: $key ($remote_size bytes, size matches)"

# ── Prune ────────────────────────────────────────────────────────────────────

# Age comes from the timestamp in the file name, which is the time the backup
# was taken. Only keys this script names are considered: exactly
# <prefix>soctriage-YYYYMMDDTHHMMSSZ.dump, directly in the prefix. Anything
# else in the bucket, inside the prefix or not, is never touched. The newest
# backup, and the one just uploaded, are always kept whatever their age.

step="prune"

if ! aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" \
      --endpoint-url "$ENDPOINT" --query 'Contents[].[Key]' --output text \
      > "$workdir/keys" 2>"$err"; then
  redact "$err"
  fail "cannot list backups"
fi

: > "$workdir/ours"
while IFS= read -r k; do
  case $k in
    "$PREFIX"soctriage-[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.dump)
      printf '%s\n' "$k" >> "$workdir/ours" ;;
  esac
done < "$workdir/keys"

# Fixed-width names, so name order is time order.
sort "$workdir/ours" > "$workdir/sorted"
newest=$(tail -n 1 "$workdir/sorted")

# YYYYMMDDHHMMSS as one number. Fourteen digits fit the shell's 64-bit math.
cutoff=$(date -u -d "@$(( $(date -u +%s) - RETENTION_DAYS * 86400 ))" +%Y%m%d%H%M%S)

pruned=0
kept=0
while IFS= read -r k; do
  [ -n "$k" ] || continue
  if [ "$k" = "$newest" ] || [ "$k" = "$key" ]; then
    kept=$((kept + 1))
    continue
  fi
  taken=${k#"$PREFIX"soctriage-}
  taken=${taken%Z.dump}
  taken=$(printf '%s' "$taken" | tr -d T)
  if [ "$((taken < cutoff))" -eq 1 ]; then
    if ! aws s3api delete-object --bucket "$BUCKET" --key "$k" \
          --endpoint-url "$ENDPOINT" > /dev/null 2>"$err"; then
      redact "$err"
      fail "cannot delete old backup $k"
    fi
    log "pruned $k"
    pruned=$((pruned + 1))
  else
    kept=$((kept + 1))
  fi
done < "$workdir/sorted"

log "objects pruned: $pruned older than $RETENTION_DAYS days, $kept backups kept"
log "finished: $key"
ping success
