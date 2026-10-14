#!/bin/sh
# Restore test for the SOCTriage database backups.
#
# Runs once and exits: a temporary Railway service starts the container, this
# downloads a backup that backup.sh wrote (the newest by default), restores it
# into an EMPTY scratch Postgres, prints counts and stops. It exits 0 only when
# every check passed, so the deploy log shows a failed restore as a failure.
# See RESTORE.md, "Restore test on Railway", for how to run it.
#
# Required: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION,
#           ENDPOINT, BUCKET, RESTORE_DATABASE_URL
# Optional: BACKUP_PREFIX        folder inside the bucket   (default soctriage/)
#           RESTORE_FILE         one backup's file name     (default the newest)
#           S3_ADDRESSING_STYLE  virtual or path            (default virtual)
#
# Safety: it refuses to start when DATABASE_URL is set at all, so the service
# can never be handed the production database by habit, and it restores
# nothing unless the target has no tables or views in schema public. Both are
# checked before anything is downloaded. On the bucket it only lists, reads
# object sizes and downloads: it never uploads or deletes.
#
# The log never shows a value from the environment, a URL, a host or any case
# content. Errors from psql, pg_restore and the AWS CLI go through redact()
# first, because they put the server address in their messages.

set -eu

log() {
  printf '%s restore-drill: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

fail() {
  log "FAILED: $*"
  exit 1
}

# Prints a tool's captured error output with URLs, quoted strings, anything in
# parentheses and IPv4 addresses removed. That is where psql, pg_restore and
# the AWS CLI put host names, addresses, user names, endpoints and key values.
# What is left (for example "password authentication failed" or "Access
# Denied") is still enough to act on.
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

# Set at all, even to an empty value, means someone wired this service up like
# the backup job. Refuse before reading anything else.
if [ "${DATABASE_URL+set}" = set ]; then
  fail "DATABASE_URL is set. This service must never be given the production database; give it RESTORE_DATABASE_URL (a scratch database) only. Nothing restored."
fi

missing=""
value=""
for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION ENDPOINT BUCKET RESTORE_DATABASE_URL; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || missing="$missing $name"
done
value=""
[ -z "$missing" ] || fail "missing required variable(s):$missing"

PREFIX=${BACKUP_PREFIX:-soctriage/}
RESTORE_FILE=${RESTORE_FILE:-}
ADDRESSING_STYLE=${S3_ADDRESSING_STYLE:-virtual}

case $PREFIX in
  '' | /* | *//* | *..* | *[!A-Za-z0-9._/-]*)
    fail "BACKUP_PREFIX must be a folder name such as soctriage/ (letters, digits, . _ - /)" ;;
  */) ;;
  *) fail "BACKUP_PREFIX must end with /" ;;
esac

# Only a name backup.sh writes, with no folder part.
case $RESTORE_FILE in
  '' | soctriage-[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.dump) ;;
  *) fail "RESTORE_FILE must be a backup file name such as soctriage-20261013T030000Z.dump" ;;
esac

case $ADDRESSING_STYLE in
  virtual | path) ;;
  *) fail "S3_ADDRESSING_STYLE must be virtual or path" ;;
esac

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
trap 'exit 1' HUP INT TERM

# The addressing style can only be set in an AWS config file, so write one
# for this run. Credentials and region still come from the AWS_* variables.
export AWS_CONFIG_FILE="$workdir/aws-config"
printf '[default]\ns3 =\n    addressing_style = %s\n' "$ADDRESSING_STYLE" > "$AWS_CONFIG_FILE"

err="$workdir/stderr"

# Runs one query against the target and leaves the bare result in $out. On an
# error it fails with the message in $2.
out=""
sql() {
  if ! out=$(psql --dbname="$RESTORE_DATABASE_URL" -X -q -A -t -v ON_ERROR_STOP=1 \
        -c "$1" 2>"$err"); then
    redact "$err"
    fail "$2"
  fi
}

log "start: restore test (prefix $PREFIX)"

# ── Target must be empty ─────────────────────────────────────────────────────

# Tables, partitioned tables, views, materialized views and foreign tables in
# schema public. Anything there means this is not a fresh scratch database.
in_use="SELECT count(*) FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"

# Three tries, five seconds apart, for a private network or a scratch database
# that is still starting. PGCONNECT_TIMEOUT (set in the Dockerfile) bounds each
# try.
attempt=1
until out=$(psql --dbname="$RESTORE_DATABASE_URL" -X -q -A -t -v ON_ERROR_STOP=1 \
      -c "$in_use" 2>"$err"); do
  if [ "$attempt" -ge 3 ]; then
    redact "$err"
    fail "cannot reach the target database after $attempt tries"
  fi
  log "target database try $attempt failed, trying again in 5 seconds"
  attempt=$((attempt + 1))
  sleep 5
done

[ "$out" = 0 ] \
  || fail "target database is not empty: $out tables or views in schema public. Point RESTORE_DATABASE_URL at a new, empty database. Nothing restored."

log "target database is empty"

# ── Pick the backup ──────────────────────────────────────────────────────────

if ! aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" \
      --endpoint-url "$ENDPOINT" --query 'Contents[].[Key]' --output text \
      > "$workdir/keys" 2>"$err"; then
  redact "$err"
  fail "cannot list backups"
fi

# Same rule as backup.sh's pruning: exactly
# <prefix>soctriage-YYYYMMDDTHHMMSSZ.dump, directly in the prefix.
: > "$workdir/ours"
while IFS= read -r k; do
  case $k in
    "$PREFIX"soctriage-[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.dump)
      printf '%s\n' "$k" >> "$workdir/ours" ;;
  esac
done < "$workdir/keys"

# Fixed-width names, so name order is time order.
sort "$workdir/ours" > "$workdir/sorted"
[ -s "$workdir/sorted" ] || fail "no backups found under $PREFIX"

if [ -n "$RESTORE_FILE" ]; then
  key="$PREFIX$RESTORE_FILE"
  grep -qxF -- "$key" "$workdir/sorted" || fail "backup $RESTORE_FILE not found under $PREFIX"
else
  key=$(tail -n 1 "$workdir/sorted")
fi
file=${key#"$PREFIX"}
dump="$workdir/$file"

if ! size=$(aws s3api head-object --bucket "$BUCKET" --key "$key" \
      --endpoint-url "$ENDPOINT" --query ContentLength --output text 2>"$err"); then
  redact "$err"
  fail "cannot read the size of $file"
fi
case $size in
  '' | 0 | *[!0-9]*) fail "$file is empty or has no size" ;;
esac

log "chosen: $file ($size bytes)"

# ── Download ─────────────────────────────────────────────────────────────────

started=$(date -u +%s)
if ! aws s3 cp "s3://$BUCKET/$key" "$dump" --endpoint-url "$ENDPOINT" \
      --only-show-errors --no-progress 2>"$err"; then
  redact "$err"
  fail "download failed"
fi
download_seconds=$(( $(date -u +%s) - started ))

local_size=$(wc -c < "$dump" | tr -d ' ')
[ "$local_size" = "$size" ] \
  || fail "downloaded $local_size bytes but the bucket says $size bytes"

# The same archive check backup.sh makes before it uploads.
if ! pg_restore --list "$dump" > "$workdir/toc" 2>"$err"; then
  redact "$err"
  fail "pg_restore cannot read the backup"
fi
for table in cases alembic_version; do
  grep -Eq "^[0-9]+; [0-9]+ [0-9]+ TABLE [^ ]+ $table( |\$)" "$workdir/toc" \
    || fail "backup has no $table table"
  grep -Eq "^[0-9]+; [0-9]+ [0-9]+ TABLE DATA [^ ]+ $table( |\$)" "$workdir/toc" \
    || fail "backup has no rows section for the $table table"
done

log "download done in $download_seconds s, archive valid, lists cases and alembic_version"

# ── Restore ──────────────────────────────────────────────────────────────────

# One transaction: on any error nothing is left behind in the target.
started=$(date -u +%s)
if ! pg_restore --no-owner --exit-on-error --single-transaction \
      --dbname="$RESTORE_DATABASE_URL" "$dump" 2>"$err"; then
  redact "$err"
  fail "restore failed, nothing was kept in the target"
fi
restore_seconds=$(( $(date -u +%s) - started ))

# The download is not needed any more; the EXIT trap would remove it anyway.
rm -f "$dump"

# ── Check ────────────────────────────────────────────────────────────────────

sql "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'" \
  "cannot count the restored tables"
tables=$out

sql "SELECT count(*) FROM cases" "cannot count the restored cases"
cases=$out

# The newest creation time as YYYYMMDDHHMMSS and as a readable UTC time, or
# empty when there are no cases.
sql "SELECT to_char(max(created_at) AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISS')
            || ' ' || to_char(max(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
       FROM cases" \
  "cannot read the newest case time"
newest_digits=${out%% *}
newest_text=${out#* }

sql "SELECT coalesce(string_agg(version_num, ',' ORDER BY version_num), '') FROM alembic_version" \
  "cannot read the migration version"
alembic=$out
[ -n "$alembic" ] || fail "alembic_version is empty"

# The time the backup was taken, from its name.
taken=${file#soctriage-}
taken=${taken%Z.dump}
taken_digits=$(printf '%s' "$taken" | tr -d T)
taken_text=$(printf '%s' "$taken" \
  | sed -E 's/^(....)(..)(..)T(..)(..)(..)$/\1-\2-\3T\4:\5:\6Z/')

if [ -z "$newest_digits" ]; then
  newest_line="none (the cases table is empty)"
elif [ "$((newest_digits <= taken_digits))" -eq 1 ]; then
  newest_line="$newest_text, not later than the backup time $taken_text"
else
  fail "newest case $newest_text is later than the backup time $taken_text"
fi

log "summary"
log "  file:             $file"
log "  file size:        $size bytes"
log "  download:         $download_seconds s"
log "  restore:          $restore_seconds s (measured restore time)"
log "  tables restored:  $tables"
log "  cases rows:       $cases"
log "  newest case:      $newest_line"
log "  alembic version:  $alembic"
log "PASSED: $file restored and checked"
