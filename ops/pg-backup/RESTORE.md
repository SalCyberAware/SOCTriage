# Restoring a SOCTriage database backup

The backup job (`backup.sh`, run nightly by a Railway cron service) writes one
file per night to the project's storage bucket:

```
<bucket>/soctriage/soctriage-YYYYMMDDTHHMMSSZ.dump
```

Each file is a `pg_dump --format=custom --no-owner` archive of the whole
database, with the time in the name in UTC. Files older than `RETENTION_DAYS`
(30 by default) are deleted by the job, except the newest, which is always
kept.

These steps restore a backup into a **scratch** database to prove it is good.
They never touch production.

## What you need

- Postgres 18 client tools (`pg_restore`, `psql`). Version 18 or newer:
  an older `pg_restore` cannot read an archive made by `pg_dump` 18.
- The AWS CLI v2.
- Docker, for the scratch database.
- The bucket's credentials from its **Credentials** tab in Railway.

If you would rather not install the tools, the backup image has all of them:
`docker build -t soctriage-pg-backup ops/pg-backup`, then
`docker run --rm -it --network host --entrypoint sh soctriage-pg-backup`
and run the commands below inside it.

## 1. Set the bucket variables for this shell

Copy them from the Credentials tab into the current shell only. Do not put them
in a file inside the repository, and do not paste them into tickets or chat.

```sh
export AWS_ACCESS_KEY_ID=...        # from the Credentials tab
export AWS_SECRET_ACCESS_KEY=...    # from the Credentials tab
export AWS_DEFAULT_REGION=...       # the bucket's region, for example auto
export ENDPOINT=...                 # the bucket's endpoint URL
export BUCKET=...                   # the bucket name (BUCKET, not RAILWAY_BUCKET_NAME)
```

If the Credentials tab says the bucket needs path-style URLs, also run
`aws configure set default.s3.addressing_style path`.

## 2. List the backups

```sh
aws s3 ls "s3://$BUCKET/soctriage/" --endpoint-url "$ENDPOINT"
```

Names sort by time, so the last line is the newest.

## 3. Download one

```sh
FILE=soctriage-YYYYMMDDTHHMMSSZ.dump    # the one you want
aws s3 cp "s3://$BUCKET/soctriage/$FILE" "./$FILE" --endpoint-url "$ENDPOINT"
```

Check it opens and lists the two tables:

```sh
pg_restore --list "./$FILE" | grep -E "TABLE (DATA )?public (cases|alembic_version)"
```

You should see four lines: a `TABLE` and a `TABLE DATA` line for each table.

## 4. Start a scratch Postgres

A throwaway Postgres 18 that listens only on this machine and is deleted when
it stops:

```sh
docker run --rm -d --name soctriage-restore \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55432:5432 \
  public.ecr.aws/docker/library/postgres:18-alpine
# wait a few seconds for it to start, then:
psql "postgresql://postgres@127.0.0.1:55432/postgres" -c "CREATE DATABASE soctriage_restore"
```

## 5. Restore into it

```sh
pg_restore --no-owner --clean --if-exists \
  --dbname="postgresql://postgres@127.0.0.1:55432/soctriage_restore" \
  "./$FILE"
```

`--clean --if-exists` drops each object before recreating it and does not
complain when it is not there yet, so the same command also works when run a
second time into the same scratch database. `--no-owner` makes the scratch
user own everything instead of the production role.

## 6. Check the row counts

```sh
psql "postgresql://postgres@127.0.0.1:55432/soctriage_restore" <<'SQL'
SELECT count(*) AS cases FROM cases;
SELECT count(*) AS open_cases FROM cases WHERE status <> 'closed';
SELECT min(created_at) AS oldest, max(created_at) AS newest FROM cases;
SELECT version_num FROM alembic_version;
SQL
```

What to compare against:

- `cases`: the total the dashboard showed around the time of the backup. It
  should match exactly, or differ only by cases opened after the backup time
  in the file name.
- `newest`: no later than the backup time in the file name.
- `version_num`: the migration head of the code that was deployed then
  (`alembic heads` in `backend/` at that commit).

## 7. Clean up

```sh
docker stop soctriage-restore   # --rm deletes it and its data
rm "./$FILE"
```

Then close the shell so the bucket credentials go with it.

## Restoring into production

This is an incident action, not a routine one. Do it only after the same file
has been restored into a scratch database and checked as above, take a fresh
backup of the current state first, and stop the backend while it runs so no
case is written halfway through.
