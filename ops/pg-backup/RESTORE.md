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

## Restore test on Railway

Steps 1 to 7 need a laptop with Docker and the Postgres tools. The restore
test does the same job inside the Railway project, with no tools and no
credentials on your machine: a temporary service built from
`Dockerfile.restore-drill` runs `restore-drill.sh` once, restores the newest
backup (or the one named in `RESTORE_FILE`) into a temporary, empty Postgres
and prints a summary. Nothing in production is read or changed apart from
downloading the backup file from the bucket.

The bucket credentials it uses can also write and delete backups. The script
only lists and downloads, but the service holding them is removed as soon as
the test is done (step 6).

1. **Add a temporary Postgres.** In the project, choose Create, then Database,
   then PostgreSQL. Rename the new service to `restore-scratch`. A new
   Railway Postgres is empty, which is what the test needs.
2. **Add a temporary service from this repository.** Choose Create, then
   GitHub Repo, and pick SOCTriage. In its Settings:
   - Source, Root Directory: `/ops/pg-backup`
   - Deploy, Restart Policy: Never, so a failed test is not run again and
     again.
   - Leave Cron Schedule empty and do not add a public domain.
   - Name it something obvious, for example `restore-drill`.
3. **Set its variables, as references only.** In the Variables tab:
   - `RAILWAY_DOCKERFILE_PATH` = `Dockerfile.restore-drill`. This is a plain
     value, not a secret. It makes the service build
     `Dockerfile.restore-drill` instead of the backup job's `Dockerfile`.
   - The five bucket variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
     `AWS_DEFAULT_REGION`, `ENDPOINT` and `BUCKET`, plus
     `S3_ADDRESSING_STYLE` if pg-backup has it: copy the same reference
     expressions that pg-backup's Variables tab shows (open its Raw Editor to
     see them). Never paste a key value.
   - `RESTORE_DATABASE_URL` = `${{restore-scratch.DATABASE_URL}}`
   - Never add `DATABASE_URL`. If it is present at all, even empty, the
     script stops before doing anything.
4. **Deploy** and wait for the deployment to finish. The container exits on
   its own, so the deployment ends as completed or failed rather than staying
   active.
5. **Read the log** in the deployment's Deploy Logs. A good run ends with:

   ```
   restore-drill: summary
   restore-drill:   file:             soctriage-YYYYMMDDTHHMMSSZ.dump
   restore-drill:   file size:        ... bytes
   restore-drill:   download:         ... s
   restore-drill:   restore:          ... s (measured restore time)
   restore-drill:   tables restored:  ...
   restore-drill:   cases rows:       ...
   restore-drill:   newest case:      ..., not later than the backup time ...
   restore-drill:   alembic version:  ...
   restore-drill: PASSED: soctriage-YYYYMMDDTHHMMSSZ.dump restored and checked
   ```

   Compare `cases rows` and `alembic version` the same way as in "6. Check
   the row counts" above. Any line
   starting with `FAILED:` means the test did not pass; it says why. Check
   the build log too: it must have built `Dockerfile.restore-drill`. If it
   built `Dockerfile` instead, the deploy log shows the backup job failing on
   a missing `DATABASE_URL`, nothing ran, and the Dockerfile variable needs
   fixing.
6. **Delete both temporary services**, `restore-drill` and
   `restore-scratch` (its volume goes with it), from each service's
   Settings, Danger section. Then check that only the usual services and the
   bucket are left in the project.

## Restoring into production

This is an incident action, not a routine one. Do it only after the same file
has been restored into a scratch database and checked as above, take a fresh
backup of the current state first, and stop the backend while it runs so no
case is written halfway through.
