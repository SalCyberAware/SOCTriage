# Backup failure alerts

Railway shows a failed cron run in the dashboard but tells nobody. The backup
job therefore reports to a dead man's switch on
[healthchecks.io](https://healthchecks.io) (free tier), which sends an email
when the job fails or does not report success in time.

## How it works

When the `HEARTBEAT_URL` variable is set, `backup.sh` sends:

| When | Request | Meaning to healthchecks.io |
|---|---|---|
| Settings checked, before the dump | `GET <url>/start` | The run has started |
| After the `finished:` log line | `GET <url>` | Success |
| Any other exit (a `FAILED:` line, an unexpected error, a stop signal) | `POST <url>/<exit status>` with body `failed step: <step>` | Failure |

- The body names the step only (`settings`, `setup`, `dump`,
  `archive check`, `upload`, `upload check` or `prune`, with
  `(stopped by a signal)` added when that applies). No file names, sizes or
  hosts are sent.
- Only one failure ping is sent per run.
- If the job never runs, or is killed without a chance to report, no
  success ping arrives and healthchecks.io alerts when the period plus grace
  time runs out.
- curl gives each ping 10 seconds and retries a timeout or a server error
  up to three times. A ping that still cannot get through is logged as
  `heartbeat: could not reach the check (<start|success|fail>)`. It never
  fails the backup.
- The URL must start with `https://`. Anything else is logged once as
  `heartbeat: HEARTBEAT_URL is not an https URL, ignored` and no pings are
  sent. The log never shows the URL.
- With `HEARTBEAT_URL` unset the job behaves exactly as before: no requests
  and no `heartbeat:` lines.

## Creating the check

1. Sign in to healthchecks.io and add a check in your project. Name it, for
   example, `soctriage-pg-backup`.
2. Schedule: **Simple**, **Period 1 day**, **Grace Time 3 hours**. The cron
   runs at 07:00 UTC and takes seconds, so an alert means no success by about
   10:00 UTC the next day. Grace time also bounds a run that sent `/start`
   but never finished.
3. Make sure the email integration is on for the check (it is by default for
   the account email).
4. Copy the check's ping URL. It is secret-like: anyone with it can mark the
   check as passed or failed. Do not paste it into code, issues, prompts,
   reports or logs.

## Where the URL lives

- Railway variable `HEARTBEAT_URL` on the **pg-backup** service only, entered
  by hand in that service's Variables tab.
- The restore drill service must **not** get it. `restore-drill.sh` does
  not read it, and keeping it on one service keeps the secret in one place.
- No other service needs it.

## When an alert email arrives

The email says whether the check went down because a failure was reported or
because no success arrived in time.

1. In Railway, open the pg-backup service and its **Cron Runs** tab. Find the
   run for that morning, or see that none ran.
2. Open that run's deploy log. A failed run ends with a `FAILED:` line that
   says which check failed. healthchecks.io also shows the failed step in the
   ping body.
3. Fix the cause (for example a changed bucket credential or a database that
   did not answer), then start the job again from the service if you do not
   want to wait for the next night.
4. Run the checks in [RESTORE.md](RESTORE.md) on the newest backup, to be sure
   the backups that do exist are good.

If the log shows `heartbeat: could not reach the check`, the backup itself may
have been fine and only the ping was lost; the log's `finished:` line says
which.
