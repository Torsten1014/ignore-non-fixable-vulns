# ignore_non_fixable_vulns

Creates **project-level ignores** in Snyk for open-source **vulnerabilities that genuinely have no remediation path**. An issue qualifies when **both** of these hold:

- **`computed_fixability`** is **`No Fix Supported`** — Snyk found no upgradable path, and
- **`fixed_in_available`** is **`false`** — no version of the package fixes it anywhere upstream.

Ignores use **`disregardIfFixable: true`** (default) so they stop applying once a fix becomes available.

Issues come from the **Export API** (`issues` dataset): the tool starts one CSV export per **organization** or **Group**, polls until it finishes, downloads the results, filters them, records the work in a **CSV**, and creates the ignores. If the run stops mid-way, **`--resume`** continues from the CSV without re-exporting.

**Author:** Torsten Cannell, torsten.cannell@snyk.io

## Prerequisites

- Python 3.11+
- Snyk API token (`SNYK_TOKEN`) with:
  - `View Organization reports (org.report.read)` for org-scoped exports, or `View reports (group.report.read)` for group-scoped exports
  - permission to create ignores on the projects in scope (Enterprise)

## APIs used

| Purpose | API |
|--------|-----|
| Start an export | REST `POST /orgs/{org_id}/export` or `POST /groups/{group_id}/export` |
| Poll export status | REST `GET .../jobs/export/{export_id}` |
| Fetch export results | REST `GET .../export/{export_id}` |
| Download results | Pre-signed object-storage URL (no auth header) |
| Create ignore | V1 `POST /org/{orgId}/project/{projectId}/ignore/{issueId}` |
| Delete ignore (`--revert`) | V1 `DELETE /org/{orgId}/project/{projectId}/ignore/{issueId}` |

Set **`SNYK_API_BASE_URL`** or **`--api-base-url`** for non-US tenants (host only, no path suffix).
The script appends **`/v1`** or **`/rest`** as needed (e.g. `https://api.eu.snyk.io` or `api.eu.snyk.io`).
Default **`--rest-version`** is **`2024-10-15`**.

### Columns requested

What is needed to build and filter an ignore — `GROUP_PUBLIC_ID`, `ORG_PUBLIC_ID`, `PROJECT_PUBLIC_ID`, `PROBLEM_ID`, `ISSUE_TYPE`, `ISSUE_STATUS`, `COMPUTED_FIXABILITY`, `FIXED_IN_AVAILABLE` — plus context for the optional report: `FIXED_IN_VERSION`, `PROBLEM_TITLE`, `ISSUE_SEVERITY`, `PROJECT_NAME`, `PACKAGE_NAME_AND_VERSION`, `ISSUE_URL`. `PROBLEM_ID` is the Snyk issue ID the V1 ignore endpoint expects.

### Filtering

| Filter | Where it runs | Default |
|--------|---------------|---------|
| Date window (`introduced` / `updated`) | Export API (required by the API) | `introduced.from = 2010-01-01T00:00:00Z` |
| `issue_status` | Export API **and** CSV | `Open` |
| `issue_type` | CSV | `Vulnerability` |
| `computed_fixability` | CSV | `No Fix Supported` |
| `fixed_in_available` | CSV | must be `false` (disable with `--include-fixed-in-available`) |
| `project_public_id` | CSV | not filtered |

The Export API does not filter on fixability, so the CSV is filtered locally — this is the approach Snyk recommends in the v1-reporting-to-Export-API migration guide. CSV-side label comparison ignores case, spaces, underscores, and hyphens, so `No Fix Supported`, `no fix supported`, and `NO_FIX_SUPPORTED` all match. Word order is **not** normalized.

> **Watch the wording.** The Export API emits **`No Fix Supported`**, while Snyk's documentation writes the same value as "No supported fix". The default accepts both spellings, but if you pass `--fixability` yourself, use the value you see in the exported CSV.

Since April 2025 non-SCA issues (Snyk Code, Snyk IaC, Open Source license issues) report `Not Applicable` rather than `No Fix Supported`, so they are excluded by the fixability filter as well as the `issue_type` filter.

### Why `fixed_in_available` also has to be false

`computed_fixability` alone selects too much. Snyk defines `No supported fix` as "the issue has no upgradable paths, **or Snyk does not support Fix PRs for this Project type**" — so an issue that is perfectly upgradable can carry that label purely because its ecosystem has no Fix PR support.

That matters because the ignore itself is evaluated against a different signal. `disregardIfFixable` uses `isUpgradable || isPinnable || isPatchable` ([snyk/policy](https://github.com/Snyk/policy/commit/0f3d883887ab26b1e44382e9aaaeaee9c24caff0)), so an upgradable issue gets an ignore created and then immediately disregarded — it exists in Snyk but never applies, and the issue keeps showing as un-ignored.

Requiring `fixed_in_available == false` closes that gap. If no version of the package fixes the vulnerability anywhere upstream, there is nothing to upgrade or pin to, so Snyk will agree it is unfixable. This is deliberately **conservative** and under-selects: a vulnerability with an upstream fix that your tree cannot reach (a transitive dependency pinned by a parent) is genuinely unfixable for you but is skipped here. Use `--include-fixed-in-available` to pick those up, understanding some of the resulting ignores may be disregarded.

A blank or unrecognised `fixed_in_available` is treated as *unknown*, not false, and the row is skipped.

Residual gap: Snyk patches. `isPatchable` is not an Export API column, so an npm issue with no upstream fix but an available Snyk patch would still be selected here and its ignore disregarded. Rare, but it is the one case this pairing cannot catch.

### When nothing matches

If a scope matches zero issues, the script prints what the export actually contained so a label mismatch is obvious rather than looking like an empty result:

```
Org 1b68fd5f…: 0 non-fixable issue(s) matched.
  computed_fixability seen: Partially Fixable=17, Fixable=41, Not Applicable=6
  issue_type seen: Vulnerability=58, License=6
  fixed_in_available seen: true=58, false=6
```

Compare those labels against your `--fixability`, `--issue-type`, and `--include-fixed-in-available` settings.

### Rate limits and freshness

Export data refreshes roughly every two hours, and the export `POST` endpoint allows **20 requests per hour**. One export is started per `--org-id` / `--group-id`, so keep the scope list short and do not schedule runs more often than every couple of hours.

## Setup

No pip packages (stdlib only).

```sh
export SNYK_TOKEN="your-token"
# Optional, for EU or other regions:
# export SNYK_API_BASE_URL="https://api.eu.snyk.io"
```

Optional env aliases:

- `SNYK_INTRODUCED_FROM` / `SNYK_INTRODUCED_TO`
- `SNYK_UPDATED_FROM` / `SNYK_UPDATED_TO`
- `SNYK_REPORT_CSV`

> **Scope is command line only.** `--group-id` and `--org-id` are the *only* way to set scope. `SNYK_GROUP_ID`, `SNYK_GROUP_IDS`, `SNYK_ORG_ID`, and `SNYK_ORG_IDS` are deliberately not read, and the script warns on stderr if it sees them. Earlier versions merged those variables on top of the CLI arguments, which meant a leftover `SNYK_GROUP_ID` silently turned an org-scoped run into a group-wide one. The scope of a run is now always visible in the command that started it.

## State CSV

Default path: **`ignore_non_fixable_progress.csv`** in the **current working directory** (override with **`--state-csv`** / **`-s`**).

Columns:

| Column | Description |
|--------|-------------|
| `group_id` | Group UUID from the export (empty when the export did not report one) |
| `org_id` | Organization UUID (`ORG_PUBLIC_ID`) |
| `project_id` | Project UUID (`PROJECT_PUBLIC_ID`) |
| `issue_id` | Snyk issue ID (`PROBLEM_ID`) |
| `status` | **`PENDING`** (not yet ignored) or **`IGNORED`** (ignore created or treated as already present) |

After each successful ignore (or “already ignored” response), the row is updated and the file is rewritten so you can **`--resume`** safely.

## Report CSV

The state CSV holds only UUIDs, so reviewing it means looking everything up. Pass **`--report-csv PATH`** (or set `SNYK_REPORT_CSV`) to also get a readable list of every issue the export matched:

| Column | Description |
|--------|-------------|
| `scope_kind` / `scope_id` | Which `--org-id` or `--group-id` export produced the row |
| `group_id`, `org_id`, `project_id`, `issue_id` | Same identifiers as the state CSV |
| `project_name` | e.g. `acme/web:package.json` |
| `problem_title` | e.g. `Prototype Pollution` |
| `package_name_and_version` | e.g. `lodash@4.17.11` |
| `issue_severity` | `critical`, `high`, `medium`, `low` |
| `issue_type`, `issue_status`, `computed_fixability`, `fixed_in_available` | The values the row was filtered on |
| `fixed_in_version` | Blank for these rows, since a matched issue has no fixed version |
| `issue_url` | Direct link to the issue in the Snyk UI |

Two things to know about it:

- It is written **immediately after the export**, before any ignores are created, so you still get it if an ignore call fails partway through. That makes it a list of **candidates**, not outcomes — the state CSV stays the record of `PENDING` vs `IGNORED`.
- It is **skipped with `--resume`** (which runs no export). The script warns rather than failing.

Pair it with `--dry-run` to review what would be ignored before doing it:

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" --dry-run \
  --report-csv non_fixable_report.csv
```

## Usage

**Export + dry-run** (writes/updates the CSV with `PENDING`, does not call the ignore API):

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" --dry-run
```

**Export + create ignores** for that org:

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>"
```

**Group** (single group-scoped export covering all its orgs):

```sh
python ignore_non_fixable_vulns.py --group-id "<GROUP_UUID>"
```

**Resume** after interruption (uses existing CSV only, no new export):

```sh
python ignore_non_fixable_vulns.py --resume
```

`--resume` is a convenience for skipping a slow re-export when you know work is outstanding. It is not required for correctness: a normal export run merges into the existing CSV and then processes every `PENDING` row, so it finishes interrupted work as well.

Custom CSV path:

```sh
python ignore_non_fixable_vulns.py -s /path/to/state.csv --org-id "<ORG_UUID>"
python ignore_non_fixable_vulns.py --resume -s /path/to/state.csv
```

**Limit to specific projects** (filters the export results):

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" \
  --project-id "<PROJ_A>" --project-id "<PROJ_B>"
```

**Incremental run** — only issues touched in the last day. Supplying `--updated-from` drops the catch-all `--introduced-from` default so the two windows are not ANDed:

```sh
python ignore_non_fixable_vulns.py --group-id "<GROUP_UUID>" \
  --updated-from "2026-09-08T00:00:00Z"
```

**Also ignore partially fixable issues:**

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" \
  --fixability "No Fix Supported" --fixability "Partially Fixable"
```

A partially fixable issue has upgradable paths, so Snyk may treat it as fixable and disregard an ignore created with the default `disregardIfFixable: true` — the ignore would exist but never apply. Test one project before rolling this out, and expect to need `--no-disregard-if-fixable` for that tier (which also means those ignores will not lapse on their own once a full fix lands).

**Also ignore issues with an upstream fix you cannot reach** (a transitive dependency pinned by a parent). Same caveat as above — some of these ignores may be disregarded:

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" --include-fixed-in-available
```

**Reason text** (default: `No fix available`):

```sh
python ignore_non_fixable_vulns.py --org-id "<ORG_UUID>" --reason "No fix available"
```

## Reverting (`--revert`)

`--revert` undoes a previous run. It reads the state CSV, deletes the ignore for every row marked `IGNORED` via `DELETE /v1/org/{orgId}/project/{projectId}/ignore/{issueId}`, and records progress in a **separate** CSV so the input is never modified.

```sh
# Preview first.
python ignore_non_fixable_vulns.py --revert --dry-run \
  -s ignore_non_fixable_progress.csv --unignore-csv unignore_progress.csv

# Then for real.
python ignore_non_fixable_vulns.py --revert \
  -s ignore_non_fixable_progress.csv --unignore-csv unignore_progress.csv
```

Behavior worth knowing:

- Only `IGNORED` rows are touched. A `PENDING` row was never ignored, so there is nothing to delete.
- The unignore CSV has the same columns as the state CSV, with status `PENDING` then `UNIGNORED`. It is rewritten after every deletion, so an interrupted revert can simply be re-run and will skip what it already removed.
- A `404` from the delete means the ignore is already gone. That is the desired end state, so the row is marked `UNIGNORED` rather than failing.
- The V1 delete removes every path for that issue on that project, which matches how the ignores were created (`ignorePath: "*"`).
- `--revert` cannot be combined with `--resume`, and rejects `--group-id` / `--org-id`, because the scope comes entirely from the CSV.
- `--unignore-csv` defaults to `unignore_progress.csv` and can be set with `SNYK_UNIGNORE_CSV`.

## GitHub Actions

Two workflows ship with the tool:

| Workflow | Purpose |
|----------|---------|
| [`ignore-non-fixable-vulns.yml`](.github/workflows/ignore-non-fixable-vulns.yml) | Export, then create ignores. Manual or scheduled. |
| [`revert-non-fixable-ignores.yml`](.github/workflows/revert-non-fixable-ignores.yml) | Delete ignores created by a previous run. Manual only. |

A sample scheduled workflow lives at [`.github/workflows/ignore-non-fixable-vulns.yml`](.github/workflows/ignore-non-fixable-vulns.yml). It runs on manual dispatch (optional schedule), exports issues, creates ignores for the non-fixable ones, uploads a report of what matched, and persists progress between runs via a workflow artifact.

The workflow defines two run steps: **org** (enabled by default) and **group** (commented out). Comment out the step you do not need, and only one should be active.

Each step reads only its own repository variables, inside that step's `env` block, and converts them into explicit `--org-id` / `--group-id` flags. Scope variables are deliberately **not** in the job-level `env`, because job-level variables apply to whichever step is uncommented, so a `SNYK_GROUP_ID` set there would widen an org-scoped run. Commenting a step out now genuinely disables that scope.

### Repository configuration

Set repository **secrets** and **variables** as needed. Unset or empty repository variables are ignored; the script uses its built-in defaults (GitHub Actions passes unset vars as empty strings).

| Name | Type | Required | Purpose |
|------|------|----------|---------|
| `SNYK_TOKEN` | Secret | Yes | Snyk API token with report-read and ignore permissions |
| `SNYK_ORG_ID` | Variable | Yes* | Organization UUID. Read by the **org step only** and passed as `--org-id` |
| `SNYK_ORG_IDS` | Variable | No | Comma-separated org UUIDs, each passed as its own `--org-id` |
| `SNYK_GROUP_ID` | Variable | Yes† | Group UUID. Read by the **group step only** and passed as `--group-id` |
| `SNYK_GROUP_IDS` | Variable | No | Comma-separated group UUIDs, each passed as its own `--group-id` |
| `SNYK_API_BASE_URL` | Variable | No | API host (e.g. `https://api.eu.snyk.io`); default US |
| `SNYK_REST_VERSION` | Variable | No | REST version query param; default `2024-10-15` |
| `SNYK_INTRODUCED_FROM` | Variable | No | Export date filter; default `2010-01-01T00:00:00Z` |
| `SNYK_INTRODUCED_TO` | Variable | No | Export date filter upper bound |
| `SNYK_UPDATED_FROM` | Variable | No | Export date filter for incremental runs |
| `SNYK_UPDATED_TO` | Variable | No | Export date filter upper bound |

\* Required when using the **org** step (default).

† Required when using the **group** step (comment in org step, uncomment group step).

### How the workflow runs

1. **Find** the most recent completed run of this workflow on the same branch (`gh run list`), excluding the current one.
2. **Restore** that run's `ignore_non_fixable_progress.csv` artifact. Missing or expired is fine — the run just starts from scratch.
3. **Export** using the active step (org or group). That step turns its own repository variables into explicit `--org-id` / `--group-id` flags, one per ID. If none are set the script exits with an error rather than doing nothing.
4. **Create ignores** for each `PENDING` row (same as a local run without `--dry-run`).
5. **Upload** the updated CSV as artifact `snyk-ignore-progress` (90-day retention) so the next run continues where it left off, and the report as `snyk-ignore-report-<run_id>`.

Both CSVs are gitignored locally and in CI; only the progress artifact carries state across runs.

> **Why `--resume` is not used in CI.** The export path already merges into the restored CSV without downgrading `IGNORED`, then processes *every* `PENDING` row — including any a crashed run left behind. So a plain export both finishes interrupted work and picks up newly introduced issues. Branching to `--resume` whenever the CSV existed would have been worse than useless: after the first successful run every row is `IGNORED`, so the workflow would resume, find nothing to do, and never discover another issue.

Restoring across runs needs `actions: read` permission plus `run-id` and `github-token` on `download-artifact` — v4 only sees the current run's artifacts by default, so without these the restore silently fails and every run starts fresh. The report uses a run-scoped artifact name so it is never restored back into the workspace on a later run.

### Triggers and safety

- **Schedule:** uncomment `cron: "0 7 * * *"` in the workflow for daily 07:00 UTC (adjust as needed). Do not schedule more often than every two hours — see the rate limit note above.
- **Manual:** **Actions → Snyk ignore non-fixable vulns → Run workflow**.
- **Concurrency:** one run at a time (`cancel-in-progress: false`) so two jobs do not write the same CSV artifact concurrently.
- **Timeout:** 360 minutes; increase for very large groups or narrow the scope with `--project-id` in the workflow.

### Customizing the workflow

Common edits:

- **Group instead of org** — comment out the org step, uncomment the group step, set `SNYK_GROUP_ID` (and optionally `SNYK_GROUP_IDS`). Leaving `SNYK_ORG_ID` set does no harm, because the commented-out step never reads it.
- **Dry-run gate** — add `--dry-run` to the `python` command, then review the `snyk-ignore-report-<run_id>` artifact before enabling live ignores.
- **Forget past work** — delete the `snyk-ignore-progress` artifact in the Actions UI. Every run exports regardless; this only clears the record of what was already ignored, so the next run re-attempts them all.

### Revert workflow

[`revert-non-fixable-ignores.yml`](.github/workflows/revert-non-fixable-ignores.yml) is **manual only** and reads its input from the repository rather than from an artifact, so what it will undo is reviewable in a diff before it runs.

1. Download the `snyk-ignore-progress` artifact from the run you want to undo.
2. Commit the CSV as [`data/ignore_non_fixable_progress.csv`](data/).
3. Run **Actions → Snyk revert non-fixable ignores → Run workflow**.

Inputs:

| Input | Default | Purpose |
|-------|---------|---------|
| `dry_run` | `true` | Preview only. Uncheck to actually delete. |
| `confirm` | empty | Must be exactly `revert` when `dry_run` is off, otherwise the job fails before touching anything. |

The job prints how many `IGNORED` rows the CSV holds before doing anything, fails early if the CSV is missing, and uploads its results as `snyk-unignore-progress-<run_id>`. It shares the `snyk-ignore-non-fixable` concurrency group with the ignore workflow so a revert cannot race a run that is creating ignores.

Because the revert writes to a separate file, the committed input CSV is never modified. Re-running is safe and only retries what is still outstanding.

## Notes

- Export jobs are polled every **15 seconds** (`--poll-seconds`) and abandoned after **1 hour** (`--export-timeout`).
- Rows are de-duplicated on `(org_id, project_id, issue_id)`, so an issue reported on several paths yields a single ignore and a single report row.
- The report CSV is deliberately a separate file: `load_state_csv` validates the state header exactly, so adding columns there would reject every existing progress CSV and CI artifact.
- **`--expires`** is optional; omit it and rely on **`disregardIfFixable`** unless you need a calendar end date.
- For VS Code/Cursor debugging, set `SNYK_TOKEN` in `data/.env` and pass **`--org-id`** / **`--group-id`** on the command line (see repo `.vscode/launch.json`).
