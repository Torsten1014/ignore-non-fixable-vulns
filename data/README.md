# data

Input for the **Snyk revert non-fixable ignores** workflow.

Commit the progress CSV you want to undo here as:

```
data/ignore_non_fixable_progress.csv
```

That file is produced by the main workflow and published as the
`snyk-ignore-progress` artifact. To revert a run, download that artifact, drop
the CSV in this directory, commit it, then run the revert workflow.

Every row with status `IGNORED` has its ignore deleted through
`DELETE /v1/org/{orgId}/project/{projectId}/ignore/{issueId}`. Rows with any
other status are left alone.

The workflow writes `unignore_progress.csv` and uploads it as an artifact. It
is not committed back here, so this directory only ever holds input.

Unlike the state CSV at the repository root, files in this directory are
**not** gitignored, because the revert workflow reads its input from the
checkout rather than from an artifact. Bear in mind the CSV contains org,
project, and issue identifiers.
