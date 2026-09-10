#!/usr/bin/env python3
"""
Create Snyk project ignores for vulnerabilities that have no supported fix.

Sources issues from the REST Export API (``issues`` dataset) and treats an
issue as non-fixable when its ``computed_fixability`` column is
``No Fix Supported`` *and* ``fixed_in_available`` is false — the pairing that
matches what Snyk's ignore logic considers unfixable. Ignores are created with
the V1 API flag
``disregardIfFixable`` so they lapse once a fix appears. Work is tracked in a
CSV so an interrupted run can resume.

Author: Torsten Cannell, torsten.cannell@snyk.io
Revision History:
- 2026-05-05: Initial version (stdlib HTTP client).
- 2026-05-05: Resolve org/project from SNYK_* env when CLI args omitted (VS Code envFile).
- 2026-05-05: Omit expires in V1 ignore POST unless --expires set (422 on empty).
- 2026-05-06: Group/org discovery, REST project listing, CSV state + resume.
- 2026-05-06: Fix REST pagination (links.next as {\"href\": ...} JSON:API).
- 2026-05-06: REST Accept application/vnd.api+json, Link header + starting_after fallback.
- 2026-05-06: Merge V1 /org/.../dependencies project discovery; JSON:API included; Link regex.
- 2026-07-17: Single SNYK_API_BASE_URL host; append /v1 or /rest per endpoint.
- 2026-07-17: Treat empty optional env vars as unset (GitHub Actions passes "").
- 2026-09-09: Replace project/aggregated-issues discovery with the Export API;
  define non-fixable as computed_fixability == "No Supported Fix".
- 2026-09-09: Add --report-csv for a reviewable list of the matched issues.
- 2026-09-09: Match "No Fix Supported" (the value the Export API actually
  emits; the docs say "No Supported Fix") and report label tallies on a miss.
- 2026-09-09: Also require fixed_in_available to be false, so the selection
  matches what disregardIfFixable treats as unfixable; classify ignore
  conflicts by HTTP status instead of substring-matching "409".
- 2026-09-10: Scope comes only from --group-id / --org-id. SNYK_GROUP_ID(S)
  and SNYK_ORG_ID(S) are no longer merged in, because a stray group variable
  silently turned an org-scoped run into a group-wide one.
- 2026-09-10: Add --revert to delete previously created ignores, driven by the
  state CSV and tracked in a separate unignore CSV.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

DEFAULT_API_HOST = "https://api.snyk.io"
DEFAULT_REST_VERSION = "2024-10-15"
DEFAULT_REASON = "No fix available"
DEFAULT_STATE_CSV = "ignore_non_fixable_progress.csv"
DEFAULT_UNIGNORE_CSV = "unignore_progress.csv"

# The Export API requires at least one date filter; this default is early
# enough to cover every issue Snyk holds.
DEFAULT_INTRODUCED_FROM = "2010-01-01T00:00:00Z"
# The Export API emits "No Fix Supported"; Snyk's docs write the same value as
# "No Supported Fix". Accept both so a wording change on either side does not
# silently match zero rows.
DEFAULT_FIXABILITY = ("No Fix Supported", "No Supported Fix")
DEFAULT_ISSUE_TYPE = "Vulnerability"
DEFAULT_ISSUE_STATUS = "Open"
DEFAULT_POLL_SECONDS = 15
DEFAULT_EXPORT_TIMEOUT_SECONDS = 3600

# The columns needed to build an ignore, the columns filtered on, and enough
# human-readable context for --report-csv to be reviewable without lookups.
EXPORT_COLUMNS = (
    "GROUP_PUBLIC_ID",
    "ORG_PUBLIC_ID",
    "PROJECT_PUBLIC_ID",
    "PROBLEM_ID",
    "ISSUE_TYPE",
    "ISSUE_STATUS",
    "COMPUTED_FIXABILITY",
    "FIXED_IN_AVAILABLE",
    "FIXED_IN_VERSION",
    "PROBLEM_TITLE",
    "ISSUE_SEVERITY",
    "PROJECT_NAME",
    "PACKAGE_NAME_AND_VERSION",
    "ISSUE_URL",
)

TRUTHY_LABELS = frozenset({"true", "yes", "1"})
FALSEY_LABELS = frozenset({"false", "no", "0"})

# Deliberately not read. Kept only so a run can warn when they are set, since
# they used to widen scope invisibly.
SCOPE_ENV_VARS = (
    "SNYK_GROUP_ID",
    "SNYK_GROUP_IDS",
    "SNYK_ORG_ID",
    "SNYK_ORG_IDS",
)

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

CSV_COLUMNS = ("group_id", "org_id", "project_id", "issue_id", "status")
STATUS_PENDING = "PENDING"
STATUS_IGNORED = "IGNORED"
STATUS_UNIGNORED = "UNIGNORED"

# Kept separate from CSV_COLUMNS: load_state_csv validates the state header
# exactly, so widening that file would reject every existing progress CSV.
REPORT_COLUMNS = (
    "scope_kind",
    "scope_id",
    "group_id",
    "org_id",
    "project_id",
    "project_name",
    "issue_id",
    "problem_title",
    "package_name_and_version",
    "issue_severity",
    "issue_type",
    "issue_status",
    "computed_fixability",
    "fixed_in_available",
    "fixed_in_version",
    "issue_url",
)


def env_or_default(key: str, default: str) -> str:
    """Return env var value if set and non-empty, else *default*."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    stripped = raw.strip()
    return stripped if stripped else default


def resolve_snyk_api_bases(raw: str) -> tuple[str, str]:
    """
    Return (v1_base, rest_base) from SNYK_API_BASE_URL / --api-base-url.

    Accepts a host root such as ``https://api.eu.snyk.io`` or ``api.eu.snyk.io``.
    Trailing ``/v1`` or ``/rest`` suffixes are stripped if present.
    """
    host = raw.strip().rstrip("/") or DEFAULT_API_HOST.strip().rstrip("/")
    while True:
        stripped = False
        for suffix in ("/v1", "/rest"):
            if host.endswith(suffix):
                host = host[: -len(suffix)].rstrip("/")
                stripped = True
        if not stripped:
            break
    if not re.match(r"^https?://", host, re.IGNORECASE):
        host = f"https://{host}"
    return f"{host}/v1", f"{host}/rest"


def normalize_label(value: str) -> str:
    """
    Fold a display label to a comparable form.

    Case and separators only (``No Fix Supported`` == ``no_fix_supported``);
    word order still has to match.
    """
    return re.sub(r"[\s_\-]+", " ", value.strip().lower())


def parse_bool_label(value: str) -> bool | None:
    """
    Interpret a boolean column from the export CSV.

    Returns None for a blank or unrecognised value so callers can treat
    "unknown" differently from "false" rather than guessing.
    """
    token = normalize_label(value)
    if token in TRUTHY_LABELS:
        return True
    if token in FALSEY_LABELS:
        return False
    return None


class SnykApiError(RuntimeError):
    """
    An HTTP error from the Snyk API, with the status code preserved.

    Subclasses RuntimeError so existing handlers still catch it; the status is
    kept so callers can branch on the code instead of grepping the message.
    """

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def describe_http_error(exc: urllib.error.HTTPError) -> str:
    """Return the most useful human-readable text from an error response."""
    detail = exc.read().decode(errors="replace")
    try:
        parsed = json.loads(detail)
    except json.JSONDecodeError:
        return detail or str(exc)
    if isinstance(parsed, dict):
        errors = parsed.get("errors")
        if isinstance(errors, list) and errors:
            parts = []
            for err in errors:
                if not isinstance(err, dict):
                    continue
                text = err.get("detail") or err.get("title")
                if text:
                    parts.append(str(text))
            if parts:
                return "; ".join(parts)
        return str(parsed.get("message") or parsed.get("error") or parsed)
    return str(parsed)


def request_json(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """Perform a V1 API request with optional JSON body and parse the response."""
    data = None if body is None else json.dumps(body).encode()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise SnykApiError(exc.code, describe_http_error(exc)) from exc


def request_rest(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """Perform a Snyk REST (JSON:API) request and parse the response."""
    data = None if body is None else json.dumps(body).encode()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.api+json",
    }
    if body is not None:
        headers["Content-Type"] = "application/vnd.api+json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise SnykApiError(exc.code, describe_http_error(exc)) from exc


def scope_path_segment(scope_kind: str) -> str:
    """Return the REST path segment for a ``group`` or ``org`` scope."""
    return "groups" if scope_kind == "group" else "orgs"


def start_export(
    rest_base: str,
    rest_version: str,
    scope_kind: str,
    scope_id: str,
    token: str,
    *,
    filters: dict[str, Any],
) -> str:
    """Start an ``issues`` CSV export and return the export job ID."""
    qs = urllib.parse.urlencode({"version": rest_version})
    url = (
        f"{rest_base}/{scope_path_segment(scope_kind)}/{scope_id}/export?{qs}"
    )
    body = {
        "data": {
            "type": "resource",
            "attributes": {
                "dataset": "issues",
                "formats": ["csv"],
                "columns": list(EXPORT_COLUMNS),
                "filters": filters,
            },
        }
    }
    data = request_rest("POST", url, token, body)
    export_id = ((data or {}).get("data") or {}).get("id")
    if not export_id:
        raise RuntimeError(f"Export API did not return an export id: {data!r}")
    return str(export_id)


def wait_for_export(
    rest_base: str,
    rest_version: str,
    scope_kind: str,
    scope_id: str,
    export_id: str,
    token: str,
    *,
    poll_seconds: int,
    timeout_seconds: int,
    quiet: bool,
) -> None:
    """Poll the export job until it reaches FINISHED, or raise."""
    qs = urllib.parse.urlencode({"version": rest_version})
    url = (
        f"{rest_base}/{scope_path_segment(scope_kind)}/{scope_id}"
        f"/jobs/export/{export_id}?{qs}"
    )
    deadline = time.monotonic() + timeout_seconds
    last_status = ""
    while True:
        data = request_rest("GET", url, token)
        attrs = ((data or {}).get("data") or {}).get("attributes") or {}
        status = str(attrs.get("status") or "").upper()
        if status == "FINISHED":
            return
        if status.startswith("ERROR"):
            raise RuntimeError(f"Export {export_id} finished with status {status}.")
        if not quiet and status and status != last_status:
            print(f"  export {export_id}: {status}")
            last_status = status
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Export {export_id} did not finish within {timeout_seconds}s "
                f"(last status: {status or 'unknown'})."
            )
        time.sleep(poll_seconds)


def fetch_export_result_urls(
    rest_base: str,
    rest_version: str,
    scope_kind: str,
    scope_id: str,
    export_id: str,
    token: str,
) -> tuple[list[str], int]:
    """Return the signed CSV download URLs and the reported row count."""
    qs = urllib.parse.urlencode({"version": rest_version})
    url = (
        f"{rest_base}/{scope_path_segment(scope_kind)}/{scope_id}"
        f"/export/{export_id}?{qs}"
    )
    data = request_rest("GET", url, token)
    attrs = ((data or {}).get("data") or {}).get("attributes") or {}
    row_count = attrs.get("row_count")
    urls: list[str] = []
    for item in attrs.get("results") or []:
        if isinstance(item, str) and item.startswith(("http://", "https://")):
            urls.append(item)
            continue
        if not isinstance(item, dict):
            continue
        for key in ("url", "href", "location", "signed_url"):
            candidate = item.get(key)
            if isinstance(candidate, str) and candidate.startswith(
                ("http://", "https://")
            ):
                urls.append(candidate)
                break
    return urls, int(row_count or 0)


def iter_export_csv(url: str) -> Iterator[dict[str, str]]:
    """
    Stream one exported CSV file as dicts keyed by lower-cased column name.

    The URL is pre-signed by object storage, so no Authorization header is sent.
    """
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=600) as resp:
        path = urllib.parse.urlparse(url).path.lower()
        gzipped = (
            resp.headers.get("Content-Encoding", "").lower() == "gzip"
            or path.endswith(".gz")
        )
        binary = gzip.GzipFile(fileobj=resp) if gzipped else resp
        text = io.TextIOWrapper(
            binary, encoding="utf-8-sig", errors="replace", newline=""
        )
        for raw in csv.DictReader(text):
            yield {
                key.strip().lower(): (value or "").strip()
                for key, value in raw.items()
                if key
            }


class ExportMatch(NamedTuple):
    """
    What one scope's export yielded.

    ``state_rows`` and ``report_rows`` are kept apart because state rows
    round-trip through the narrow state CSV while report rows carry the
    descriptive columns used only for review. The tallies cover every exported
    row and exist to explain a zero-match run.
    """

    state_rows: list[dict[str, str]]
    report_rows: list[dict[str, str]]
    fixability_seen: Counter[str]
    issue_type_seen: Counter[str]
    fixed_in_available_seen: Counter[str]


def format_label_counts(counts: Counter[str]) -> str:
    """Render a label tally as ``Fixable=41, Partially Fixable=17``."""
    if not counts:
        return "(none)"
    return ", ".join(
        f"{label or '(blank)'}={n}" for label, n in counts.most_common()
    )


def collect_rows_from_export(
    urls: list[str],
    *,
    scope_kind: str,
    scope_id: str,
    fixability: set[str],
    issue_types: set[str],
    issue_statuses: set[str],
    project_filter: set[str] | None,
    require_unfixed_upstream: bool,
) -> ExportMatch:
    """Filter exported issue rows down to non-fixable vulns."""
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, str]] = []
    report_rows: list[dict[str, str]] = []
    fixability_seen: Counter[str] = Counter()
    issue_type_seen: Counter[str] = Counter()
    fixed_in_available_seen: Counter[str] = Counter()
    for url in urls:
        for record in iter_export_csv(url):
            fixability_seen[record.get("computed_fixability", "")] += 1
            issue_type_seen[record.get("issue_type", "")] += 1
            fixed_in_available_seen[record.get("fixed_in_available", "")] += 1
            if normalize_label(record.get("computed_fixability", "")) not in fixability:
                continue
            # An upstream fixed version means Snyk may still find an upgrade
            # path and disregard the ignore, so require it to be absent. A
            # blank or unrecognised value is treated as unknown, not false.
            if require_unfixed_upstream:
                if parse_bool_label(record.get("fixed_in_available", "")) is not False:
                    continue
            if (
                issue_types
                and normalize_label(record.get("issue_type", "")) not in issue_types
            ):
                continue
            if (
                issue_statuses
                and normalize_label(record.get("issue_status", "")) not in issue_statuses
            ):
                continue
            org_id = record.get("org_public_id", "")
            project_id = record.get("project_public_id", "")
            issue_id = record.get("problem_id", "")
            if not (org_id and project_id and issue_id):
                continue
            if project_filter is not None and project_id not in project_filter:
                continue
            key = (org_id, project_id, issue_id)
            if key in seen:
                continue
            seen.add(key)
            group_id = record.get("group_public_id", "")
            if not group_id and scope_kind == "group":
                group_id = scope_id
            rows.append(
                {
                    "group_id": group_id,
                    "org_id": org_id,
                    "project_id": project_id,
                    "issue_id": issue_id,
                    "status": STATUS_PENDING,
                }
            )
            report_rows.append(
                {
                    "scope_kind": scope_kind,
                    "scope_id": scope_id,
                    "group_id": group_id,
                    "org_id": org_id,
                    "project_id": project_id,
                    "project_name": record.get("project_name", ""),
                    "issue_id": issue_id,
                    "problem_title": record.get("problem_title", ""),
                    "package_name_and_version": record.get(
                        "package_name_and_version", ""
                    ),
                    "issue_severity": record.get("issue_severity", ""),
                    "issue_type": record.get("issue_type", ""),
                    "issue_status": record.get("issue_status", ""),
                    "computed_fixability": record.get("computed_fixability", ""),
                    "fixed_in_available": record.get("fixed_in_available", ""),
                    "fixed_in_version": record.get("fixed_in_version", ""),
                    "issue_url": record.get("issue_url", ""),
                }
            )
    return ExportMatch(
        rows,
        report_rows,
        fixability_seen,
        issue_type_seen,
        fixed_in_available_seen,
    )


def add_ignore(
    api_base: str,
    org_id: str,
    project_id: str,
    issue_id: str,
    token: str,
    *,
    reason: str,
    reason_type: str,
    disregard_if_fixable: bool,
    ignore_path: str,
    expires: str | None = None,
) -> Any:
    """POST a new ignore rule for one issue."""
    url = f"{api_base}/org/{org_id}/project/{project_id}/ignore/{issue_id}"
    payload: dict[str, Any] = {
        "ignorePath": ignore_path,
        "reason": reason,
        "reasonType": reason_type,
        "disregardIfFixable": disregard_if_fixable,
    }
    if expires is not None and expires.strip():
        payload["expires"] = expires.strip()
    return request_json("POST", url, token, payload)


def delete_ignore(
    api_base: str,
    org_id: str,
    project_id: str,
    issue_id: str,
    token: str,
) -> Any:
    """
    Remove every ignore rule for one issue on one project.

    The V1 endpoint deletes all paths for the issue, which matches how
    ``add_ignore`` creates them with ``ignorePath: "*"``.
    """
    url = f"{api_base}/org/{org_id}/project/{project_id}/ignore/{issue_id}"
    return request_json("DELETE", url, token, None)


def row_key(row: dict[str, str]) -> tuple[str, str, str]:
    """Stable tuple for de-duplication."""
    return (row["org_id"], row["project_id"], row["issue_id"])


def load_state_csv(path: Path) -> list[dict[str, str]]:
    """Load CSV rows; validate columns."""
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    rows: list[dict[str, str]] = []
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames != list(CSV_COLUMNS):
        raise ValueError(
            f"CSV header must be exactly: {', '.join(CSV_COLUMNS)} "
            f"(got {reader.fieldnames})"
        )
    for raw in reader:
        rows.append({k: (raw.get(k) or "").strip() for k in CSV_COLUMNS})
    return rows


def save_state_csv(path: Path, rows: list[dict[str, str]]) -> None:
    """Atomically write CSV (temp file + replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for row in sorted(rows, key=lambda r: row_key(r)):
            writer.writerow({k: row[k] for k in CSV_COLUMNS})
    tmp.replace(path)


def save_report_csv(path: Path, rows: list[dict[str, str]]) -> None:
    """Write the reviewable report of every issue the export matched."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(REPORT_COLUMNS))
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda r: (r["org_id"], r["project_id"], r["issue_id"]),
        ):
            writer.writerow({k: row.get(k, "") for k in REPORT_COLUMNS})
    tmp.replace(path)


def merge_pending_rows(
    existing: list[dict[str, str]],
    new_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Insert new PENDING rows; never downgrade IGNORED."""
    by_key: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in existing:
        by_key[row_key(row)] = dict(row)

    for row in new_rows:
        key = row_key(row)
        if key not in by_key:
            by_key[key] = dict(row)
            continue
        cur = by_key[key]
        if cur.get("status") == STATUS_IGNORED:
            continue
        if cur.get("status") == STATUS_PENDING:
            if not cur.get("group_id") and row.get("group_id"):
                cur["group_id"] = row["group_id"]
    return list(by_key.values())


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Export Snyk issues, keep the ones whose computed_fixability is "
            "'No Fix Supported' and whose fixed_in_available is false, record "
            "them in a CSV, create ignores with disregardIfFixable, and "
            "resume from the CSV if interrupted."
        )
    )
    parser.add_argument(
        "--group-id",
        action="append",
        default=[],
        metavar="UUID",
        help=(
            "Snyk Group ID (repeatable). One group-scoped export per ID. "
            "Command line only: SNYK_GROUP_ID(S) is not read."
        ),
    )
    parser.add_argument(
        "--org-id",
        action="append",
        default=[],
        metavar="UUID",
        help=(
            "Snyk Organization ID (repeatable). One org-scoped export per ID. "
            "Command line only: SNYK_ORG_ID(S) is not read."
        ),
    )
    parser.add_argument(
        "--project-id",
        action="append",
        dest="project_filter",
        default=None,
        metavar="UUID",
        help="If set, keep only these project IDs from the export. Repeatable.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip the export; only process PENDING rows in the state CSV "
            "(use after an interrupted run)."
        ),
    )
    parser.add_argument(
        "--state-csv",
        "-s",
        default=DEFAULT_STATE_CSV,
        metavar="PATH",
        help=(
            "CSV path for queue/resume (default: %(default)s in the current "
            "working directory)."
        ),
    )
    parser.add_argument(
        "--revert",
        action="store_true",
        help=(
            "Undo mode. Read the state CSV and DELETE every ignore recorded "
            "as IGNORED, tracking progress in --unignore-csv. Runs no export "
            "and creates no ignores. Cannot be combined with --resume."
        ),
    )
    parser.add_argument(
        "--unignore-csv",
        default=env_or_default("SNYK_UNIGNORE_CSV", DEFAULT_UNIGNORE_CSV),
        metavar="PATH",
        help=(
            "Where --revert records its progress (default: %(default)s). Same "
            "columns as the state CSV, with status UNIGNORED once removed, so "
            "an interrupted revert can be re-run safely."
        ),
    )
    parser.add_argument(
        "--report-csv",
        default=env_or_default("SNYK_REPORT_CSV", ""),
        metavar="PATH",
        help=(
            "Also write a reviewable CSV of every matched issue (project name, "
            "package, severity, title, fixability, issue URL). Written right "
            "after the export, so it lists candidates rather than outcomes; "
            "the state CSV remains the record of PENDING vs IGNORED. Ignored "
            "with --resume, which runs no export."
        ),
    )
    parser.add_argument(
        "--api-base-url",
        default=env_or_default("SNYK_API_BASE_URL", DEFAULT_API_HOST),
        help=(
            "Snyk API host (e.g. https://api.snyk.io or api.eu.snyk.io). "
            "/v1 and /rest are appended per endpoint."
        ),
    )
    parser.add_argument(
        "--rest-version",
        default=env_or_default("SNYK_REST_VERSION", DEFAULT_REST_VERSION),
        help="REST API version query param for the Export API.",
    )
    parser.add_argument(
        "--introduced-from",
        default=env_or_default("SNYK_INTRODUCED_FROM", DEFAULT_INTRODUCED_FROM),
        metavar="YYYY-MM-DDTHH:MM:SSZ",
        help=(
            "Export filter: earliest issue introduction date (default: "
            "%(default)s). The Export API requires at least one date filter."
        ),
    )
    parser.add_argument(
        "--introduced-to",
        default=env_or_default("SNYK_INTRODUCED_TO", ""),
        metavar="YYYY-MM-DDTHH:MM:SSZ",
        help="Export filter: latest issue introduction date (optional).",
    )
    parser.add_argument(
        "--updated-from",
        default=env_or_default("SNYK_UPDATED_FROM", ""),
        metavar="YYYY-MM-DDTHH:MM:SSZ",
        help=(
            "Export filter: only issues updated since this time. Setting this "
            "drops the default --introduced-from window so incremental runs "
            "are not also bounded by introduction date."
        ),
    )
    parser.add_argument(
        "--updated-to",
        default=env_or_default("SNYK_UPDATED_TO", ""),
        metavar="YYYY-MM-DDTHH:MM:SSZ",
        help="Export filter: only issues updated before this time (optional).",
    )
    parser.add_argument(
        "--fixability",
        action="append",
        default=None,
        metavar="LABEL",
        help=(
            "computed_fixability value treated as non-fixable (repeatable, "
            f"case-insensitive; default: {' or '.join(DEFAULT_FIXABILITY)}). "
            "Use 'Partially Fixable' to widen the scope."
        ),
    )
    parser.add_argument(
        "--include-fixed-in-available",
        action="store_true",
        help=(
            "Also keep issues where fixed_in_available is true (a fixed "
            "version exists upstream but Snyk reports no supported fix). Snyk "
            "may still find an upgrade path for these and disregard the "
            "ignore. Off by default."
        ),
    )
    parser.add_argument(
        "--issue-type",
        action="append",
        default=None,
        metavar="LABEL",
        help=(
            "issue_type value to keep (repeatable, case-insensitive; default: "
            f"{DEFAULT_ISSUE_TYPE}). Pass an empty string to keep all types."
        ),
    )
    parser.add_argument(
        "--issue-status",
        action="append",
        default=None,
        metavar="LABEL",
        help=(
            "issue_status to export and keep (repeatable; default: "
            f"{DEFAULT_ISSUE_STATUS}). Valid values: Open, Resolved, Ignored."
        ),
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=DEFAULT_POLL_SECONDS,
        help="Seconds between export status checks (default: %(default)s).",
    )
    parser.add_argument(
        "--export-timeout",
        type=int,
        default=DEFAULT_EXPORT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="Give up on an export job after this long (default: %(default)s).",
    )
    parser.add_argument(
        "--reason",
        default=DEFAULT_REASON,
        help="Ignore reason text stored in Snyk (default: %(default)s).",
    )
    parser.add_argument(
        "--reason-type",
        choices=("temporary-ignore", "not-vulnerable", "wont-fix"),
        default="temporary-ignore",
        help="Snyk ignore classification (default: %(default)s).",
    )
    parser.add_argument(
        "--ignore-path",
        default="*",
        help="Scope of the ignore (default: %(default)s = all paths).",
    )
    parser.add_argument(
        "--no-disregard-if-fixable",
        action="store_true",
        help="Set disregardIfFixable to false (not recommended).",
    )
    parser.add_argument(
        "--expires",
        default=None,
        metavar="ISO8601",
        help="Optional calendar expiry (ISO 8601). Omitted by default.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Do not call the ignore API or mark rows IGNORED. The export still "
            "runs and writes PENDING rows to the state CSV."
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress on stdout.",
    )
    return parser.parse_args()


def warn_ignored_scope_env() -> None:
    """
    Warn that scope environment variables are no longer honoured.

    These used to be merged on top of ``--group-id`` / ``--org-id``, which
    meant a stray ``SNYK_GROUP_ID`` silently added a group-wide export to a
    run that looked org-scoped. Scope now comes only from the command line.
    """
    present = [name for name in SCOPE_ENV_VARS if os.environ.get(name, "").strip()]
    if not present:
        return
    print(
        f"Warning: ignoring {', '.join(present)}. Scope must be given with "
        "--group-id / --org-id so the run's scope is visible in the command.",
        file=sys.stderr,
    )


def label_set(
    values: list[str] | None,
    default: str | tuple[str, ...],
) -> set[str]:
    """
    Normalize repeatable label options.

    A default may list several accepted spellings. An explicit empty value on
    the command line disables the filter entirely.
    """
    if values is None:
        defaults = (default,) if isinstance(default, str) else default
        return {normalize_label(v) for v in defaults}
    return {normalize_label(v) for v in values if v.strip()}


def build_date_filters(args: argparse.Namespace) -> dict[str, Any]:
    """Build the Export API ``introduced`` / ``updated`` filters from CLI options."""
    introduced_from = args.introduced_from
    # The two windows are ANDed, so the catch-all introduced default would
    # otherwise tag along and muddy an explicitly requested updated window.
    if (args.updated_from or args.updated_to) and not args.introduced_to:
        if introduced_from.strip() == DEFAULT_INTRODUCED_FROM:
            introduced_from = ""

    filters: dict[str, Any] = {}
    for name, lower, upper in (
        ("introduced", introduced_from, args.introduced_to),
        ("updated", args.updated_from, args.updated_to),
    ):
        window = {}
        for bound, raw in (("from", lower), ("to", upper)):
            value = (raw or "").strip()
            if not value:
                continue
            if not TIMESTAMP_RE.match(value):
                raise ValueError(
                    f"--{name}-{bound} must look like YYYY-MM-DDTHH:MM:SSZ "
                    f"(got {value!r})"
                )
            window[bound] = value
        if window:
            filters[name] = window
    if not filters:
        raise ValueError(
            "The Export API requires at least one date filter: set "
            "--introduced-from/--introduced-to or --updated-from/--updated-to."
        )
    return filters


def run_exports(
    *,
    rest_base: str,
    rest_version: str,
    scopes: list[tuple[str, str]],
    filters: dict[str, Any],
    token: str,
    fixability: set[str],
    issue_types: set[str],
    issue_statuses: set[str],
    project_filter: set[str] | None,
    require_unfixed_upstream: bool,
    poll_seconds: int,
    export_timeout: int,
    quiet: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Run one export per scope and return (new PENDING rows, report rows)."""
    new_rows: list[dict[str, str]] = []
    report_rows: list[dict[str, str]] = []
    for scope_kind, scope_id in scopes:
        if not quiet:
            print(f"{scope_kind.capitalize()} {scope_id}: starting export.")
        export_id = start_export(
            rest_base, rest_version, scope_kind, scope_id, token, filters=filters
        )
        wait_for_export(
            rest_base,
            rest_version,
            scope_kind,
            scope_id,
            export_id,
            token,
            poll_seconds=poll_seconds,
            timeout_seconds=export_timeout,
            quiet=quiet,
        )
        urls, row_count = fetch_export_result_urls(
            rest_base, rest_version, scope_kind, scope_id, export_id, token
        )
        if not quiet:
            print(
                f"{scope_kind.capitalize()} {scope_id}: export {export_id} "
                f"ready ({row_count} row(s) in {len(urls)} file(s))."
            )
        if not urls:
            continue
        match = collect_rows_from_export(
            urls,
            scope_kind=scope_kind,
            scope_id=scope_id,
            fixability=fixability,
            issue_types=issue_types,
            issue_statuses=issue_statuses,
            project_filter=project_filter,
            require_unfixed_upstream=require_unfixed_upstream,
        )
        if not quiet:
            print(
                f"{scope_kind.capitalize()} {scope_id}: "
                f"{len(match.state_rows)} non-fixable issue(s) matched."
            )
            if not match.state_rows:
                # A label the filters do not recognise looks identical to an
                # empty result, so show what the export actually contained.
                print(
                    "  computed_fixability seen: "
                    f"{format_label_counts(match.fixability_seen)}"
                )
                print(
                    f"  issue_type seen: {format_label_counts(match.issue_type_seen)}"
                )
                print(
                    "  fixed_in_available seen: "
                    f"{format_label_counts(match.fixed_in_available_seen)}"
                )
        new_rows.extend(match.state_rows)
        report_rows.extend(match.report_rows)
    return new_rows, report_rows


def build_revert_queue(
    ignored_rows: list[dict[str, str]],
    existing: list[dict[str, str]],
) -> list[dict[str, str]]:
    """
    Build the unignore queue, preserving rows already marked UNIGNORED.

    Mirrors merge_pending_rows but in the opposite direction: a row that has
    already been reverted must never drop back to PENDING on a re-run.
    """
    done = {
        row_key(row)
        for row in existing
        if row.get("status") == STATUS_UNIGNORED
    }
    queue: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in ignored_rows:
        key = row_key(row)
        if key in queue:
            continue
        queue[key] = {
            "group_id": row.get("group_id", ""),
            "org_id": row["org_id"],
            "project_id": row["project_id"],
            "issue_id": row["issue_id"],
            "status": STATUS_UNIGNORED if key in done else STATUS_PENDING,
        }
    return list(queue.values())


def run_revert(
    *,
    api_base: str,
    state_path: Path,
    unignore_path: Path,
    token: str,
    dry_run: bool,
    quiet: bool,
) -> int:
    """Delete the ignores recorded in the state CSV, tracking progress separately."""
    if not state_path.is_file():
        print(
            f"Error: --revert needs an existing state CSV (looked for {state_path}).",
            file=sys.stderr,
        )
        return 1
    try:
        state_rows = load_state_csv(state_path)
    except ValueError as exc:
        print(f"Error reading state CSV: {exc}", file=sys.stderr)
        return 1

    ignored_rows = [r for r in state_rows if r.get("status") == STATUS_IGNORED]
    if not ignored_rows:
        print(
            f"Nothing to revert: no {STATUS_IGNORED} rows in {state_path}.",
            file=sys.stderr,
        )
        return 1

    existing: list[dict[str, str]] = []
    if unignore_path.is_file():
        try:
            existing = load_state_csv(unignore_path)
        except ValueError as exc:
            print(f"Error reading unignore CSV: {exc}", file=sys.stderr)
            return 1

    rows = build_revert_queue(ignored_rows, existing)
    save_state_csv(unignore_path, rows)
    pending = [r for r in rows if r.get("status") == STATUS_PENDING]
    if not quiet:
        print(
            f"Reverting ignores from {state_path}: {len(ignored_rows)} "
            f"{STATUS_IGNORED} row(s), {len(pending)} still to remove."
        )
        print(f"Unignore CSV: {unignore_path}")

    removed = 0
    already_gone = 0
    for row in pending:
        org_id = row["org_id"]
        project_id = row["project_id"]
        issue_id = row["issue_id"]

        if dry_run:
            if not quiet:
                print(
                    f"  [dry-run] would delete ignore {issue_id} "
                    f"({org_id}/{project_id})"
                )
            removed += 1
            continue

        try:
            delete_ignore(api_base, org_id, project_id, issue_id, token)
            row["status"] = STATUS_UNIGNORED
            removed += 1
            save_state_csv(unignore_path, rows)
            if not quiet:
                print(f"  unignored {issue_id}")
        except SnykApiError as exc:
            # Nothing there to delete is the desired end state, so treat it as
            # done rather than failing a re-run.
            if exc.status == 404:
                row["status"] = STATUS_UNIGNORED
                already_gone += 1
                save_state_csv(unignore_path, rows)
                if not quiet:
                    print(
                        f"  skip {issue_id} (no ignore found): {exc}",
                        file=sys.stderr,
                    )
            else:
                print(f"  Error unignoring {issue_id}: {exc}", file=sys.stderr)
                return 1
        except RuntimeError as exc:
            print(f"  Error unignoring {issue_id}: {exc}", file=sys.stderr)
            return 1

    if not quiet:
        print(
            f"Done. Ignores removed: {removed}; "
            f"already absent: {already_gone}. "
            f"Unignore file: {unignore_path}"
        )
    return 0


def main() -> int:
    """Entry point."""
    args = parse_args()
    token = os.environ.get("SNYK_TOKEN", "").strip()
    if not token:
        print("Error: SNYK_TOKEN environment variable is not set.", file=sys.stderr)
        return 1

    warn_ignored_scope_env()
    group_ids = list(args.group_id)
    org_ids = list(args.org_id)

    state_path = Path(args.state_csv).expanduser()
    report_path = (
        Path(args.report_csv).expanduser() if args.report_csv.strip() else None
    )
    api_base, rest_base = resolve_snyk_api_bases(args.api_base_url)
    rest_version = args.rest_version.strip() or DEFAULT_REST_VERSION
    disregard = not args.no_disregard_if_fixable

    if args.revert:
        if args.resume:
            print(
                "Error: --revert and --resume are mutually exclusive.",
                file=sys.stderr,
            )
            return 1
        if group_ids or org_ids:
            print(
                "Error: --revert works from the state CSV, so --group-id and "
                "--org-id are not accepted.",
                file=sys.stderr,
            )
            return 1
        return run_revert(
            api_base=api_base,
            state_path=state_path,
            unignore_path=Path(args.unignore_csv).expanduser(),
            token=token,
            dry_run=args.dry_run,
            quiet=args.quiet,
        )

    project_filter: set[str] | None = None
    if args.project_filter:
        project_filter = {p.strip() for p in args.project_filter if p.strip()}

    rows: list[dict[str, str]] = []
    if state_path.is_file():
        try:
            rows = load_state_csv(state_path)
        except ValueError as exc:
            print(f"Error reading state CSV: {exc}", file=sys.stderr)
            return 1

    if args.resume:
        if not rows:
            print(
                "Error: --resume requires an existing state CSV with rows.",
                file=sys.stderr,
            )
            return 1
        if not args.quiet:
            print(f"Resume mode: loaded {len(rows)} row(s) from {state_path}")
        if report_path is not None:
            print(
                "Warning: --report-csv is ignored with --resume (no export "
                "runs, so there is nothing to report).",
                file=sys.stderr,
            )
    else:
        if not group_ids and not org_ids:
            print(
                "Error: provide --group-id and/or --org-id to export, or use "
                "--resume with an existing state CSV.",
                file=sys.stderr,
            )
            return 1

        try:
            filters = build_date_filters(args)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        issue_statuses = label_set(args.issue_status, DEFAULT_ISSUE_STATUS)
        if args.issue_status is not None:
            status_values = [v.strip() for v in args.issue_status if v.strip()]
        else:
            status_values = [DEFAULT_ISSUE_STATUS]
        if status_values:
            filters["issue_status"] = status_values

        scopes: list[tuple[str, str]] = []
        for kind, ids in (("group", group_ids), ("org", org_ids)):
            for scope_id in ids:
                if (kind, scope_id) not in scopes:
                    scopes.append((kind, scope_id))

        if not args.quiet:
            print(f"Exporting issues for {len(scopes)} scope(s).")

        try:
            discovered, report_rows = run_exports(
                rest_base=rest_base,
                rest_version=rest_version,
                scopes=scopes,
                filters=filters,
                token=token,
                fixability=label_set(args.fixability, DEFAULT_FIXABILITY),
                issue_types=label_set(args.issue_type, DEFAULT_ISSUE_TYPE),
                issue_statuses=issue_statuses,
                project_filter=project_filter,
                require_unfixed_upstream=not args.include_fixed_in_available,
                poll_seconds=max(1, args.poll_seconds),
                export_timeout=max(1, args.export_timeout),
                quiet=args.quiet,
            )
        except RuntimeError as exc:
            print(f"Export failed: {exc}", file=sys.stderr)
            return 1

        rows = merge_pending_rows(rows, discovered)
        save_state_csv(state_path, rows)
        if not args.quiet:
            print(
                f"State CSV updated: {state_path} "
                f"({len(discovered)} candidate issue row(s) from the export)."
            )

        if report_path is not None:
            save_report_csv(report_path, report_rows)
            if not args.quiet:
                print(
                    f"Report CSV written: {report_path} "
                    f"({len(report_rows)} matched issue(s))."
                )

    pending = [r for r in rows if r.get("status") == STATUS_PENDING]
    if not args.quiet:
        print(f"PENDING rows to process: {len(pending)}")

    created = 0
    skipped_existing = 0

    for row in pending:
        org_id = row["org_id"]
        project_id = row["project_id"]
        issue_id = row["issue_id"]

        if args.dry_run:
            if not args.quiet:
                print(f"  [dry-run] would ignore {issue_id} ({org_id}/{project_id})")
            created += 1
            continue

        try:
            add_ignore(
                api_base,
                org_id,
                project_id,
                issue_id,
                token,
                reason=args.reason,
                reason_type=args.reason_type,
                disregard_if_fixable=disregard,
                expires=args.expires,
                ignore_path=args.ignore_path,
            )
            row["status"] = STATUS_IGNORED
            created += 1
            save_state_csv(state_path, rows)
            if not args.quiet:
                print(f"  ignored {issue_id}")
        except SnykApiError as exc:
            # Match on the status code, never on digits in the message: issue
            # IDs such as SNYK-JS-NODESASS-540958 contain "409" and used to be
            # misread as an existing-ignore conflict.
            err_text = str(exc).lower()
            if (
                exc.status == 409
                or "already" in err_text
                or "duplicate" in err_text
            ):
                row["status"] = STATUS_IGNORED
                skipped_existing += 1
                save_state_csv(state_path, rows)
                if not args.quiet:
                    print(f"  skip {issue_id} (already ignored): {exc}", file=sys.stderr)
            else:
                print(f"  Error ignoring {issue_id}: {exc}", file=sys.stderr)
                return 1
        except RuntimeError as exc:
            print(f"  Error ignoring {issue_id}: {exc}", file=sys.stderr)
            return 1

    if not args.quiet:
        print(
            f"Done. Ignores applied: {created}; "
            f"marked existing/conflict as IGNORED: {skipped_existing}. "
            f"State file: {state_path}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
