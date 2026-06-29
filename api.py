"""
api.py — FastAPI read-only backend for the VulTracker security dashboard.

Run:
    uvicorn api:app --reload --port 8000
"""
import os
from datetime import datetime

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Optional

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]

app = FastAPI(title="VulTracker API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── Database helpers ──────────────────────────────────────────────────────────

def _conn():
    """Open a fresh psycopg2 connection. Caller must close it."""
    return psycopg2.connect(DATABASE_URL)


def _row(d: dict) -> dict:
    """Convert a psycopg2 RealDictRow to a JSON-safe dict.
    - datetime  → ISO-8601 string
    - list      → kept as-is (psycopg2 maps TEXT[] to Python list)
    """
    out = {}
    for k, v in d.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


# ── Endpoints ─────────────────────────────────────────────────────────────────

_DASHBOARD = os.path.join(os.path.dirname(__file__), "dashboard.html")

@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the single-file dashboard UI."""
    return FileResponse(_DASHBOARD, media_type="text/html")


@app.get("/stats")
def get_stats():
    """Total advisories, total affected repos, timestamp of most recent detection."""
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    COUNT(DISTINCT ghsa_id) AS total_advisories,
                    COUNT(DISTINCT repo)    AS total_repos,
                    MAX(detected_at)        AS last_detected
                FROM affected_repos
                """
            )
            return _row(dict(cur.fetchone()))
    finally:
        conn.close()


@app.get("/heatmap")
def get_heatmap():
    """Top 20 packages ranked by number of distinct affected repos."""
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    package,
                    COUNT(DISTINCT repo) AS affected_repo_count
                FROM affected_repos
                GROUP BY package
                ORDER BY affected_repo_count DESC
                LIMIT 20
                """
            )
            return [_row(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()


@app.get("/advisories")
def get_advisories():
    """All advisories with affected-repo count and latest detection time, most recent first."""
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    ghsa_id,
                    COUNT(DISTINCT repo)  AS affected_repo_count,
                    MAX(detected_at)      AS latest_detection
                FROM affected_repos
                GROUP BY ghsa_id
                ORDER BY latest_detection DESC
                LIMIT 100
                """
            )
            return [_row(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()


@app.get("/advisories/{ghsa_id}")
def get_advisory_detail(ghsa_id: str):
    """All affected repos for a single advisory."""
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT repo, package, installed_version, osv_vuln_ids, detected_at
                FROM affected_repos
                WHERE ghsa_id = %s
                ORDER BY detected_at DESC
                """,
                (ghsa_id,),
            )
            rows = cur.fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="Advisory not found")
        return [_row(dict(r)) for r in rows]
    finally:
        conn.close()


@app.get("/feed")
def get_feed(
    package: Optional[str] = Query(default=None),
    q:       Optional[str] = Query(default=None),
):
    """Last detections ordered newest first.

    ?package=<name>  – exact package filter (up to 200 rows)
    ?q=<text>        – full-text ILIKE search on repo OR package (up to 200 rows)
    (no params)      – latest 50 globally
    """
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if q:
                pattern = f"%{q}%"
                cur.execute(
                    """
                    SELECT ghsa_id, repo, package, installed_version, detected_at
                    FROM affected_repos
                    WHERE repo ILIKE %s OR package ILIKE %s
                    ORDER BY detected_at DESC
                    LIMIT 200
                    """,
                    (pattern, pattern),
                )
            elif package:
                cur.execute(
                    """
                    SELECT ghsa_id, repo, package, installed_version, detected_at
                    FROM affected_repos
                    WHERE package = %s
                    ORDER BY detected_at DESC
                    LIMIT 200
                    """,
                    (package,),
                )
            else:
                cur.execute(
                    """
                    SELECT ghsa_id, repo, package, installed_version, detected_at
                    FROM affected_repos
                    ORDER BY detected_at DESC
                    LIMIT 50
                    """
                )
            return [_row(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()
