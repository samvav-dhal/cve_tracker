"""

Reads last-seen state from Postgres, fetches new PyPI advisories from GHSA
since that state, and prints them. No Kafka producing yet — validate that
the fetch and filter logic is correct on real data before wiring to the topic.

Once this prints real advisories correctly, the next step is adding the
Kafka producer and the state-update logic.
"""

import logging
import os
import sys
from datetime import datetime, timezone

import httpx
import psycopg2
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

GHSA_API_URL = "https://api.github.com/advisories"
ECOSYSTEM = "pip"        # GHSA's parameter value for PyPI advisories
PER_PAGE = 30            # max allowed by GHSA
SOURCE = "ghsa"          # matches the row we inserted into poller_state


# ---------------------------------------------------------------------------
# Postgres helpers
# ---------------------------------------------------------------------------

def get_db_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def read_poller_state(conn) -> tuple[datetime, str | None]:
    """Return (last_seen_published_at, last_seen_advisory_id) from Postgres."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT last_seen_published_at, last_seen_advisory_id "
            "FROM poller_state WHERE source = %s",
            (SOURCE,),
        )
        row = cur.fetchone()
        if not row:
            log.error(
                "No poller_state row found for source=%r. "
                "Did you run db/schema.sql?",
                SOURCE,
            )
            sys.exit(1)
        last_seen_at, last_seen_id = row
        # psycopg2 returns TIMESTAMPTZ as an aware datetime — ensure UTC
        if last_seen_at.tzinfo is None:
            last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
        return last_seen_at, last_seen_id


# ---------------------------------------------------------------------------
# GHSA fetch helpers
# ---------------------------------------------------------------------------

def build_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_advisories_page(
    client: httpx.Client,
    after: datetime,
    page: int,
) -> list[dict]:
    """
    Fetch one page of PyPI advisories published strictly after `after`.

    GHSA's `published` parameter accepts ISO 8601 range syntax:
        >YYYY-MM-DDTHH:MM:SSZ   →  strictly after this timestamp
    Results are sorted oldest-first so we process and store state
    in the order they actually arrived.
    """
    after_str = after.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "ecosystem": ECOSYSTEM,
        "published": f">{after_str}",
        "sort": "published",
        "direction": "asc",
        "per_page": PER_PAGE,
        "page": page,
    }
    resp = client.get(GHSA_API_URL, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


def fetch_all_new_advisories(after: datetime, last_seen_id: str | None) -> list[dict]:
    """
    Page through GHSA until no more results, then apply the tiebreaker:
    drop any advisory whose published_at == after AND whose ghsa_id
    == last_seen_id (already processed on the previous run).

    Returns a list of new advisory dicts, oldest-first.
    """
    all_advisories: list[dict] = []

    with httpx.Client(headers=build_headers()) as client:
        page = 1
        while True:
            log.info("Fetching GHSA page %d (after=%s) ...", page, after.isoformat())
            try:
                results = fetch_advisories_page(client, after, page)
            except httpx.HTTPStatusError as e:
                log.error(
                    "GHSA API returned %d: %s", e.response.status_code, e.response.text
                )
                raise
            except httpx.RequestError as e:
                log.error("Network error fetching GHSA: %s", e)
                raise

            if not results:
                log.info("No more results on page %d — done paginating.", page)
                break

            log.info("Page %d: %d advisory/ies returned.", page, len(results))
            all_advisories.extend(results)

            if len(results) < PER_PAGE:
                # Last page — no need to request another
                break
            page += 1

    # Apply same-second tiebreaker:
    # If the very first advisory has the same published_at as our cursor
    # AND the same ghsa_id as last_seen_id, it's a duplicate from the
    # previous run — skip it.
    if all_advisories and last_seen_id:
        first = all_advisories[0]
        first_published = datetime.fromisoformat(
            first["published_at"].replace("Z", "+00:00")
        )
        if first_published == after and first["ghsa_id"] == last_seen_id:
            log.info(
                "Skipping already-seen advisory %s (tiebreaker).", last_seen_id
            )
            all_advisories = all_advisories[1:]

    return all_advisories


# ---------------------------------------------------------------------------
# Advisory parsing helpers
# ---------------------------------------------------------------------------

def extract_pypi_packages(advisory: dict) -> list[dict]:
    """
    Pull out only the PyPI-ecosystem vulnerability entries from an advisory.
    An advisory can cover multiple ecosystems; we only care about pip/PyPI.
    """
    packages = []
    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        if pkg.get("ecosystem", "").lower() == "pip":
            packages.append(
                {
                    "name": pkg.get("name"),
                    "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                    "first_patched_version": vuln.get("first_patched_version"),
                }
            )
    return packages


def print_advisory(advisory: dict) -> None:
    packages = extract_pypi_packages(advisory)
    print(
        f"\n{'─' * 60}\n"
        f"  GHSA ID   : {advisory.get('ghsa_id')}\n"
        f"  CVE ID    : {advisory.get('cve_id') or 'n/a'}\n"
        f"  Severity  : {advisory.get('severity', 'unknown')}\n"
        f"  Published : {advisory.get('published_at')}\n"
        f"  Summary   : {advisory.get('summary')}\n"
        f"  Packages  : {packages if packages else '(none matched pip ecosystem)'}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Poller starting.")

    conn = get_db_conn()
    try:
        last_seen_at, last_seen_id = read_poller_state(conn)
        log.info(
            "State: last_seen_published_at=%s  last_seen_advisory_id=%s",
            last_seen_at.isoformat(),
            last_seen_id,
        )

        advisories = fetch_all_new_advisories(last_seen_at, last_seen_id)

        if not advisories:
            log.info("No new PyPI advisories since last run. Nothing to do.")
            return

        log.info("Found %d new advisory/ies.", len(advisories))
        for adv in advisories:
            print_advisory(adv)

        # ----------------------------------------------------------------
        # NOT updating poller_state here yet — that comes in the next step
        # when we add Kafka producing and confirmed-delivery logic.
        # ----------------------------------------------------------------
        log.info(
            "\nDone (print-only run). State NOT updated — "
            "re-running will fetch the same advisories again until "
            "Kafka producing + state update is wired in."
        )

    finally:
        conn.close()


if __name__ == "__main__":
    main()