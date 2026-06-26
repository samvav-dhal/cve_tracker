# consumer.py — reads advisory_published, finds real repos using affected packages,
#               verifies via OSV.dev querybatch, produces matches to repo_affected.
import base64, json, os, re, time
from datetime import datetime, timezone

import httpx
from confluent_kafka import Consumer, Producer
from dotenv import load_dotenv

load_dotenv()

# ── Config ──────────────────────────────────────────────────────────────────
GITHUB_TOKEN      = os.environ["GITHUB_TOKEN"]
BOOTSTRAP_SERVERS = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
SASL_USERNAME     = os.environ["KAFKA_SASL_USERNAME"]
SASL_PASSWORD     = os.environ["KAFKA_SASL_PASSWORD"]
TOPIC_IN          = "advisory_published"
TOPIC_OUT         = "repo_affected"
GROUP_ID          = "vuln-repo-matcher"
REPOS_PER_PACKAGE = int(os.getenv("REPOS_PER_PACKAGE", "5"))

_KAFKA = {
    "bootstrap.servers": BOOTSTRAP_SERVERS,
    "security.protocol": "SASL_SSL",
    "sasl.mechanism":    "SCRAM-SHA-256",
    "sasl.username":     SASL_USERNAME,
    "sasl.password":     SASL_PASSWORD,
}


# ── GitHub ───────────────────────────────────────────────────────────────────

def _gh_get(url: str, params: dict | None = None, text_match: bool = False) -> dict:
    """GET with automatic rate-limit retry."""
    accept = (
        "application/vnd.github.text-match+json"
        if text_match
        else "application/vnd.github+json"
    )
    for _ in range(4):
        resp = httpx.get(
            url,
            headers={
                "Authorization":        f"Bearer {GITHUB_TOKEN}",
                "Accept":               accept,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            params=params,
            timeout=20,
        )
        if resp.status_code in (403, 429):
            # Respect both retry-after and x-ratelimit-reset headers
            wait = max(
                int(resp.headers.get("retry-after", 0)),
                int(resp.headers.get("x-ratelimit-reset", time.time() + 60)) - int(time.time()),
                5,
            )
            print(f"  [RATE LIMIT] HTTP {resp.status_code} — sleeping {wait}s")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"GitHub rate limit not cleared after retries: {url}")


# Matches only pinned versions: "requests==2.31.0"
# Deliberately ignores >=, ~=, etc. — unpinned deps can't be precisely verified.
_PIN_RE = re.compile(
    r"(?:^|\n)\s*(?P<pkg>[A-Za-z0-9_\-\.]+)\s*==\s*(?P<ver>[^\s;#\n]+)",
    re.MULTILINE,
)

def _pinned_version(text: str, package: str) -> str | None:
    norm = package.lower().replace("-", "_")
    for m in _PIN_RE.finditer(text):
        if m.group("pkg").lower().replace("-", "_") == norm:
            return m.group("ver").strip()
    return None


def search_repos(package_name: str) -> list[dict]:
    print(f"  [GH SEARCH] {package_name}")
    data = _gh_get(
        "https://api.github.com/search/code",
        params={
            "q":        f"{package_name}== filename:requirements.txt",
            "per_page": REPOS_PER_PACKAGE,
        },
        text_match=True,
    )
    time.sleep(2.5)   # Code Search: 30 req/min authenticated — conservative buffer

    results = []
    seen    = set()

    for item in data.get("items", []):
        repo = item["repository"]["full_name"]
        if repo in seen:
            continue
        seen.add(repo)

        # 1. Try text-match fragment — GitHub highlights matching lines
        version = None
        for match in item.get("text_matches", []):
            version = _pinned_version(match.get("fragment", ""), package_name)
            if version:
                break

        # 2. Fallback: fetch the actual file and parse it
        if version is None:
            try:
                file_data = _gh_get(
                    f"https://api.github.com/repos/{repo}/contents/{item['path']}",
                )
                content = base64.b64decode(
                    file_data.get("content", "")
                ).decode("utf-8", errors="ignore")
                version = _pinned_version(content, package_name)
                time.sleep(0.5)
            except Exception as e:
                print(f"    [WARN] could not read {repo}/{item['path']}: {e}")

        results.append({"repo": repo, "version": version})

    return results


# ── OSV.dev ──────────────────────────────────────────────────────────────────

def osv_querybatch(candidates: list[dict]) -> dict:
    """
    Batch-verify (package, version) pairs against OSV.dev.

    candidates: [{repo, package, version}, ...]
    Returns {(package, version): [vuln_id, ...]} — only affected pairs present.
    """
    if not candidates:
        return {}

    resp = httpx.post(
        "https://api.osv.dev/v1/querybatch",
        json={
            "queries": [
                {
                    "package": {"name": c["package"], "ecosystem": "PyPI"},
                    "version": c["version"],
                }
                for c in candidates
            ]
        },
        timeout=30,
    )
    resp.raise_for_status()

    out = {}
    for i, result in enumerate(resp.json().get("results", [])):
        vulns = result.get("vulns", [])
        if vulns:
            key     = (candidates[i]["package"], candidates[i]["version"])
            out[key] = [v["id"] for v in vulns]
    return out


# ── Core processing ──────────────────────────────────────────────────────────

def process(advisory: dict, producer: Producer) -> int:
    ghsa_id  = advisory["ghsa_id"]
    packages = [
        p["name"]
        for p in advisory.get("packages", [])
        if p.get("ecosystem") == "PyPI" and p.get("name")
    ]
    if not packages:
        print(f"  [SKIP] {ghsa_id}: no PyPI packages in advisory")
        return 0

    # Step 1 — collect candidates
    candidates = []
    for pkg in packages:
        for r in search_repos(pkg):
            if r["version"]:
                candidates.append({
                    "repo":    r["repo"],
                    "package": pkg,
                    "version": r["version"],
                })
            else:
                print(f"    [SKIP] {r['repo']}: unpinned {pkg} — can't verify")

    if not candidates:
        print(f"  [NO CANDIDATES] {ghsa_id}")
        return 0

    # Step 2 — batch OSV check
    print(f"  [OSV] verifying {len(candidates)} (repo, package, version) pairs")
    affected = osv_querybatch(candidates)

    # Step 3 — produce confirmed matches
    n = 0
    for c in candidates:
        key = (c["package"], c["version"])
        if key not in affected:
            continue

        producer.produce(
            topic=TOPIC_OUT,
            # Compound key: same advisory + same repo always lands in the same partition
            key=f"{ghsa_id}::{c['repo']}".encode(),
            value=json.dumps({
                "ghsa_id":           ghsa_id,
                "repo":              c["repo"],
                "package":           c["package"],
                "installed_version": c["version"],
                "osv_vuln_ids":      affected[key],
                "detected_at":       datetime.now(timezone.utc).isoformat(),
            }).encode(),
        )
        producer.poll(0)
        print(f"  [MATCH] {c['repo']} — {c['package']}=={c['version']}")
        n += 1

    # flush() blocks until all in-flight messages are ack'd (or timeout)
    remaining = producer.flush(timeout=15)
    if remaining:
        raise RuntimeError(f"{remaining} messages unacknowledged — skipping offset commit")

    return n


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    consumer = Consumer({
        **_KAFKA,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": False,   # manual commit only after successful produce
    })
    producer = Producer({
        **_KAFKA,
        "acks":             "all",
        "retries":          3,
        "retry.backoff.ms": 1000,
    })

    consumer.subscribe([TOPIC_IN])
    print(f"[START] group={GROUP_ID}  in={TOPIC_IN}  out={TOPIC_OUT}")

    try:
        while True:
            msg = consumer.poll(5.0)
            if msg is None:
                continue
            if msg.error():
                print(f"[KAFKA ERR] {msg.error()}")
                continue

            advisory = json.loads(msg.value().decode())
            ghsa_id  = advisory.get("ghsa_id", "?")
            print(f"\n[ADVISORY] {ghsa_id}  severity={advisory.get('severity', '?')}")
            print(f"  {advisory.get('summary', '')[:100]}")

            try:
                n = process(advisory, producer)
                consumer.commit(asynchronous=False)
                print(f"  → {n} match(es) published  [offset committed]")
            except Exception as e:
                # Offset intentionally NOT committed — advisory replays on restart
                print(f"  [ERROR] {e}  [offset NOT committed]")

    except KeyboardInterrupt:
        print("[EXIT]")
    finally:
        consumer.close()
        producer.flush()


if __name__ == "__main__":
    main()