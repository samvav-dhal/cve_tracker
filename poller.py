# poller.py — polls GHSA and publishes advisories to advisory_published topic
import json
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
import psycopg2
from confluent_kafka import Producer
from dotenv import load_dotenv

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────────
GITHUB_TOKEN      = os.environ["GITHUB_TOKEN"]
DB_URL            = os.environ["DATABASE_URL"]
BOOTSTRAP_SERVERS = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
SASL_USERNAME     = os.environ["KAFKA_SASL_USERNAME"]
SASL_PASSWORD     = os.environ["KAFKA_SASL_PASSWORD"]
TOPIC             = "advisory_published"
PER_PAGE          = 100
POLL_INTERVAL     = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))


# ── Kafka ──────────────────────────────────────────────────────────────────
def make_producer() -> Producer:
    return Producer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "security.protocol": "SASL_SSL",
        "sasl.mechanism":    "SCRAM-SHA-256",
        "sasl.username":     SASL_USERNAME,
        "sasl.password":     SASL_PASSWORD,
        "acks":              "all",     # wait for all in-sync replicas
        "retries":           3,
        "retry.backoff.ms":  1000,
    })


# ── Postgres ───────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(DB_URL)

def load_state(cur):
    cur.execute(
        "SELECT last_seen_published_at, last_seen_advisory_id "
        "FROM poller_state WHERE id = 1"
    )
    row = cur.fetchone()
    return (row[0], row[1]) if row else (None, None)

def save_state(cur, published_at, advisory_id):
    cur.execute(
        """
        INSERT INTO poller_state (id, last_seen_published_at, last_seen_advisory_id)
        VALUES (1, %s, %s)
        ON CONFLICT (id) DO UPDATE
            SET last_seen_published_at = EXCLUDED.last_seen_published_at,
                last_seen_advisory_id  = EXCLUDED.last_seen_advisory_id
        """,
        (published_at, advisory_id),
    )


# ── GHSA fetch ─────────────────────────────────────────────────────────────
def fetch_page(since_iso: str, page: int) -> list[dict]:
    resp = httpx.get(
        "https://api.github.com/advisories",
        headers={
            "Authorization":        f"Bearer {GITHUB_TOKEN}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params={
            "type":      "reviewed",
            "ecosystem": "pip",
            "published": f">={since_iso}",
            "sort":      "published",
            "direction": "asc",
            "per_page":  PER_PAGE,
            "page":      page,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()

def to_message(adv: dict) -> dict:
    """Flatten an advisory to the shape consumers expect."""
    packages = [
        {
            "ecosystem":                v.get("package", {}).get("ecosystem"),
            "name":                     v.get("package", {}).get("name"),
            "vulnerable_version_range": v.get("vulnerable_version_range"),
            "first_patched_version":    v.get("first_patched_version"),
        }
        for v in adv.get("vulnerabilities", [])
    ]
    return {
        "ghsa_id":      adv["ghsa_id"],
        "cve_id":       adv.get("cve_id"),
        "published_at": adv["published_at"],
        "updated_at":   adv.get("updated_at"),
        "severity":     adv.get("severity"),
        "summary":      adv.get("summary"),
        "packages":     packages,
    }


# ── Poll cycle ─────────────────────────────────────────────────────────────
def poll_once(producer: Producer, db_conn):
    cur = db_conn.cursor()
    last_ts, last_id = load_state(cur)

    since = (
        last_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        if last_ts
        else (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    print(f"\n[POLL] since={since}  cursor={last_id}")

    failed:     list[str] = []
    newest_ts   = last_ts
    newest_id   = last_id
    n_produced  = 0

    def on_delivery(err, msg):
        key = msg.key().decode()
        if err:
            print(f"  [ERR] {key}: {err}")
            failed.append(key)
        else:
            print(f"  [OK]  {key} → partition {msg.partition()} offset {msg.offset()}")

    page = 1
    while True:
        advisories = fetch_page(since, page)
        if not advisories:
            break

        for adv in advisories:
            # Skip the exact advisory the cursor is pointing at
            # (it was already published in the previous cycle)
            if adv["ghsa_id"] == last_id:
                continue

            producer.produce(
                topic=TOPIC,
                key=adv["ghsa_id"].encode(),
                value=json.dumps(to_message(adv)).encode(),
                callback=on_delivery,
            )
            producer.poll(0)    # serve delivery callbacks without blocking

            adv_ts = datetime.fromisoformat(adv["published_at"].replace("Z", "+00:00"))
            if newest_ts is None or adv_ts >= newest_ts:
                newest_ts = adv_ts
                newest_id = adv["ghsa_id"]

            n_produced += 1

        if len(advisories) < PER_PAGE:
            break           # reached the last page
        page += 1
        time.sleep(0.3)     # respect GitHub's rate limit

    # Block until all in-flight messages are acknowledged (or fail)
    producer.flush()

    if failed:
        # Don't advance the cursor — next cycle will retry from same position
        print(f"[WARN] {len(failed)} deliveries failed — state not advanced")
    elif newest_id != last_id:
        save_state(cur, newest_ts, newest_id)
        db_conn.commit()
        print(f"[STATE] cursor → {newest_ts}  {newest_id}")

    print(f"[DONE] produced={n_produced} failed={len(failed)}")
    cur.close()


# ── Entry point ────────────────────────────────────────────────────────────
def main():
    producer = make_producer()
    db_conn  = get_db()
    try:
        while True:
            poll_once(producer, db_conn)
            print(f"[SLEEP] {POLL_INTERVAL}s before next poll...")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("[EXIT] Shutting down.")
    finally:
        producer.flush()
        db_conn.close()


if __name__ == "__main__":
    main()