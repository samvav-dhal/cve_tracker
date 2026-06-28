# sink.py — consumes repo_affected and persists matches to Postgres affected_repos
import json, os

import psycopg2
from confluent_kafka import Consumer
from dotenv import load_dotenv

load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────
DB_URL            = os.environ["DATABASE_URL"]
BOOTSTRAP_SERVERS = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
SASL_USERNAME     = os.environ["KAFKA_SASL_USERNAME"]
SASL_PASSWORD     = os.environ["KAFKA_SASL_PASSWORD"]
TOPIC             = "repo_affected"
GROUP_ID          = "repo-affected-sink"


# ── Postgres ──────────────────────────────────────────────────────────────────

_INSERT = """
    INSERT INTO affected_repos
        (ghsa_id, repo, package, installed_version, osv_vuln_ids, detected_at)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (ghsa_id, repo, package) DO NOTHING
"""

def write_match(cur, match: dict) -> bool:
    """
    Persist one match to affected_repos.
    Returns True if a new row was inserted; False if the row already existed
    (ON CONFLICT DO NOTHING sets rowcount=0 on a duplicate).
    """
    cur.execute(_INSERT, (
        match["ghsa_id"],
        match["repo"],
        match["package"],
        match["installed_version"],
        match["osv_vuln_ids"],      # list[str] → psycopg2 → PostgreSQL TEXT[]
        match["detected_at"],
    ))
    return cur.rowcount == 1


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "security.protocol": "SASL_SSL",
        "sasl.mechanism":    "SCRAM-SHA-256",
        "sasl.username":     SASL_USERNAME,
        "sasl.password":     SASL_PASSWORD,
        "group.id":          GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    db_conn = psycopg2.connect(DB_URL)
    consumer.subscribe([TOPIC])
    print(f"[START] group={GROUP_ID}  topic={TOPIC}")

    try:
        while True:
            msg = consumer.poll(5.0)
            if msg is None:
                continue
            if msg.error():
                print(f"[KAFKA ERR] {msg.error()}")
                continue

            match   = json.loads(msg.value().decode())
            ghsa_id = match.get("ghsa_id", "?")
            repo    = match.get("repo",    "?")

            try:
                cur      = db_conn.cursor()
                inserted = write_match(cur, match)
                db_conn.commit()
                cur.close()
                # Offset committed only after Postgres has durably written the row.
                # On restart, a duplicate message hits ON CONFLICT DO NOTHING safely.
                consumer.commit(asynchronous=False)
                label = "inserted" if inserted else "duplicate — skipped"
                print(f"[SINK] {ghsa_id} → {repo}  [{label}]")
            except Exception as e:
                db_conn.rollback()
                print(f"[ERROR] {ghsa_id}/{repo}: {e}  [offset NOT committed]")

    except KeyboardInterrupt:
        print("[EXIT]")
    finally:
        consumer.close()
        db_conn.close()


if __name__ == "__main__":
    main()