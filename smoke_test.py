import os
import sys

from dotenv import load_dotenv

load_dotenv()

REQUIRED_ENV_VARS = [
    "GITHUB_TOKEN",
    "KAFKA_BOOTSTRAP_SERVERS",
    "KAFKA_SASL_USERNAME",
    "KAFKA_SASL_PASSWORD",
    "DATABASE_URL"
]

def check_env_vars() -> bool:
    missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        print(f"FAIL  .env: missing value(s) for {missing}")
        return False
    print("PASS  .env: all required variables are set")
    return True

def check_postgres() -> bool:
    import psycopg2
 
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        cur = conn.cursor()
        cur.execute(
            "SELECT source, last_seen_published_at, last_seen_advisory_id "
            "FROM poller_state;"
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
 
        if not rows:
            print(
                "FAIL  Postgres: connected, but poller_state has no rows "
                "(did you run the INSERT in schema.sql?)"
            )
            return False
 
        for source, last_seen_at, last_seen_id in rows:
            print(
                f"      poller_state row: source={source!r} "
                f"last_seen_published_at={last_seen_at} "
                f"last_seen_advisory_id={last_seen_id!r}"
            )
        print("PASS  Postgres: connected, poller_state is readable")
        return True
 
    except Exception as e:
        print(f"FAIL  Postgres: {e}")
        return False

def check_kafka() -> bool:
    from confluent_kafka.admin import AdminClient
 
    try:
        conf = {
            "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
            "security.protocol": "SASL_SSL",
            # If your Redpanda cluster's connection page shows SCRAM-SHA-512
            # instead, change this one line to match.
            "sasl.mechanism": "SCRAM-SHA-256",
            "sasl.username": os.environ["KAFKA_SASL_USERNAME"],
            "sasl.password": os.environ["KAFKA_SASL_PASSWORD"],
        }
        admin = AdminClient(conf)
        metadata = admin.list_topics(timeout=10)
        topic_names = set(metadata.topics.keys())
 
        required_topics = {"advisory_published", "repo_affected"}
        missing = required_topics - topic_names
 
        print(f"      topics found on cluster: {sorted(topic_names)}")
 
        if missing:
            print(f"FAIL  Kafka/Redpanda: connected, but missing topic(s): {missing}")
            return False
 
        print("PASS  Kafka/Redpanda: connected, both required topics exist")
        return True
 
    except Exception as e:
        print(f"FAIL  Kafka/Redpanda: {e}")
        return False

def check_github() -> bool:
    import httpx
 
    try:
        headers = {
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
        }
        # 'pip' is the ecosystem value GHSA's API expects for PyPI advisories.
        params = {"ecosystem": "pip", "per_page": 1}
 
        resp = httpx.get(
            "https://api.github.com/advisories",
            headers=headers,
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
 
        if not data:
            print("FAIL  GitHub API: request succeeded but returned no advisories")
            return False
 
        first = data[0]
        print(
            f"      sample advisory: {first.get('ghsa_id')} "
            f"— {first.get('summary')}"
        )
        print("PASS  GitHub API: connected, token is valid")
        return True
 
    except Exception as e:
        print(f"FAIL  GitHub API: {e}")
        return False
 
def main() -> None:
    print("Running smoke test...\n")
 
    if not check_env_vars():
        print("\nFix .env before testing individual connections.")
        sys.exit(1)
    print()
 
    results = {
        "Postgres": check_postgres(),
        "Kafka/Redpanda": check_kafka(),
        "GitHub API": check_github(),
    }
 
    print("\nSummary:")
    all_passed = True
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            all_passed = False
 
    if not all_passed:
        print("\nFix the failures above before writing poller.py.")
        sys.exit(1)
 
    print("\nAll connections good. Ready to build poller.py.")
 
 
if __name__ == "__main__":
    main()
 