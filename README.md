# VulTracker

A Kafka-based streaming pipeline that detects public GitHub repositories pinning vulnerable PyPI packages — automatically, within minutes of a GHSA advisory being published.

**Real results on live data:** 1039 affected repositories identified across 89 advisories, including repos pinning vulnerable versions of `litellm`, `cryptography`, and `torch`.

---

## The Problem

When a supply chain attack hits a popular package (e.g. the TeamPCP campaign targeting LiteLLM, March 2026), the immediate question is: *which repos are running the compromised version right now?* GHSA publishes the advisory, but finding affected consumers is a manual, slow process. VulTracker automates it.

---

## How It Works

```
GHSA API
   │
   ▼
poller.py ──► [advisory_published] ──► consumer.py ──► [repo_affected] ──► sink.py
                  Kafka topic           │                  Kafka topic         │
                                        ├─ GitHub Code Search                  ▼
                                        └─ OSV.dev /v1/querybatch          Postgres
                                                                               │
                                                                               ▼
                                                                    api.py + dashboard.html
```

1. **`poller.py`** — polls `api.github.com/advisories` every 5 minutes for reviewed PyPI advisories. Publishes each new advisory as a JSON message to the `advisory_published` Kafka topic. Persists a cursor to Postgres so it never re-publishes on restart.

2. **`consumer.py`** — consumes `advisory_published`. For each affected package, searches GitHub Code for `requirements.txt` files containing a pinned (`==`) version. Verifies each candidate version against [OSV.dev's `querybatch` API](https://google.github.io/osv.dev/post-v1-querybatch/). Publishes only confirmed matches to `repo_affected`.

3. **`sink.py`** — consumes `repo_affected` and writes confirmed matches to the `affected_repos` Postgres table. Uses `ON CONFLICT DO NOTHING` — the full pipeline is idempotent.

4. **`api.py`** — FastAPI read-only backend serving the dashboard and JSON endpoints.

5. **`dashboard.html`** — single-file security dashboard (served at `/`).

---

## Scope

| Dimension | Current scope |
|---|---|
| Advisory source | GitHub Security Advisories (GHSA), reviewed only |
| Ecosystem | PyPI only |
| Dependency files | `requirements.txt` only |
| Version matching | Pinned versions (`==`) only — unpinned ranges can't be precisely verified |

---

## Stack

- **[Redpanda](https://redpanda.com/)** (Kafka-compatible) — message broker
- **[Neon](https://neon.tech/)** — serverless Postgres
- **[FastAPI](https://fastapi.tiangolo.com/)** — API + dashboard server
- **[OSV.dev](https://osv.dev/)** — vulnerability verification
- **GitHub REST API** — advisory polling + code search
- **Python 3.11+**

---

## Setup

### Prerequisites

- Python 3.11+
- A Redpanda (or Kafka) cluster with two topics: `advisory_published`, `repo_affected`
- A Postgres database with the schema applied
- A GitHub personal access token (for advisory polling and code search)

### Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment

Copy the following into a `.env` file:

```env
GITHUB_TOKEN=ghp_...
DATABASE_URL=postgresql://user:pass@host/dbname
KAFKA_BOOTSTRAP_SERVERS=your-broker:9092
KAFKA_SASL_USERNAME=...
KAFKA_SASL_PASSWORD=...

# Optional
POLL_INTERVAL_SECONDS=300   # default: 300
REPOS_PER_PACKAGE=5         # GitHub code search results per package; default: 5
```

### Verify connectivity

```bash
python3 smoke_test.py
```

Checks `.env` completeness, Postgres connectivity, Kafka topic existence, and GitHub API access.

---

## Running

Start all three processes (each in its own terminal):

```bash
python3 poller.py    # polls GHSA → advisory_published
python3 consumer.py  # advisory_published → OSV verify → repo_affected
python3 sink.py      # repo_affected → Postgres
```

Start the dashboard:

```bash
uvicorn api:app --port 8000
```

Open [http://localhost:8000](http://localhost:8000).

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/stats` | Total advisories, repos, last detection time |
| `GET` | `/heatmap` | Top 20 packages by affected-repo count |
| `GET` | `/advisories` | All advisories with repo counts, newest first |
| `GET` | `/advisories/{ghsa_id}` | All affected repos for a single advisory |
| `GET` | `/feed` | Latest detections; filter by `?package=` or `?q=` |

Interactive docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Tests

48 unit tests covering the parser, message shaping, OSV verification, poll loop, and sink writer. All external dependencies (Kafka, GitHub, OSV.dev, Postgres) are mocked.

```bash
python3 -m pytest test_pipeline.py -v
```

The pipeline is idempotent — re-processing already-stored advisories produces no duplicates.
