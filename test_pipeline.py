"""
test_pipeline.py — unit tests for poller.py, consumer.py, sink.py

All external dependencies (Kafka, GitHub, OSV.dev, Postgres) are mocked.
Pure functions are tested directly; orchestration functions are tested with
mock injections so that no network or broker connection is required.
"""
import json, os, sys, unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

# ── Set fake env vars BEFORE importing project modules ─────────────────────
os.environ.update({
    "GITHUB_TOKEN":            "gh_fake",
    "DATABASE_URL":            "postgresql://fake",
    "KAFKA_BOOTSTRAP_SERVERS": "fake:9092",
    "KAFKA_SASL_USERNAME":     "fake_user",
    "KAFKA_SASL_PASSWORD":     "fake_pass",
})
sys.path.insert(0, "/home/claude/vuln-tracker")

import consumer, poller, sink
from consumer import _pinned_version, osv_querybatch, process
from poller   import to_message, poll_once
from sink     import write_match


# ═══════════════════════════════════════════════════════════════════════════════
# _pinned_version
# ═══════════════════════════════════════════════════════════════════════════════

class TestPinnedVersionParser(unittest.TestCase):

    def test_basic_pin(self):
        self.assertEqual(_pinned_version("requests==2.31.0\n", "requests"), "2.31.0")

    def test_package_not_in_file(self):
        self.assertIsNone(_pinned_version("numpy==1.24.0\n", "requests"))

    def test_ignores_gte(self):
        self.assertIsNone(_pinned_version("requests>=2.0.0\n", "requests"))

    def test_ignores_approx_eq(self):
        self.assertIsNone(_pinned_version("requests~=2.0.0\n", "requests"))

    def test_ignores_lte(self):
        self.assertIsNone(_pinned_version("requests<=3.0.0\n", "requests"))

    def test_strips_inline_comment(self):
        self.assertEqual(
            _pinned_version("requests==2.31.0  # pinned for CVE fix\n", "requests"),
            "2.31.0",
        )

    def test_case_insensitive_package_name(self):
        self.assertEqual(_pinned_version("Requests==2.31.0\n", "requests"), "2.31.0")

    def test_hyphen_underscore_normalization(self):
        # Pillow in requirements.txt, queried as "pillow"
        self.assertEqual(_pinned_version("Pillow==9.5.0\n", "pillow"), "9.5.0")

    def test_multipackage_file_picks_correct_one(self):
        content = "flask==2.3.0\nrequests==2.31.0\nnumpy>=1.20.0\n"
        self.assertEqual(_pinned_version(content, "requests"), "2.31.0")
        self.assertEqual(_pinned_version(content, "flask"),    "2.3.0")
        self.assertIsNone(_pinned_version(content, "numpy"))

    def test_no_false_prefix_match(self):
        # "requests-mock" must NOT match query "requests"
        content = "requests-mock==1.11.0\nrequests==2.31.0\n"
        self.assertEqual(_pinned_version(content, "requests"), "2.31.0")

    def test_leading_whitespace_in_file(self):
        self.assertEqual(_pinned_version("  requests==2.31.0\n", "requests"), "2.31.0")

    def test_multi_segment_version(self):
        self.assertEqual(_pinned_version("urllib3==1.26.16\n", "urllib3"), "1.26.16")

    def test_empty_file(self):
        self.assertIsNone(_pinned_version("", "requests"))


# ═══════════════════════════════════════════════════════════════════════════════
# to_message (poller)
# ═══════════════════════════════════════════════════════════════════════════════

class TestToMessage(unittest.TestCase):

    def _advisory(self, **overrides):
        base = {
            "ghsa_id":      "GHSA-1234-5678-9abc",
            "cve_id":       "CVE-2024-99999",
            "published_at": "2024-01-15T10:00:00Z",
            "updated_at":   "2024-01-16T10:00:00Z",
            "severity":     "HIGH",
            "summary":      "Test vulnerability in requests",
            "vulnerabilities": [
                {
                    "package":                  {"ecosystem": "PyPI", "name": "requests"},
                    "vulnerable_version_range": "<2.32.0",
                    "first_patched_version":    "2.32.0",
                }
            ],
        }
        base.update(overrides)
        return base

    def test_top_level_fields(self):
        msg = to_message(self._advisory())
        self.assertEqual(msg["ghsa_id"],      "GHSA-1234-5678-9abc")
        self.assertEqual(msg["cve_id"],       "CVE-2024-99999")
        self.assertEqual(msg["published_at"], "2024-01-15T10:00:00Z")
        self.assertEqual(msg["severity"],     "HIGH")
        self.assertEqual(msg["summary"],      "Test vulnerability in requests")

    def test_package_fields_extracted(self):
        msg = to_message(self._advisory())
        self.assertEqual(len(msg["packages"]), 1)
        pkg = msg["packages"][0]
        self.assertEqual(pkg["name"],                     "requests")
        self.assertEqual(pkg["ecosystem"],                "PyPI")
        self.assertEqual(pkg["vulnerable_version_range"], "<2.32.0")
        self.assertEqual(pkg["first_patched_version"],    "2.32.0")

    def test_missing_optional_fields_are_none(self):
        adv = self._advisory()
        del adv["cve_id"]
        del adv["summary"]
        msg = to_message(adv)
        self.assertIsNone(msg["cve_id"])
        self.assertIsNone(msg["summary"])

    def test_multiple_vulnerabilities_all_included(self):
        adv = self._advisory()
        adv["vulnerabilities"].append({
            "package":                  {"ecosystem": "PyPI", "name": "urllib3"},
            "vulnerable_version_range": "<1.26.17",
            "first_patched_version":    "1.26.17",
        })
        msg = to_message(adv)
        self.assertEqual(len(msg["packages"]), 2)
        self.assertEqual({p["name"] for p in msg["packages"]}, {"requests", "urllib3"})

    def test_empty_vulnerabilities(self):
        msg = to_message(self._advisory(vulnerabilities=[]))
        self.assertEqual(msg["packages"], [])

    def test_raw_vulnerabilities_key_not_present(self):
        # consumers should never see the raw GHSA shape
        self.assertNotIn("vulnerabilities", to_message(self._advisory()))

    def test_output_is_json_serialisable(self):
        msg = to_message(self._advisory())
        try:
            json.dumps(msg)
        except TypeError as e:
            self.fail(f"to_message output is not JSON-serialisable: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# osv_querybatch (consumer)
# ═══════════════════════════════════════════════════════════════════════════════

class TestOsvQuerybatch(unittest.TestCase):

    def test_empty_candidates_no_http_call(self):
        with patch("consumer.httpx.post") as mock_post:
            result = osv_querybatch([])
        self.assertEqual(result, {})
        mock_post.assert_not_called()

    def test_affected_pair_included(self):
        candidates = [{"repo": "owner/repo", "package": "requests", "version": "2.31.0"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "results": [{"vulns": [{"id": "GHSA-1234"}, {"id": "CVE-2024-99"}]}]
        }
        with patch("consumer.httpx.post", return_value=mock_resp):
            result = osv_querybatch(candidates)
        self.assertIn(("requests", "2.31.0"), result)
        self.assertEqual(result[("requests", "2.31.0")], ["GHSA-1234", "CVE-2024-99"])

    def test_unaffected_pair_excluded(self):
        candidates = [{"repo": "owner/repo", "package": "requests", "version": "2.32.0"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [{"vulns": []}]}
        with patch("consumer.httpx.post", return_value=mock_resp):
            result = osv_querybatch(candidates)
        self.assertEqual(result, {})

    def test_missing_vulns_key_treated_as_empty(self):
        candidates = [{"repo": "owner/repo", "package": "requests", "version": "2.32.0"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [{}]}  # no "vulns" key
        with patch("consumer.httpx.post", return_value=mock_resp):
            result = osv_querybatch(candidates)
        self.assertEqual(result, {})

    def test_mixed_results(self):
        candidates = [
            {"repo": "a/a", "package": "requests", "version": "2.31.0"},
            {"repo": "b/b", "package": "requests", "version": "2.32.0"},  # patched
            {"repo": "c/c", "package": "numpy",    "version": "1.24.0"},
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "results": [
                {"vulns": [{"id": "GHSA-1111"}]},
                {"vulns": []},
                {"vulns": [{"id": "GHSA-2222"}]},
            ]
        }
        with patch("consumer.httpx.post", return_value=mock_resp):
            result = osv_querybatch(candidates)
        self.assertIn(("requests", "2.31.0"), result)
        self.assertNotIn(("requests", "2.32.0"), result)
        self.assertIn(("numpy", "1.24.0"), result)

    def test_request_payload_structure(self):
        candidates = [{"repo": "owner/repo", "package": "requests", "version": "2.31.0"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [{"vulns": []}]}
        with patch("consumer.httpx.post", return_value=mock_resp) as mock_post:
            osv_querybatch(candidates)
        _, kwargs = mock_post.call_args
        payload   = kwargs["json"]
        self.assertIn("queries", payload)
        q = payload["queries"][0]
        self.assertEqual(q["package"]["ecosystem"], "PyPI")
        self.assertEqual(q["package"]["name"],      "requests")
        self.assertEqual(q["version"],              "2.31.0")

    def test_url_is_osv_querybatch(self):
        candidates = [{"repo": "r/r", "package": "p", "version": "1.0"}]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [{"vulns": []}]}
        with patch("consumer.httpx.post", return_value=mock_resp) as mock_post:
            osv_querybatch(candidates)
        url = mock_post.call_args.args[0]
        self.assertIn("osv.dev", url)
        self.assertIn("querybatch", url)


# ═══════════════════════════════════════════════════════════════════════════════
# process() (consumer)
# ═══════════════════════════════════════════════════════════════════════════════

class TestProcess(unittest.TestCase):

    def _advisory(self, packages=None):
        return {
            "ghsa_id":  "GHSA-test-aaaa-bbbb",
            "severity": "HIGH",
            "summary":  "Test vulnerability",
            "packages": packages or [
                {
                    "ecosystem":                "PyPI",
                    "name":                     "requests",
                    "vulnerable_version_range": "<2.32.0",
                    "first_patched_version":    "2.32.0",
                }
            ],
        }

    def _prod(self, flush_remaining=0):
        p = MagicMock()
        p.flush.return_value = flush_remaining
        return p

    @patch("consumer.search_repos")
    def test_no_pypi_packages_returns_zero_no_search(self, mock_search):
        adv = self._advisory(packages=[{"ecosystem": "npm", "name": "lodash"}])
        self.assertEqual(process(adv, self._prod()), 0)
        mock_search.assert_not_called()

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_no_repos_found_returns_zero(self, mock_search, mock_osv):
        mock_search.return_value = []
        self.assertEqual(process(self._advisory(), self._prod()), 0)
        mock_osv.assert_not_called()

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_all_unpinned_skips_osv_check(self, mock_search, mock_osv):
        mock_search.return_value = [
            {"repo": "a/a", "version": None},
            {"repo": "b/b", "version": None},
        ]
        self.assertEqual(process(self._advisory(), self._prod()), 0)
        mock_osv.assert_not_called()

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_no_osv_matches_returns_zero(self, mock_search, mock_osv):
        mock_search.return_value = [{"repo": "owner/repo", "version": "2.32.0"}]
        mock_osv.return_value    = {}
        self.assertEqual(process(self._advisory(), self._prod()), 0)

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_single_match_correct_message_shape(self, mock_search, mock_osv):
        mock_search.return_value = [{"repo": "owner/myrepo", "version": "2.31.0"}]
        mock_osv.return_value    = {("requests", "2.31.0"): ["GHSA-test-aaaa-bbbb"]}
        prod = self._prod()

        n = process(self._advisory(), prod)

        self.assertEqual(n, 1)
        prod.produce.assert_called_once()
        _, kwargs = prod.produce.call_args
        self.assertEqual(kwargs["topic"], "repo_affected")
        self.assertEqual(kwargs["key"],   b"GHSA-test-aaaa-bbbb::owner/myrepo")
        value = json.loads(kwargs["value"].decode())
        self.assertEqual(value["ghsa_id"],           "GHSA-test-aaaa-bbbb")
        self.assertEqual(value["repo"],              "owner/myrepo")
        self.assertEqual(value["package"],           "requests")
        self.assertEqual(value["installed_version"], "2.31.0")
        self.assertIn("GHSA-test-aaaa-bbbb", value["osv_vuln_ids"])
        self.assertIn("detected_at", value)

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_multiple_matches_all_produced(self, mock_search, mock_osv):
        mock_search.return_value = [
            {"repo": "owner/a", "version": "2.31.0"},
            {"repo": "owner/b", "version": "2.28.0"},
        ]
        mock_osv.return_value = {
            ("requests", "2.31.0"): ["GHSA-test-aaaa-bbbb"],
            ("requests", "2.28.0"): ["GHSA-test-aaaa-bbbb"],
        }
        prod = self._prod()
        self.assertEqual(process(self._advisory(), prod), 2)
        self.assertEqual(prod.produce.call_count, 2)

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_flush_failure_raises(self, mock_search, mock_osv):
        mock_search.return_value = [{"repo": "owner/repo", "version": "2.31.0"}]
        mock_osv.return_value    = {("requests", "2.31.0"): ["GHSA-test-aaaa-bbbb"]}
        with self.assertRaises(RuntimeError):
            process(self._advisory(), self._prod(flush_remaining=1))

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_flush_called_with_timeout(self, mock_search, mock_osv):
        mock_search.return_value = [{"repo": "owner/repo", "version": "2.31.0"}]
        mock_osv.return_value    = {("requests", "2.31.0"): ["GHSA-test-aaaa-bbbb"]}
        prod = self._prod()
        process(self._advisory(), prod)
        prod.flush.assert_called_once_with(timeout=15)

    @patch("consumer.osv_querybatch")
    @patch("consumer.search_repos")
    def test_only_pypi_packages_searched(self, mock_search, mock_osv):
        """npm packages in a mixed advisory must not trigger a search."""
        mock_search.return_value = []
        mock_osv.return_value    = {}
        adv = self._advisory(packages=[
            {"ecosystem": "PyPI", "name": "requests"},
            {"ecosystem": "npm",  "name": "lodash"},
        ])
        process(adv, self._prod())
        # search_repos should only be called for "requests", not "lodash"
        self.assertEqual(mock_search.call_count, 1)
        self.assertEqual(mock_search.call_args.args[0], "requests")


# ═══════════════════════════════════════════════════════════════════════════════
# poll_once (poller)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPollOnce(unittest.TestCase):

    def _db(self, row=None):
        cur = MagicMock()
        cur.fetchone.return_value = row
        db  = MagicMock()
        db.cursor.return_value = cur
        return db, cur

    def _prod(self):
        p = MagicMock()
        p.flush.return_value = 0
        return p

    def _item(self, ghsa_id, published_at):
        return {
            "ghsa_id":         ghsa_id,
            "published_at":    published_at,
            "cve_id":          None,
            "updated_at":      published_at,
            "severity":        "MEDIUM",
            "summary":         "test",
            "vulnerabilities": [],
        }

    @patch("poller.fetch_page")
    def test_first_run_uses_30_day_lookback(self, mock_fetch):
        mock_fetch.return_value = []
        db, _ = self._db(row=None)
        poll_once(self._prod(), db)
        since    = mock_fetch.call_args.args[0]
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        delta    = datetime.now(timezone.utc) - since_dt
        self.assertGreater(delta.days, 28)
        self.assertLess(delta.days, 32)

    @patch("poller.fetch_page")
    def test_resumes_from_saved_cursor(self, mock_fetch):
        mock_fetch.return_value = []
        saved_ts = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
        db, _    = self._db(row=(saved_ts, "GHSA-prev"))
        poll_once(self._prod(), db)
        self.assertEqual(mock_fetch.call_args.args[0], "2024-01-10T12:00:00Z")

    @patch("poller.fetch_page")
    def test_skips_last_seen_advisory(self, mock_fetch):
        saved_ts = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
        db, _    = self._db(row=(saved_ts, "GHSA-already-seen"))
        mock_fetch.return_value = [
            self._item("GHSA-already-seen", "2024-01-10T12:00:00Z"),
            self._item("GHSA-new-1111-2222", "2024-01-10T13:00:00Z"),
        ]
        prod = self._prod()
        poll_once(prod, db)
        self.assertEqual(prod.produce.call_count, 1)
        self.assertEqual(prod.produce.call_args.kwargs["key"], b"GHSA-new-1111-2222")

    @patch("poller.fetch_page")
    def test_cursor_advances_to_newest(self, mock_fetch):
        db, cur = self._db(row=None)
        mock_fetch.return_value = [
            self._item("GHSA-old-aaaa", "2024-01-10T10:00:00Z"),
            self._item("GHSA-new-bbbb", "2024-01-10T12:00:00Z"),
        ]
        poll_once(self._prod(), db)
        insert_calls = [c for c in cur.execute.call_args_list
                        if "INSERT INTO poller_state" in str(c.args[0])]
        self.assertEqual(len(insert_calls), 1)
        _, advisory_id = insert_calls[0].args[1]
        self.assertEqual(advisory_id, "GHSA-new-bbbb")

    @patch("poller.fetch_page")
    def test_state_not_committed_on_delivery_failure(self, mock_fetch):
        db, cur = self._db(row=None)
        mock_fetch.return_value = [
            self._item("GHSA-fail-1234", "2024-01-10T10:00:00Z"),
        ]
        prod = MagicMock()
        prod.flush.return_value = 0

        # Simulate the on_delivery callback being fired with an error
        def produce_with_error(*args, **kwargs):
            cb = kwargs.get("callback")
            if cb:
                mock_msg = MagicMock()
                mock_msg.key.return_value = b"GHSA-fail-1234"
                cb(Exception("Broker unavailable"), mock_msg)

        prod.produce.side_effect = produce_with_error
        poll_once(prod, db)

        insert_calls = [c for c in cur.execute.call_args_list
                        if "INSERT INTO poller_state" in str(c.args[0])]
        self.assertEqual(len(insert_calls), 0)
        db.commit.assert_not_called()

    @patch("poller.fetch_page")
    def test_no_state_change_when_only_cursor_advisory_returned(self, mock_fetch):
        saved_ts = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
        db, _    = self._db(row=(saved_ts, "GHSA-already-seen"))
        mock_fetch.return_value = [
            self._item("GHSA-already-seen", "2024-01-10T12:00:00Z"),
        ]
        prod = self._prod()
        poll_once(prod, db)
        prod.produce.assert_not_called()
        db.commit.assert_not_called()

    @patch("poller.fetch_page")
    def test_paginates_until_short_page(self, mock_fetch):
        """Should stop fetching when a page has fewer items than PER_PAGE."""
        db, _ = self._db(row=None)
        # First page: full (100 items); second page: 3 items → stop
        full_page  = [self._item(f"GHSA-page1-{i:04d}", "2024-01-10T10:00:00Z")
                      for i in range(100)]
        short_page = [self._item(f"GHSA-page2-{i:04d}", "2024-01-10T11:00:00Z")
                      for i in range(3)]
        mock_fetch.side_effect = [full_page, short_page]
        poll_once(self._prod(), db)
        self.assertEqual(mock_fetch.call_count, 2)


# ═══════════════════════════════════════════════════════════════════════════════
# write_match (sink)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWriteMatch(unittest.TestCase):

    def _match(self, **overrides):
        base = {
            "ghsa_id":           "GHSA-test-1234-5678",
            "repo":              "owner/myrepo",
            "package":           "requests",
            "installed_version": "2.31.0",
            "osv_vuln_ids":      ["GHSA-test-1234-5678", "CVE-2024-99999"],
            "detected_at":       "2024-01-15T10:00:00+00:00",
        }
        base.update(overrides)
        return base

    def test_executes_insert_with_correct_params(self):
        cur = MagicMock()
        cur.rowcount = 1
        write_match(cur, self._match())
        cur.execute.assert_called_once()
        sql, params = cur.execute.call_args.args
        self.assertIn("INSERT INTO affected_repos", sql)
        self.assertEqual(params[0], "GHSA-test-1234-5678")
        self.assertEqual(params[1], "owner/myrepo")
        self.assertEqual(params[2], "requests")
        self.assertEqual(params[3], "2.31.0")
        self.assertEqual(params[4], ["GHSA-test-1234-5678", "CVE-2024-99999"])
        self.assertEqual(params[5], "2024-01-15T10:00:00+00:00")

    def test_on_conflict_do_nothing_in_sql(self):
        cur = MagicMock()
        cur.rowcount = 0
        write_match(cur, self._match())
        sql = cur.execute.call_args.args[0]
        self.assertIn("ON CONFLICT", sql)
        self.assertIn("DO NOTHING", sql)

    def test_returns_true_on_new_row(self):
        cur = MagicMock()
        cur.rowcount = 1
        self.assertTrue(write_match(cur, self._match()))

    def test_returns_false_on_conflict(self):
        cur = MagicMock()
        cur.rowcount = 0   # ON CONFLICT DO NOTHING sets rowcount=0
        self.assertFalse(write_match(cur, self._match()))

    def test_osv_vuln_ids_passed_as_list(self):
        """psycopg2 converts Python list → PostgreSQL TEXT[] — must stay a list."""
        cur = MagicMock()
        cur.rowcount = 1
        write_match(cur, self._match())
        params = cur.execute.call_args.args[1]
        self.assertIsInstance(params[4], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)