import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import threatfeed as tf  # noqa: E402


def kev(*entries):
    return {"catalogVersion": "test", "vulnerabilities": [
        {"cveID": c, "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": f"{c} bug",
         "dateAdded": added, "dueDate": due, "knownRansomwareCampaignUse": ransom,
         "shortDescription": "desc | pipe", "requiredAction": "patch", "cwes": ["CWE-79"], "notes": ""}
        for c, added, due, ransom in entries
    ]}


class MergeTests(unittest.TestCase):
    def test_first_run_uses_date_added(self):
        recs = {}
        new = tf.merge_kev(recs, kev(("CVE-1", "2026-11-05", "2026-11-19", "Known"),
                                     ("CVE-2", "2026-01-01", "2026-01-15", "Unknown"),
                                     ("CVE-3", "2026-10-30", "2026-11-13", "Unknown")), "2026-11-05")
        self.assertEqual(sorted(new), ["CVE-1", "CVE-3"])  # first run reports the past week
        self.assertTrue(recs["CVE-1"]["ransomware"])
        self.assertFalse(recs["CVE-2"]["ransomware"])

    def test_later_run_marks_unseen_as_new_and_is_stable(self):
        recs = {}
        tf.merge_kev(recs, kev(("CVE-1", "2026-01-01", "2026-01-15", "Unknown")), "2026-11-04")
        feed = kev(("CVE-1", "2026-01-01", "2026-01-15", "Unknown"), ("CVE-9", "2026-11-03", "2026-11-17", "Unknown"))
        self.assertEqual(tf.merge_kev(recs, feed, "2026-11-05"), ["CVE-9"])
        # re-running the same day still reports it
        self.assertEqual(tf.merge_kev(recs, feed, "2026-11-05"), ["CVE-9"])


class EpssTests(unittest.TestCase):
    def setUp(self):
        self.recs = {}
        tf.merge_kev(self.recs, kev(("CVE-1", "2026-01-01", "2026-01-15", "Unknown"),
                                    ("CVE-2", "2026-01-01", "2026-01-15", "Known")), "2026-11-05")

    def test_prev_score_kept_across_same_day_reruns(self):
        tf.apply_epss(self.recs, {"CVE-1": (0.10, 0.5), "CVE-2": (0.50, 0.9)}, "2026-11-04")
        tf.apply_epss(self.recs, {"CVE-1": (0.40, 0.8), "CVE-2": (0.45, 0.9)}, "2026-11-05")
        tf.apply_epss(self.recs, {"CVE-1": (0.40, 0.8), "CVE-2": (0.45, 0.9)}, "2026-11-05")
        mv = tf.movers(self.recs)
        self.assertEqual(mv[0][0]["cve"], "CVE-1")
        self.assertAlmostEqual(mv[0][1], 0.30)

    def test_top_and_ransomware_filter(self):
        tf.apply_epss(self.recs, {"CVE-1": (0.9, 0.99), "CVE-2": (0.2, 0.7)}, "2026-11-05")
        self.assertEqual([r["cve"] for r in tf.top_epss(self.recs)], ["CVE-1", "CVE-2"])
        self.assertEqual([r["cve"] for r in tf.top_epss(self.recs, ransomware=True)], ["CVE-2"])


class DigestTests(unittest.TestCase):
    def test_digest_escapes_pipes_and_keeps_notes(self):
        recs = {}
        new = tf.merge_kev(recs, kev(("CVE-1", "2026-11-05", "2026-11-08", "Known")), "2026-11-05")
        md = tf.build_digest(recs, new, {"catalogVersion": "x"}, date(2026, 11, 5), False, "- 09:00 my note")
        self.assertIn("desc \\| pipe", md)
        self.assertIn("not refreshed", md)
        self.assertIn("- 09:00 my note", md)
        self.assertIn("Federal remediation deadlines", md)

    def test_existing_notes_round_trip(self):
        md = tf.build_digest({}, [], {}, date(2026, 11, 5), True, "")
        path = Path(__file__).parent / "_tmp_digest.md"
        try:
            path.write_text(md, encoding="utf-8")
            self.assertEqual(tf.existing_notes(path), "")
            path.write_text(tf.build_digest({}, [], {}, date(2026, 11, 5), True, "- a\n- b"), encoding="utf-8")
            self.assertEqual(tf.existing_notes(path), "- a\n- b")
        finally:
            path.unlink(missing_ok=True)


class SiteSummaryTests(unittest.TestCase):
    def test_summary_shape(self):
        recs = {}
        new = tf.merge_kev(recs, kev(("CVE-1", "2026-11-05", "2026-11-08", "Known"),
                                     ("CVE-2", "2026-10-01", "2026-10-22", "Unknown")), "2026-11-05")
        tf.apply_epss(recs, {"CVE-1": (0.9, 0.99), "CVE-2": (0.1, 0.5)}, "2026-11-05")
        s = tf.build_site_summary(recs, new, {"catalogVersion": "v"}, date(2026, 11, 5), True)
        self.assertEqual(s["schema"], tf.SITE_SCHEMA)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["ransomware"], 1)
        self.assertEqual([r["cve"] for r in s["new"]], ["CVE-1"])
        self.assertEqual(len(s["history"]), 30)
        self.assertEqual(s["history"][-1], {"date": "2026-11-05", "count": 1})
        self.assertEqual(s["top"][0]["cve"], "CVE-1")
        self.assertNotIn("description", s["top"][0])  # keep the payload small


if __name__ == "__main__":
    unittest.main()
