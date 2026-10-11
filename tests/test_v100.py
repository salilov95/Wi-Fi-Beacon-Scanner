"""1.0.0: проверка обновлений, «О программе», журнал Windows в демо, журнал программы без шума."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_beacon_scanner import update
from wifi_beacon_scanner.backends import DemoBackend
from wifi_beacon_scanner.model import Snapshot, now_iso
from wifi_beacon_scanner.web.server import make_server
from wifi_beacon_scanner.web.state import AppState, sanitize_prefs

from test_diag import FakeBackend, wait_scan
from test_web import Client


class UpdateTests(unittest.TestCase):
    def test_newer_release(self):
        d = update.check("0.9.0", fetch=lambda url, t: {"tag_name": "v1.0.0", "html_url": "https://x/r/1.0.0",
                                                         "published_at": "2026-10-12T00:00:00Z"})
        self.assertEqual((d["latest"], d["newer"], d["url"], d["error"]), ("1.0.0", True, "https://x/r/1.0.0", ""))

    def test_same_or_older(self):
        self.assertFalse(update.check("1.0.0", fetch=lambda u, t: {"tag_name": "v1.0.0"})["newer"])
        self.assertTrue(update.check("1.2.0", fetch=lambda u, t: {"tag_name": "v1.10.0"})["newer"])   # не строковое сравнение

    def test_network_error_is_reported_not_raised(self):
        def boom(url, t):
            raise OSError("proxy refused")
        d = update.check("1.0.0", fetch=boom)
        self.assertIn("proxy refused", d["error"])
        self.assertFalse(d["newer"])

    def test_parse_version(self):
        self.assertEqual(update.parse_version("v1.2.3-beta"), (1, 2, 3))
        self.assertIsNone(update.parse_version("latest"))


class AboutAndWinlogTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(DemoBackend(seed=1), None)
        self.server = make_server(self.state)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.c = Client(self.server, self.server.token)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_about(self):
        from wifi_beacon_scanner import __version__
        st, d = self.c.j("GET", "/api/about")
        self.assertEqual((st, d["version"], d["backend"]), (200, __version__, "demo"))
        self.assertIn("log_dir", d)

    def test_demo_winlog_respects_hours_and_has_fields(self):
        _, day = self.c.j("GET", "/api/winlog?hours=24")
        _, hour = self.c.j("GET", "/api/winlog?hours=1")
        self.assertGreater(len(day["events"]), len(hour["events"]))
        self.assertTrue(all(e["t"] >= time.time() - 3600 - 5 for e in hour["events"]))
        fail = [e for e in day["events"] if e["id"] == 8002]
        self.assertTrue(fail and fail[0]["reason"] and fail[0]["data"].get("ReasonCode"))

    def test_winlog_is_a_remembered_tab(self):
        self.assertEqual(sanitize_prefs({"tab": "winlog"}), {"tab": "winlog"})


class ScanLogTests(unittest.TestCase):
    def snap(self, n):
        from wifi_beacon_scanner.demo import build_demo_snapshot
        return Snapshot(taken_at=now_iso(), interface="Fake", bss=build_demo_snapshot().bss[:n])

    def test_quiet_log(self):
        st = AppState(FakeBackend([self.snap(5), self.snap(6), OSError("x"), OSError("x"), self.snap(4)]), None)
        with self.assertLogs("wifi_beacon_scanner.web.state", "INFO") as cm:
            for _ in range(5):
                st.start_scan(0, 0)
                wait_scan(st)
        out = "\n".join(cm.output)
        self.assertIn("первый скан", out)
        self.assertEqual(out.count("скан не удался"), 1)          # одна и та же ошибка подряд - один раз
        self.assertIn("скан снова работает", out)
        self.assertEqual(len(cm.output), 3)


if __name__ == "__main__":
    unittest.main()
