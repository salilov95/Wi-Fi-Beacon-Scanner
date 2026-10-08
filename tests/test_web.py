import http.client
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_diag.backends import DemoBackend
from wifi_diag.model import Snapshot
from wifi_diag.web.server import app_url, make_server
from wifi_diag.web.state import AppState

from ie_builder import *  # noqa: F401,F403


class Client:
    def __init__(self, server, token=None):
        self.server, self.token = server, token

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        h = dict(headers or {})
        if self.token is not None:
            h.setdefault("X-Token", self.token)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, dict(r.getheaders()), raw

    def j(self, method, path, body=None, headers=None):
        st, hd, raw = self.req(method, path, body, headers)
        return st, (json.loads(raw) if raw else None)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(DemoBackend(seed=1), None)
        self.state.refresh_interfaces()
        self.server = make_server(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.c = Client(self.server, self.server.token)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def scan_and_wait(self):
        before = self.state.scan_count
        st, _ = self.c.j("POST", "/api/scan", {"interface": 0, "wait": 1})
        self.assertEqual(st, 202)
        for _ in range(100):
            time.sleep(0.05)
            if not self.state.scanning and self.state.scan_count > before:
                return
        self.fail("скан не завершился")

    # ---- доступ ----
    def test_token_required(self):
        anon = Client(self.server, None)
        st0, _, shell = anon.req("GET", "/")          # оболочка без данных отдаётся и без токена
        self.assertEqual(st0, 200)
        self.assertNotIn(self.server.token.encode(), shell)
        self.assertEqual(anon.req("GET", "/api/state")[0], 403)
        self.assertEqual(anon.req("POST", "/api/scan", {})[0], 403)
        self.assertEqual(Client(self.server, "wrong").req("GET", "/api/state")[0], 403)
        st, hd, raw = anon.req("GET", "/?t=" + self.server.token)
        self.assertEqual(st, 200)
        self.assertIn(b"/app.js", raw)
        self.assertIn("script-src 'self'", hd["Content-Security-Policy"])
        self.assertTrue(app_url(self.server).startswith("http://127.0.0.1:"))

    def test_bad_host_and_origin_rejected(self):
        self.assertEqual(self.c.req("GET", "/api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.c.req("GET", "/api/state", headers={"Origin": "http://evil.example"})[0], 403)

    def test_static_whitelist(self):
        self.assertEqual(self.c.req("GET", "/app.js")[0], 200)
        self.assertEqual(self.c.req("GET", "/app.css")[0], 200)
        self.assertEqual(self.c.req("GET", "/../server.py")[0], 404)   # вне белого списка
        self.assertEqual(self.c.req("GET", "/static/app.js")[0], 404)
        self.assertEqual(self.c.req("GET", "/etc/passwd")[0], 404)

    # ---- работа ----
    def test_scan_flow_history_and_busy(self):
        st, d = self.c.j("GET", "/api/state")
        self.assertEqual((st, d["bss"], d["backend"], d["interfaces"]), (200, [], "demo", ["Demo adapter"]))
        st1, _ = self.c.j("POST", "/api/scan", {"interface": 0, "wait": 1})
        st2, _ = self.c.j("POST", "/api/scan", {"interface": 0, "wait": 1})
        self.assertEqual((st1, st2), (202, 409))      # второй запуск во время скана отклонён
        for _ in range(100):
            time.sleep(0.05)
            if not self.state.scanning:
                break
        self.scan_and_wait()
        _, d = self.c.j("GET", "/api/state")
        self.assertEqual(d["scan_count"], 2)
        self.assertGreater(len(d["bss"]), 10)
        self.assertTrue(d["findings"])
        some = d["bss"][0]["bssid"]
        self.assertEqual(len(d["history"][some]), 2)
        for k in ("bssid", "ssid", "band", "channel", "center", "width", "rssi", "security", "k", "r", "v", "ie_tree", "cap"):
            self.assertIn(k, d["bss"][0])

    def test_config_focus_changes_findings(self):
        self.scan_and_wait()
        _, d0 = self.c.j("GET", "/api/state")
        self.assertEqual(self.c.j("POST", "/api/config", {"focus": ["CORP"]})[0], 200)
        _, d1 = self.c.j("GET", "/api/state")
        self.assertEqual(d1["focus"], ["CORP"])
        self.assertNotEqual(len(d0["findings"]), len(d1["findings"]))
        self.assertTrue(any(f["code"].startswith("ROAM_11R") for f in d1["findings"]))
        self.assertEqual(self.c.j("POST", "/api/config", {"focus": "CORP"})[0], 400)

    def test_export(self):
        self.assertEqual(self.c.j("GET", "/api/export/html")[0], 409)   # данных ещё нет
        self.scan_and_wait()
        st, hd, raw = self.c.req("GET", "/api/export/html")
        self.assertEqual(st, 200)
        self.assertIn("attachment", hd["Content-Disposition"])
        self.assertIn("<!doctype html>", raw.decode("utf-8"))
        st, hd, raw = self.c.req("GET", "/api/export/csv")
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        snap = Snapshot.from_json(self.c.req("GET", "/api/export/json")[2].decode("utf-8"))
        self.assertEqual(len(snap.bss), len(self.state.snapshot.bss))
        self.assertEqual(self.c.req("GET", "/api/export/exe")[0], 404)

    def test_load_snapshot_and_bad_input(self):
        snap = Snapshot("2026-10-08T00:00:00+03:00", "x", [make_bss("02:00:00:00:00:01", "a", CH1, -50, rsn_ie([2]))])
        self.assertEqual(self.c.j("POST", "/api/load", json.loads(snap.to_json()))[0], 200)
        _, d = self.c.j("GET", "/api/state")
        self.assertEqual([b["ssid"] for b in d["bss"]], ["a"])
        self.assertEqual(self.c.j("POST", "/api/load", {"version": 99})[0], 400)
        self.assertEqual(self.c.j("POST", "/api/load", [1, 2, 3])[0], 400)
        st, _, _ = self.c.req("POST", "/api/load", headers={"Content-Length": "9999999999"})
        self.assertEqual(st, 400)

    def test_hostile_ssid_is_escaped_in_html_export(self):
        evil = '<img src=x onerror=alert(1)>'
        snap = Snapshot("t", "x", [make_bss("02:00:00:00:00:02", evil, CH6, -50, rsn_ie([2]))])
        self.state.load_snapshot(snap)
        _, _, raw = self.c.req("GET", "/api/export/html")
        self.assertNotIn(evil.encode(), raw)
        self.assertIn(b"&lt;img src=x onerror=alert(1)&gt;", raw)

    def test_history_csv_advice_and_tree(self):
        self.scan_and_wait()
        self.scan_and_wait()
        st, hd, raw = self.c.req("GET", "/api/export/history")
        self.assertEqual(st, 200)
        lines = raw.decode("utf-8-sig").splitlines()
        self.assertTrue(lines[0].startswith("time;ssid;bssid"))
        self.assertGreater(len(lines), 10)
        _, d = self.c.j("GET", "/api/state")
        self.assertIn("2.4", d["advice"])
        self.assertTrue(any(r["best"] for r in d["advice"]["2.4"]))
        self.assertTrue(any(t["id"] == 0 for t in d["bss"][0]["ie_tree"]))
        self.assertIn("cap", d["bss"][0])

    def test_baseline_diff_and_stats(self):
        self.assertEqual(self.c.j("POST", "/api/baseline", {"current": True})[0], 409)   # данных ещё нет
        self.scan_and_wait()
        _, d = self.c.j("GET", "/api/state")
        self.assertIsNone(d["baseline"])
        self.assertIsNone(d["diff"])
        b0 = d["bss"][0]
        self.assertEqual((b0["seen"], b0["seen_pct"], b0["rssi_min"], b0["rssi_max"]), (1, 100, b0["rssi"], b0["rssi"]))
        self.assertEqual(self.c.j("POST", "/api/baseline", {"current": True})[0], 200)
        _, d = self.c.j("GET", "/api/state")
        self.assertTrue(d["baseline"]["is_current"])
        self.assertIsNone(d["diff"])            # сравнивать снапшот с самим собой незачем
        self.scan_and_wait()
        _, d = self.c.j("GET", "/api/state")
        self.assertFalse(d["baseline"]["is_current"])
        self.assertEqual(set(d["diff"]), {"added", "removed", "changed", "rssi", "rssi_delta", "same"})
        other = Snapshot("2026-01-01T00:00:00+03:00", "x", [make_bss("02:00:00:00:0f:01", "old-net", CH1, -50, rsn_ie([2]))])
        self.assertEqual(self.c.j("POST", "/api/baseline", json.loads(other.to_json()))[0], 200)
        _, d = self.c.j("GET", "/api/state")
        self.assertEqual([x["ssid"] for x in d["diff"]["removed"]], ["old-net"])
        self.assertEqual(len(d["diff"]["added"]), len(d["bss"]))
        self.assertEqual(self.c.j("POST", "/api/baseline", {"clear": True})[0], 200)
        self.assertIsNone(self.c.j("GET", "/api/state")[1]["baseline"])
        self.assertEqual(self.c.j("POST", "/api/baseline", {"version": 5})[0], 400)

    def test_export_scopes(self):
        self.scan_and_wait()
        st, _, raw = self.c.req("POST", "/api/export/csv", {"scope": "focus"})
        self.assertEqual(st, 400)                                   # «Мои SSID» не заданы
        self.assertIn("Мои SSID", json.loads(raw)["error"])
        self.c.j("POST", "/api/config", {"focus": ["CORP"]})
        rows = self.c.req("POST", "/api/export/csv", {"scope": "focus"})[2].decode("utf-8-sig").splitlines()[1:]
        self.assertTrue(rows and all(r.split(";")[0] == "CORP" for r in rows))
        st, hd, raw = self.c.req("POST", "/api/export/html", {"scope": "focus"})
        self.assertIn("wifi-report-my.html", hd["Content-Disposition"])
        html = raw.decode("utf-8")
        self.assertIn("только мои SSID: CORP", html)
        body = html.split("<tbody>")[1]
        self.assertNotIn("Neighbor-2G", body)
        all_rows = self.c.req("POST", "/api/export/csv", {"scope": "all"})[2].decode("utf-8-sig").splitlines()[1:]
        self.assertGreater(len(all_rows), len(rows))
        pick = [self.state.snapshot.bss[0].bssid, self.state.snapshot.bss[1].bssid]
        js = json.loads(self.c.req("POST", "/api/export/json", {"scope": "list", "bssids": pick})[2])
        self.assertEqual(sorted(b["bssid"] for b in js["bss"]), sorted(pick))
        self.assertEqual(self.c.req("POST", "/api/export/csv", {"scope": "list", "bssids": ["aa:bb:cc:dd:ee:ff"]})[0], 400)
        self.assertEqual(self.c.req("POST", "/api/export/csv", {"scope": "list", "bssids": "x"})[0], 400)
        self.assertEqual(self.c.req("POST", "/api/export/csv", {"scope": "zzz"})[0], 400)
        self.assertEqual(self.c.req("POST", "/api/export/exe", {"scope": "all"})[0], 404)
        self.assertEqual(Client(self.server, None).req("POST", "/api/export/csv", {"scope": "all"})[0], 403)
        _, d = self.c.j("GET", "/api/state")
        self.assertTrue(d["util"]["channels"])
        self.assertIn(d["util"]["channels"][0]["level"], ("low", "mid", "high", "crit"))

    def test_quit_stops_server(self):
        self.assertEqual(self.c.j("POST", "/api/quit", {})[0], 200)
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())


class PrefsTests(unittest.TestCase):
    def test_sanitize_drops_unknown_and_hostile_values(self):
        from wifi_diag.web.state import sanitize_prefs
        dirty = {"theme": '"><script>alert(1)</script>', "density": "compact", "cols": ["rssi", "<b>", 5, "trend"],
                 "panelH": 99999, "tab": "nope", "group": "yes", "evil": 1, "focus": ["  CORP ", "", 3], "v": 2}
        self.assertEqual(sanitize_prefs(dirty), {"density": "compact", "cols": ["rssi", "trend"], "focus": ["CORP"], "v": 2})
        self.assertEqual(sanitize_prefs("x"), {})
        self.assertEqual(sanitize_prefs({"theme": "nord", "panelH": 320, "group": True})["theme"], "nord")

    def test_prefs_persist_on_disk_and_theme_goes_into_html(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "prefs.json")
            st = AppState(DemoBackend(seed=1), None, prefs_path=path)
            server = make_server(st)
            th = threading.Thread(target=server.serve_forever, daemon=True)
            th.start()
            try:
                c = Client(server, server.token)
                self.assertEqual(c.j("GET", "/api/prefs"), (200, {}))
                self.assertEqual(Client(server, None).req("POST", "/api/prefs", {"theme": "nord"})[0], 403)
                self.assertEqual(c.j("POST", "/api/prefs", {"theme": "nord", "density": "compact", "x": "<i>"})[1],
                                 {"theme": "nord", "density": "compact"})
                self.assertEqual(c.j("POST", "/api/config", {"focus": ["CORP", "Guest"]})[0], 200)
                html = c.req("GET", "/")[2]
                self.assertIn(b'<html lang="ru" data-theme="nord" data-density="compact">', html)
            finally:
                server.shutdown()
                server.server_close()
            st2 = AppState(DemoBackend(seed=1), None, prefs_path=path)      # «следующий запуск»
            self.assertEqual(st2.prefs["theme"], "nord")
            self.assertEqual(st2.focus, ["CORP", "Guest"])
            self.assertEqual(AppState(DemoBackend(seed=1), None, ["X"], prefs_path=path).focus, ["X"])  # --ssid важнее
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            self.assertEqual(AppState(DemoBackend(seed=1), None, prefs_path=path).prefs, {})  # битый файл не роняет


if __name__ == "__main__":
    unittest.main()
