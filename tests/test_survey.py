import base64
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_diag.backends import DemoBackend
from wifi_diag.survey import Survey
from wifi_diag.web.server import make_server
from wifi_diag.web.state import AppState

from ie_builder import *  # noqa: F401,F403
from test_web import Client

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64          # для проверок достаточно сигнатуры
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


def b64(data):
    return base64.b64encode(data).decode("ascii")


class SurveyUnitTests(unittest.TestCase):
    def test_plan_validation(self):
        s = Survey()
        with self.assertRaises(ValueError):
            s.add_point(0.5, 0.5)                          # без плана нельзя
        for mime, data in (("image/gif", PNG), ("image/png", JPG), ("image/png", b"x" * 10)):
            with self.assertRaises(ValueError):
                s.set_plan(mime, b64(data))
        with self.assertRaises(ValueError):
            s.set_plan("image/png", "@@@не base64@@@")
        s.set_plan("image/jpeg", b64(JPG), "Этаж 3")
        self.assertEqual((s.has_plan, s.name, s.plan_rev), (True, "Этаж 3", 1))

    def test_points_fill_only_from_scan_started_after_click(self):
        s = Survey()
        s.set_plan("image/png", b64(PNG))
        p1 = s.add_point(0.1, 0.2, t=100.0)
        with self.assertRaises(ValueError):
            s.add_point(0.4, 0.4, t=100.5)                 # пока предыдущая точка ждёт скан, новую не принимаем
        for bad in ((-0.1, 0.5), (0.5, 1.5), ("0.5", 0.5), (True, 0.5), (float("nan"), 0.5)):
            with self.assertRaises(ValueError):
                s.add_point(*bad)
        bss = [make_bss("02:00:00:00:10:01", "CORP", CH36, -61, rsn_ie([1]))]
        self.assertEqual(s.fill(99.0, bss, None), 0)       # скан начат ДО клика - не годится
        self.assertTrue(s.pending_after(99.0))
        self.assertEqual(s.fill(101.0, bss, {"ssid": "CORP", "bssid": "02:00:00:00:10:01", "rssi": -60}), 1)
        self.assertEqual(p1["status"], "done")
        self.assertEqual(p1["results"]["02:00:00:00:10:01"], ["CORP", "5", 36, -61])
        self.assertEqual(p1["conn"]["rssi"], -60)
        s.add_point(0.3, 0.3, t=200.0)
        s.fail_pending(201.0, "адаптер выключен")
        self.assertEqual(s.points[-1]["status"], "failed")
        self.assertTrue(s.delete(p1["id"]))
        self.assertFalse(s.delete(999))

    def test_project_roundtrip_and_hostile_input(self):
        s = Survey()
        s.set_plan("image/png", b64(PNG), "План")
        p = s.add_point(0.25, 0.75, t=10.0)
        s.fill(11.0, [make_bss("02:00:00:00:10:02", "<b>x</b>", CH1, -70, rsn_ie([2]))], None)
        proj = json.loads(json.dumps(s.to_project()))
        s2 = Survey()
        rev0 = s2.rev
        s2.load_project(proj)
        self.assertGreater(s2.rev, rev0)
        self.assertEqual(s2.plan, PNG)
        self.assertEqual([(q["x"], q["y"], q["status"]) for q in s2.points], [(0.25, 0.75, "done")])
        self.assertEqual(s2.points[0]["results"]["02:00:00:00:10:02"], ["<b>x</b>", "2.4", 1, -70])
        bad = dict(proj, points=[{"x": 2, "y": 0.5}])
        with self.assertRaises(ValueError):
            Survey().load_project(bad)
        with self.assertRaises(ValueError):
            Survey().load_project({"format": "other"})
        junk = dict(proj, points=[dict(proj["points"][0], results={"aa": ["x", "5", 36, "evil"], "b" * 40: ["x", "5", 1, -50]})])
        s3 = Survey()
        s3.load_project(junk)
        self.assertEqual(s3.points[0]["results"], {})          # мусорные записи отброшены
        self.assertEqual(p["id"], 1)


class SurveyApiTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(DemoBackend(seed=3), None)
        self.server = make_server(self.state)
        self.th = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.th.start()
        self.state.start_monitors()
        self.c = Client(self.server, self.server.token)

    def tearDown(self):
        self.state.stop_monitors()
        self.server.shutdown()
        self.server.server_close()

    def wait(self, cond, timeout=8.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if cond():
                return True
            time.sleep(0.05)
        self.fail("не дождались")

    def test_survey_flow(self):
        self.assertEqual(self.c.j("POST", "/api/survey/point", {"x": 0.5, "y": 0.5})[0], 400)    # нет плана
        self.assertEqual(self.c.req("GET", "/api/survey/plan")[0], 404)
        self.assertEqual(self.c.j("POST", "/api/survey/plan", {"mime": "image/png", "data": b64(PNG), "name": "Этаж 2"})[0], 200)
        st, hd, raw = self.c.req("GET", "/api/survey/plan")
        self.assertEqual((st, hd["Content-Type"], raw), (200, "image/png", PNG))
        st, p = self.c.j("POST", "/api/survey/point", {"x": 0.3, "y": 0.6})
        self.assertEqual((st, p["status"]), (200, "pending"))
        self.wait(lambda: self.c.j("GET", "/api/survey/points")[1]["points"][0]["status"] == "done")
        pts = self.c.j("GET", "/api/survey/points")[1]["points"]
        self.assertGreater(len(pts[0]["results"]), 10)
        self.assertIsNotNone(pts[0]["conn"])                    # демо-журнал: ноутбук подключён
        # вторая точка во время скана: после текущего скана запускается ещё один
        self.c.j("POST", "/api/scan", {"interface": 0, "wait": 1})
        self.c.j("POST", "/api/survey/point", {"x": 0.7, "y": 0.2})
        self.wait(lambda: all(q["status"] == "done" for q in self.c.j("GET", "/api/survey/points")[1]["points"]))
        st, hd, raw = self.c.req("GET", "/api/survey/project")
        self.assertIn("attachment", hd["Content-Disposition"])
        proj = json.loads(raw)
        self.assertEqual(self.c.j("POST", "/api/survey/clear", {})[0], 200)
        self.assertEqual(self.c.j("GET", "/api/survey/points")[1]["points"], [])
        self.assertEqual(self.c.j("POST", "/api/survey/project", proj)[0], 200)
        self.assertEqual(len(self.c.j("GET", "/api/survey/points")[1]["points"]), 2)
        pid = self.c.j("GET", "/api/survey/points")[1]["points"][0]["id"]
        self.assertEqual(self.c.j("POST", "/api/survey/delete", {"id": pid})[0], 200)
        self.assertEqual(self.c.j("POST", "/api/survey/delete", {"id": pid})[0], 404)
        self.assertEqual(self.c.j("POST", "/api/survey/plan", {"mime": "image/svg+xml", "data": b64(b"<svg/>")})[0], 400)
        self.assertEqual(Client(self.server, None).req("GET", "/api/survey/plan")[0], 403)

    def test_journal_in_state_and_export(self):
        self.wait(lambda: len(self.c.j("GET", "/api/state")[1]["conn"]["events"]) >= 5)
        _, d = self.c.j("GET", "/api/state")
        conn = d["conn"]
        self.assertEqual(conn["current"]["state"], "connected")
        kinds = {e["kind"] for e in conn["events"]}
        self.assertTrue({"roam", "disconnected", "pingpong", "sticky"} <= kinds)
        self.assertGreater(len(conn["samples"]), 250)
        self.assertIn("демо", conn["status"])
        st, hd, raw = self.c.req("GET", "/api/export/journal")
        self.assertEqual(st, 200)
        lines = raw.decode("utf-8-sig").splitlines()
        self.assertTrue(lines[0].startswith("time;event;"))
        self.assertTrue(any("deauth" in ln for ln in lines))
        self.assertEqual(self.c.j("POST", "/api/conn/clear", {})[0], 200)
        self.assertLessEqual(len(self.c.j("GET", "/api/state")[1]["conn"]["events"]), 1)


if __name__ == "__main__":
    unittest.main()
