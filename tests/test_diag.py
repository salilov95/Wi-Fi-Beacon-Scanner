"""Диагностика первого запуска: журнал в файл, отказ Windows в доступе к сканированию, пустой скан."""
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_beacon_scanner.backends import Backend
from wifi_beacon_scanner.model import LOCATION_HINT, ScanAccessDenied, Snapshot, now_iso
from wifi_beacon_scanner.web.server import make_server
from wifi_beacon_scanner.web.state import AppState

from test_web import Client


class FakeBackend(Backend):
    name = "fake"

    def __init__(self, results, gate=None):
        self.results = list(results)
        self.gate = gate            # threading.Event: скан ждёт его, чтобы тест увидел состояние «идёт скан»

    def interfaces(self):
        return ["Fake adapter"]

    def scan(self, interface_index, wait_s):
        r = self.results.pop(0)
        if self.gate is not None and not isinstance(r, Exception):
            self.gate.wait(5)
        if isinstance(r, Exception):
            raise r
        return r


def wait_scan(state):
    for _ in range(200):
        if not state.scanning:
            return
        time.sleep(0.01)
    raise AssertionError("скан не закончился")


class ScanErrorTests(unittest.TestCase):
    def test_location_denied_has_kind_and_hint_then_recovers(self):
        empty_then_ok = Snapshot(taken_at=now_iso(), interface="Fake adapter", bss=[])
        gate = threading.Event()
        st = AppState(FakeBackend([ScanAccessDenied(), empty_then_ok], gate), None)
        st.start_scan(0, 0)
        wait_scan(st)
        d = st.to_dict()
        self.assertEqual((d["error_kind"], d["error"]), ("location", LOCATION_HINT))
        self.assertIn("расположени", d["error"])
        st.start_scan(0, 0)
        self.assertEqual(st.to_dict()["error_kind"], "location")   # пока идёт новый скан, плашка не мигает
        gate.set()
        wait_scan(st)
        d = st.to_dict()
        self.assertEqual((d["error"], d["error_kind"]), (None, ""))
        self.assertIsNotNone(d["taken_at"])

    def test_empty_scan_is_logged(self):
        st = AppState(FakeBackend([Snapshot(taken_at=now_iso(), interface="Fake adapter", bss=[])]), None)
        with self.assertLogs("wifi_beacon_scanner.web.state", "WARNING") as cm:
            st.start_scan(0, 0)
            wait_scan(st)
        self.assertIn("пустой список", "\n".join(cm.output))
        self.assertIsNotNone(st.to_dict()["last_scan_ms"])

    def test_other_errors_are_logged_with_traceback(self):
        st = AppState(FakeBackend([OSError("WlanOpenHandle: код ошибки 1062")]), None)
        with self.assertLogs("wifi_beacon_scanner.web.state", "ERROR"):
            st.start_scan(0, 0)
            wait_scan(st)
        self.assertEqual(st.to_dict()["error_kind"], "")


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(FakeBackend([]), None)
        self.server = make_server(self.state)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.c = Client(self.server, self.server.token)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_clientlog_goes_to_program_log(self):
        with self.assertLogs("wifi_beacon_scanner.page", "WARNING") as cm:
            st, _ = self.c.j("POST", "/api/clientlog", {"level": "error", "msg": "TypeError: x\nat app.js:1"})
        self.assertEqual(st, 200)
        self.assertIn("TypeError: x | at app.js:1", cm.output[0])

    def test_clientlog_needs_token_and_is_rate_limited(self):
        self.assertEqual(Client(self.server, "bad").j("POST", "/api/clientlog", {"msg": "x"})[0], 403)
        with self.assertLogs("wifi_beacon_scanner.page", "WARNING") as cm:
            for i in range(70):
                self.c.j("POST", "/api/clientlog", {"msg": "m%d" % i})
        self.assertEqual(len(cm.output), 60)

    def test_open_target(self):
        self.assertEqual(self.c.j("POST", "/api/open", {"target": "calc.exe"})[0], 400)
        if sys.platform != "win32":
            st, d = self.c.j("POST", "/api/open", {"target": "logs"})
            self.assertEqual(st, 200)
            self.assertFalse(d["ok"])
            self.assertTrue(d["path"].endswith("logs"))


class AppLogTests(unittest.TestCase):
    def test_log_file_and_uncaught_exception(self):
        with tempfile.TemporaryDirectory() as d:
            code = ("import sys, logging, threading; sys.path.insert(0, %r)\n"
                    "from wifi_beacon_scanner import applog\n"
                    "print(applog.setup(directory=sys.argv[1]))\n"
                    "logging.getLogger('wifi_beacon_scanner.x').warning('проверка')\n"
                    "t = threading.Thread(target=lambda: 1 / 0); t.start(); t.join()\n" % ROOT)
            r = subprocess.run([sys.executable, "-c", code, d], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(r.returncode, 0, r.stderr)
            path = os.path.join(d, "app.log")
            self.assertEqual(r.stdout.strip(), path)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertIn("запуск", text)
            self.assertIn("проверка", text)
            self.assertIn("ZeroDivisionError", text)

    def test_unwritable_dir_does_not_break_start(self):
        with tempfile.TemporaryDirectory() as d:
            blocker = os.path.join(d, "file")
            open(blocker, "w").close()
            code = ("import sys; sys.path.insert(0, %r)\n"
                    "from wifi_beacon_scanner import applog\n"
                    "print(applog.setup(directory=sys.argv[1]))\n" % ROOT)
            r = subprocess.run([sys.executable, "-c", code, os.path.join(blocker, "sub")], capture_output=True,
                               text=True, encoding="utf-8")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "None")


if __name__ == "__main__":
    unittest.main()
