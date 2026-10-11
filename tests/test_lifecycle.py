import os
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_beacon_scanner.backends import DemoBackend
from wifi_beacon_scanner.web.server import Lifeline, make_server
from wifi_beacon_scanner.web.state import AppState

from test_web import Client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class LifelineTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock()
        self.l = Lifeline(idle_s=900, first_s=300, bye_grace_s=5, clock=self.c)

    def test_bye_then_silence_exits(self):
        self.l.touch()
        self.c.t += 10
        self.l.bye()
        self.c.t += 3
        self.assertIsNone(self.l.should_exit())
        self.c.t += 3
        self.assertEqual(self.l.should_exit(), "окно закрыто")

    def test_reload_cancels_bye(self):
        self.l.touch(); self.l.bye()
        self.c.t += 1
        self.l.touch()                     # новая страница начала опрос
        self.c.t += 60
        self.assertIsNone(self.l.should_exit())

    def test_idle_and_never_opened(self):
        self.c.t += 299
        self.assertIsNone(self.l.should_exit())
        self.c.t += 2
        self.assertEqual(self.l.should_exit(), "окно так и не открылось")
        self.l.touch()
        self.c.t += 899
        self.assertIsNone(self.l.should_exit())   # свёрнутое окно опрашивает редко - это не повод выходить
        self.c.t += 2
        self.assertIn("не отвечает", self.l.should_exit())


class FakeWindow:
    def __init__(self):
        self.code = None

    def poll(self):
        return self.code


class OwnWindowTests(unittest.TestCase):
    """Своё окно Edge: пока его процесс жив, тишина (свёрнуто, страница усыплена) - не повод выходить."""

    def setUp(self):
        self.c = Clock()
        self.l = Lifeline(idle_s=900, first_s=300, bye_grace_s=5, clock=self.c)
        self.w = FakeWindow()
        self.l.attach_window(self.w)

    def test_minimized_and_frozen_for_hours_keeps_running(self):
        self.l.touch()
        self.c.t += 6 * 3600
        self.assertIsNone(self.l.should_exit())

    def test_hidden_page_discarded_without_bye_keeps_running(self):
        self.l.touch()
        self.c.t += 4000
        self.l.touch()                      # страницу перезагрузили после выгрузки - работает дальше
        self.assertIsNone(self.l.should_exit())

    def test_window_process_exit_means_closed(self):
        self.l.touch()
        self.c.t += 30
        self.w.code = 0
        self.assertIsNone(self.l.should_exit())     # пару секунд ждём: вдруг Edge перезапустился
        self.c.t += 5
        self.assertEqual(self.l.should_exit(), "окно Edge закрыто")

    def test_edge_relaunched_itself_page_keeps_polling(self):
        """Первый запуск с новым профилем: процесс Edge завершился, но окно живо и страница опрашивает программу."""
        self.l.touch()
        self.c.t += 3
        self.w.code = 0
        self.assertIsNone(self.l.should_exit())
        for _ in range(3):
            self.c.t += 1
            self.l.touch()
            self.assertIsNone(self.l.should_exit())
        self.assertIsNone(self.l.window)            # дальше следим по запросам
        self.c.t += 600
        self.assertIsNone(self.l.should_exit())
        self.l.bye()
        self.c.t += 6
        self.assertEqual(self.l.should_exit(), "окно закрыто")

    def test_request_in_flight_at_close_is_not_a_relaunch(self):
        self.l.touch()
        self.w.code = 0
        self.assertIsNone(self.l.should_exit())
        self.c.t += 0.5
        self.l.touch()                              # последний запрос страницы долетел после выхода Edge
        self.c.t += 5
        self.assertEqual(self.l.should_exit(), "окно Edge закрыто")

    def test_bye_while_edge_stays_in_background(self):
        self.l.touch(); self.l.bye()
        self.c.t += 6
        self.assertEqual(self.l.should_exit(), "окно закрыто")

    def test_edge_handed_window_to_running_instance(self):
        self.w.code = 0                     # процесс-лаунчер сразу вышел, окно в чужом Edge
        self.c.t += 1
        self.assertIsNone(self.l.should_exit())
        self.c.t += 5
        self.assertIsNone(self.l.should_exit())
        self.assertIsNone(self.l.window)    # дальше следим по запросам, как раньше
        self.l.touch(); self.c.t += 899
        self.assertIsNone(self.l.should_exit())


class WindowCommandTests(unittest.TestCase):
    def test_own_profile_and_no_background_throttling(self):
        from wifi_beacon_scanner.web.server import window_command
        cmd = window_command("msedge.exe", "http://127.0.0.1:1/?t=x", r"C:\p")
        self.assertIn("--app=http://127.0.0.1:1/?t=x", cmd)
        self.assertIn(r"--user-data-dir=C:\p", cmd)
        for f in ("--disable-background-timer-throttling", "--disable-renderer-backgrounding",
                  "--disable-backgrounding-occluded-windows"):
            self.assertIn(f, cmd)


class ByeEndpointTests(unittest.TestCase):
    def test_bye_needs_token_and_does_not_count_as_contact(self):
        state = AppState(DemoBackend(seed=1), None)
        server = make_server(state)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        try:
            self.assertEqual(Client(server, "wrong").req("POST", "/api/bye")[0], 403)
            self.assertIsNone(server.lifeline.bye_at)
            c = Client(server, server.token)
            self.assertEqual(c.req("GET", "/api/prefs")[0], 200)
            last = server.lifeline.last
            self.assertIsNotNone(last)
            self.assertEqual(c.req("POST", "/api/bye")[0], 200)
            self.assertIsNotNone(server.lifeline.bye_at)
            self.assertEqual(server.lifeline.last, last)
        finally:
            server.shutdown()
            server.server_close()


class VersionInfoTests(unittest.TestCase):
    def test_version_file(self):
        from wifi_beacon_scanner import __version__
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "v.txt")
            r = subprocess.run([sys.executable, os.path.join(ROOT, "installer", "version_info.py"), out],
                               capture_output=True, text=True, check=True)
            self.assertEqual(r.stdout.strip(), __version__)
            with open(out, encoding="utf-8") as f:
                txt = f.read()
            self.assertIn("StringStruct('ProductVersion', '%s')" % __version__, txt)
            self.assertIn("filevers=(%s, 0)" % __version__.replace(".", ", "), txt)

    def test_build_scripts_are_ascii_crlf(self):
        for name in ("build.bat", "build_installer.bat"):
            with open(os.path.join(ROOT, name), "rb") as f:
                data = f.read()
            data.decode("ascii")
            self.assertNotIn(b"\n", data.replace(b"\r\n", b""), name)

    def test_iss_has_fixed_appid_and_paths(self):
        with open(os.path.join(ROOT, "installer", "WiFiBeaconScanner.iss"), encoding="utf-8") as f:
            iss = f.read()
        self.assertIn("AppId={{E8295D65-7A8A-4314-88BF-2F9104398348}", iss)
        self.assertIn('Source: "..\\dist\\WiFiBeaconScanner\\*"', iss)
        self.assertTrue(os.path.exists(os.path.join(ROOT, "assets", "wifi-beacon-scanner.ico")))


if __name__ == "__main__":
    unittest.main()
