"""Разбор 802.1X (ONEX), журнала WLAN-AutoConfig, раскладка IP_ADAPTER_INFO и API вкладки «Сессии»."""
import ctypes
import os
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_beacon_scanner import onex, report
from wifi_beacon_scanner.winlog import group_of, parse_event_xml
from wifi_beacon_scanner.backends import DemoBackend
from wifi_beacon_scanner.web.server import make_server
from wifi_beacon_scanner.web.state import AppState

from test_web import Client


def result_update(status, reason=0, error=0, eap=None, identity=None):
    """ONEX_RESULT_UPDATE_DATA, собранный по раскладке из onexstruct.h."""
    head = bytearray(40)
    flags = 0
    tail = b""
    auth_off = eap_off = 0
    if identity is not None:
        flags |= 1
        auth = struct.pack("<IIIII", 0, 0, 0, identity, 0) + b"\x00" * 52
        auth_off = 40 + len(tail)
        tail += auth
    if eap is not None:
        flags |= 2
        e = struct.pack("<IB3xIIII", 0x80092013, eap, 0, 0, 0, 0x50005) + b"\x00" * 60
        eap_off = 40 + len(tail)
        tail += e
    struct.pack_into("<IIIIII", head, 0, status, reason, error, 1, 1, flags)
    struct.pack_into("<II", head, 24, (68 if identity is not None else 0), auth_off)
    struct.pack_into("<II", head, 32, (84 if eap is not None else 0), eap_off)
    return bytes(head) + tail


class OnexParseTests(unittest.TestCase):
    def test_failure_with_eap_error_and_identity(self):
        r = onex.parse_result_update(result_update(4, 0x50005, 0, eap=13, identity=1))
        self.assertEqual((r["status"], r["reason"], r["eap_type"], r["identity"]), (4, 0x50005, 13, 1))
        self.assertEqual((r["eap_win_error"], r["eap_reason"]), (0x80092013, 0x50005))

    def test_success_without_blobs_and_truncated(self):
        r = onex.parse_result_update(result_update(3))
        self.assertEqual((r["status"], r["eap_type"], r["identity"]), (3, None, None))
        r = onex.parse_result_update(b"\x03\x00\x00\x00")
        self.assertEqual((r["status"], r["reason"]), (3, 0))
        bad = bytearray(result_update(4, eap=13))
        struct.pack_into("<II", bad, 32, 5000, 40)         # blob за пределами данных - не читаем
        self.assertIsNone(onex.parse_result_update(bytes(bad))["eap_type"])

    def test_restart(self):
        self.assertEqual(onex.parse_restart(struct.pack("<I", 3))["reason_ru"], "тайм-аут аутентификации")


XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-WLAN-AutoConfig"/><EventID>8002</EventID><Level>2</Level>
<TimeCreated SystemTime="2026-10-11T12:00:01.1234567Z"/></System><EventData>
<Data Name="SSID">CORP</Data><Data Name="FailureReason">Нет ответа от сервера</Data></EventData></Event>"""


class WinlogTests(unittest.TestCase):
    def test_parse(self):
        e = parse_event_xml(XML, "Не удалось подключиться к сети CORP")
        self.assertEqual((e["id"], e["level"], e["group"], e["ssid"], e["reason"]),
                         (8002, 2, "подключение", "CORP", "Нет ответа от сервера"))
        self.assertAlmostEqual(e["t"], 1791720001.123456, places=3)
        self.assertEqual(e["level_ru"], "ошибка")

    def test_groups(self):
        self.assertEqual([group_of(i) for i in (8001, 11001, 11005, 12013, 4000)],
                         ["подключение", "ассоциация", "безопасность / 4-way", "802.1X", "прочее"])


class IpStructTests(unittest.TestCase):
    def test_layout_and_guid(self):
        from wifi_beacon_scanner import ip_win
        from wifi_beacon_scanner.winstructs import GUID
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(ip_win.IP_ADAPTER_INFO), ip_win.EXPECTED_SIZE_X64)
        g = GUID()
        g.Data1, g.Data2, g.Data3 = 0x12345678, 0x9ABC, 0xDEF0
        for i, v in enumerate([1, 2, 3, 4, 5, 6, 7, 8]):
            g.Data4[i] = v
        self.assertEqual(ip_win.guid_str(g), "{12345678-9ABC-DEF0-0102-030405060708}")


class SessionsApiTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(DemoBackend(seed=1), None, ["CORP"])
        self.state.refresh_interfaces()
        self.state.start_monitors()
        self.server = make_server(self.state)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.c = Client(self.server, self.server.token)
        time.sleep(0.4)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.state.stop_monitors()

    def test_state_winlog_and_exports(self):
        st, d = self.c.j("GET", "/api/state")
        ses = d["sessions"]
        self.assertGreaterEqual(ses["summary"]["roams"], 4)
        self.assertEqual(ses["summary"]["onex_fail"], 1)
        self.assertTrue(any(s["kind"] == "connect" and s["ip_note"] == "новая аренда DHCP" for s in ses["sessions"]))
        st, w = self.c.j("GET", "/api/winlog?hours=24")
        self.assertEqual((st, w["error"]), (200, ""))
        self.assertTrue(any(e["id"] == 12013 for e in w["events"]))
        st, hd, raw = self.c.req("POST", "/api/export/sessions", {})
        text = raw.decode("utf-8-sig")
        self.assertEqual(st, 200)
        self.assertIn("Аутентификация, мс", text.splitlines()[0])
        self.assertIn("роуминг", text)
        self.c.j("POST", "/api/scan", {"interface": 0, "wait": 1})
        for _ in range(50):
            if self.state.scan_count:
                break
            time.sleep(0.1)
        st, hd, raw = self.c.req("POST", "/api/export/html", {"scope": "all"})
        self.assertIn("Сессии подключения", raw.decode("utf-8"))

    def test_winlog_error_is_reported(self):
        class NoLog(DemoBackend):
            def read_winlog(self, hours=24):
                raise OSError("нет прав на чтение журнала")
        self.state.backend = NoLog()
        st, w = self.c.j("GET", "/api/winlog")
        self.assertEqual((st, w["events"], w["error"]), (200, [], "нет прав на чтение журнала"))

    def test_session_rows(self):
        rows = report.session_rows(self.state.conn.sessions.to_dict()["sessions"])
        self.assertEqual(rows[0][:3], ["Время", "Тип", "Итог"])
        self.assertTrue(any(r[2] == "ошибка" for r in rows[1:]))


if __name__ == "__main__":
    unittest.main()
