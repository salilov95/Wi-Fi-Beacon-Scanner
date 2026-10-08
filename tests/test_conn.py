import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_diag.conn import ConnSample, ConnTracker

A, B, C = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03"


def up(t, bssid, rssi=-55, ssid="CORP"):
    return ConnSample(t=t, state="connected", ssid=ssid, bssid=bssid, rssi=rssi)


def down(t, state="disconnected"):
    return ConnSample(t=t, state=state)


def kinds(tr):
    return [e.kind for e in tr.events]


class TrackerTests(unittest.TestCase):
    def test_roam_dwell_and_rssi(self):
        tr = ConnTracker()
        for t in range(0, 30):
            tr.add_sample(up(t, A, -60 - t // 3))
        ev = tr.add_sample(up(30, B, -50))
        self.assertEqual([e.kind for e in ev], ["roam"])
        r = ev[0]
        self.assertEqual((r.bssid_from, r.bssid_to, r.rssi_from, r.rssi_to, r.duration_s), (A, B, -69, -50, 30.0))
        self.assertEqual(kinds(tr), ["connected", "roam"])
        st = tr.stats()
        self.assertEqual(st["roams"], 1)
        self.assertEqual(st["dwell"][0], {"bssid": A, "s": 30.0})

    def test_pingpong_only_within_window(self):
        tr = ConnTracker(pingpong_window_s=30)
        tr.add_sample(up(0, A)); tr.add_sample(up(10, B)); tr.add_sample(up(20, A))
        self.assertEqual(kinds(tr), ["connected", "roam", "roam", "pingpong"])
        tr2 = ConnTracker(pingpong_window_s=30)
        tr2.add_sample(up(0, A)); tr2.add_sample(up(10, B)); tr2.add_sample(up(80, A))
        self.assertNotIn("pingpong", kinds(tr2))
        tr3 = ConnTracker()
        tr3.add_sample(up(0, A)); tr3.add_sample(up(10, B)); tr3.add_sample(up(15, C))   # A->B->C не пинг-понг
        self.assertNotIn("pingpong", kinds(tr3))

    def test_disconnect_gap_and_reason_after(self):
        tr = ConnTracker()
        tr.add_sample(up(0, A, -70)); tr.add_sample(up(5, A, -72))
        ev = tr.add_sample(down(6))
        self.assertEqual(ev[0].kind, "disconnected")
        self.assertEqual((ev[0].bssid_from, ev[0].rssi_from), (A, -72))
        self.assertIsNone(tr.add_reason(7, "disconnected", 0x28002, "Тайм-аут 802.1X"))   # приклеилась
        self.assertEqual(tr.events[-1].reason, "Тайм-аут 802.1X")
        for t in range(7, 12):
            tr.add_sample(down(t))
        ev = tr.add_sample(up(12, B, -60))
        self.assertEqual(ev[0].kind, "connected")
        self.assertEqual(ev[0].duration_s, 6.0)
        st = tr.stats()
        self.assertEqual((st["disconnects"], st["down_s"]), (1, 6.0))

    def test_reason_before_disconnect_is_attached(self):
        tr = ConnTracker()
        tr.add_sample(up(0, A))
        ev = tr.add_reason(0.5, "disconnected", 7, "AP отключила клиента")
        self.assertEqual(ev.kind, "disconnect_reason")
        tr.add_sample(down(1))
        self.assertEqual(kinds(tr), ["connected", "disconnected"])
        self.assertEqual(tr.events[-1].reason, "AP отключила клиента")

    def test_reason_far_from_disconnect_is_separate(self):
        tr = ConnTracker(reason_attach_s=5)
        tr.add_sample(up(0, A)); tr.add_sample(down(1))
        ev = tr.add_reason(60, "disconnected", 1, "x")
        self.assertEqual(ev.kind, "disconnect_reason")
        self.assertEqual(tr.events[1].reason, "")

    def test_ssid_change_and_attempt_fail(self):
        tr = ConnTracker()
        tr.add_sample(up(0, A, ssid="CORP"))
        tr.add_sample(up(1, C, ssid="Guest"))
        ev = tr.add_reason(2, "attempt_fail", 0x50005, "Неверный пароль", ssid="CORP")
        self.assertEqual(kinds(tr), ["connected", "ssid_change", "attempt_fail"])
        self.assertEqual(ev.severity, "critical")

    def test_sticky_needs_hold_and_reports_once(self):
        tr = ConnTracker(sticky_rssi=-75, sticky_delta=8, sticky_hold_s=10)
        tr.add_sample(up(0, A, -80))
        scan = [SimpleNamespace(bssid=A, ssid="CORP", rssi=-80), SimpleNamespace(bssid=B, ssid="CORP", rssi=-62),
                SimpleNamespace(bssid=C, ssid="OTHER", rssi=-40)]
        self.assertIsNone(tr.check_scan(0, scan))
        self.assertIsNone(tr.check_scan(5, scan))
        ev = tr.check_scan(11, scan)
        self.assertEqual((ev.kind, ev.bssid_to, ev.rssi_from, ev.rssi_to), ("sticky", B, -80, -62))
        self.assertIsNone(tr.check_scan(30, scan))               # повторно о той же BSS не сообщаем
        weak_alt = [SimpleNamespace(bssid=A, ssid="CORP", rssi=-80), SimpleNamespace(bssid=B, ssid="CORP", rssi=-76)]
        tr2 = ConnTracker()
        tr2.add_sample(up(0, A, -80))
        self.assertIsNone(tr2.check_scan(0, weak_alt)); self.assertIsNone(tr2.check_scan(20, weak_alt))
        tr3 = ConnTracker()
        tr3.add_sample(up(0, A, -60))                            # своя BSS сильная - не залипание
        self.assertIsNone(tr3.check_scan(0, scan)); self.assertIsNone(tr3.check_scan(20, scan))

    def test_to_dict_and_clear(self):
        tr = ConnTracker()
        tr.add_sample(up(0, A)); tr.add_sample(down(1)); tr.add_raw(1, 8, 21, "acm_disconnected")
        d = tr.to_dict()
        self.assertEqual(d["samples"], [[0, -55, A], [1, None, ""]])
        self.assertEqual(d["current"]["state"], "disconnected")
        self.assertEqual(len(d["raw"]), 1)
        tr.clear()
        self.assertEqual(list(tr.events), [])
        self.assertEqual(len(tr.samples), 1)


class WinStructsTests(unittest.TestCase):
    """Раскладка структур Native Wifi API: сверено по wlanapi.h, считается для x64."""

    def test_sizes_and_helpers(self):
        import ctypes
        from wifi_diag import winstructs as ws
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ws.sizes(), ws.EXPECTED_SIZES_X64)
        self.assertEqual(ws.WLAN_CONNECTION_ATTRIBUTES.wlanAssociationAttributes.offset, 520)
        self.assertEqual(ws.WLAN_ASSOCIATION_ATTRIBUTES.dot11Bssid.offset, 40)
        self.assertEqual(ws.WLAN_MSM_NOTIFICATION_DATA.wlanReasonCode.offset, 576)
        self.assertEqual((ws.norm_code(21), ws.norm_code(0x1015)), (21, 21))     # обе базы кодов ACM
        arr = (ctypes.c_uint16 * 8)(*[ord(c) for c in "Корп"], 0, 0, 0, 0)
        self.assertEqual(ws.u16_str(arr), "Корп")
        self.assertEqual((ws.auth_name(7), ws.auth_name(42), ws.cipher_name(4)), ("WPA2-PSK", "auth 42", "CCMP"))


if __name__ == "__main__":
    unittest.main()
