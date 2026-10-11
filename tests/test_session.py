import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_beacon_scanner.session import SessionTracker

A, B = "aa:00:00:00:00:01", "aa:00:00:00:00:02"


class ConnectFlowTests(unittest.TestCase):
    def connect(self, tr, t0, bssid=A):
        tr.stage(t0, "start", ssid="CORP")
        tr.stage(t0 + 0.10, "associating", "CORP", bssid)
        tr.stage(t0 + 0.14, "associated", "CORP", bssid)
        tr.stage(t0 + 0.15, "authenticating", "CORP", bssid)
        tr.stage(t0 + 0.55, "connected", "CORP", bssid)
        return tr.stage(t0 + 0.60, "complete", "CORP", bssid)

    def test_stage_durations(self):
        tr = SessionTracker()
        s = self.connect(tr, 100.0).to_dict()
        self.assertEqual((s["kind"], s["result"], s["bssid"]), ("connect", "ok", A))
        self.assertEqual((s["assoc_ms"], s["auth_ms"], s["total_ms"]), (40, 400, 550))
        self.assertEqual([x["stage"] for x in s["stages"]],
                         ["start", "associating", "associated", "authenticating", "connected", "complete"])

    def test_roam_measured_from_association(self):
        tr = SessionTracker()
        self.connect(tr, 100.0)
        tr.stage(200.0, "roam_start", "CORP", A)
        tr.stage(200.20, "associating", "CORP", B)
        tr.stage(200.23, "associated", "CORP", B)
        tr.stage(200.23, "authenticating", "CORP", B)
        tr.stage(200.26, "connected", "CORP", B)
        tr.stage(200.27, "roam_end", "CORP", B)
        s = tr.sessions[-1].to_dict()
        self.assertEqual((s["kind"], s["result"], s["bssid_from"], s["bssid"]), ("roam", "ok", A, B))
        self.assertEqual((s["assoc_ms"], s["auth_ms"], s["total_ms"]), (30, 30, 60))
        self.assertEqual(s["stages"][-1]["stage"], "roam_end")
        self.assertEqual(tr.summary()["roams"], 1)

    def test_attempt_fail_and_reason(self):
        tr = SessionTracker()
        tr.stage(10, "start", ssid="CORP")
        tr.stage(10.1, "associating", "CORP", A)
        tr.stage(10.2, "associated", "CORP", A)
        tr.stage(10.2, "authenticating", "CORP", A)
        s = tr.stage(15, "fail", "CORP", reason_code=0x48001, reason="тайм-аут 4-way handshake")
        self.assertEqual((s.result, s.reason, s.reason_code), ("fail", "тайм-аут 4-way handshake", 0x48001))
        self.assertIsNone(s.to_dict()["total_ms"])
        self.assertEqual(tr.summary()["connects_fail"], 1)

    def test_complete_with_reason_code_is_failure(self):
        tr = SessionTracker()
        tr.stage(1, "start", ssid="X")
        s = tr.stage(2, "complete", "X", reason_code=0x28002, reason="сеть не найдена")
        self.assertEqual(s.result, "fail")

    def test_associating_while_linked_is_roam(self):
        tr = SessionTracker()
        self.connect(tr, 1.0)
        s = tr.stage(50, "associating", "CORP", B)
        self.assertEqual((s.kind, s.bssid_from), ("roam", A))
        tr.stage(60, "disconnected", "CORP")
        tr.stage(70, "associating", "CORP", A)
        self.assertEqual(tr.sessions[-1].kind, "connect")

    def test_associating_without_start_opens_session(self):
        tr = SessionTracker()
        s = tr.stage(5, "associating", "CORP", A)
        self.assertEqual((s.kind, s.result), ("connect", "in_progress"))

    def test_new_attempt_aborts_previous_and_timeout(self):
        tr = SessionTracker()
        tr.stage(1, "start", ssid="X")
        tr.stage(2, "start", ssid="X")
        self.assertEqual(tr.sessions[0].result, "aborted")
        tr.stage(3, "associating", "X", A)
        tr.stage(500, "associated", "X", A)        # через 8 минут: прошлую попытку закрыли по тайм-ауту
        self.assertEqual(tr.sessions[1].result, "aborted")

    def test_stray_events_ignored(self):
        tr = SessionTracker()
        self.assertIsNone(tr.stage(1, "disconnected", "X"))
        self.assertIsNone(tr.stage(1, "roam_end", "X"))
        self.assertEqual(len(tr.sessions), 0)


class OnexTests(unittest.TestCase):
    def test_eap_failure_fails_session(self):
        tr = SessionTracker()
        tr.stage(1, "start", ssid="CORP")
        tr.stage(1.1, "associating", "CORP", A)
        tr.stage(1.2, "associated", "CORP", A)
        tr.stage(1.2, "authenticating", "CORP", A)
        tr.onex(1.3, 1, eap_type=13, identity=1)
        s = tr.onex(3.0, 4, reason_code=0x50005, reason="EAP: получен отказ", error_code=0x80420112,
                    error="сертификат не найден", eap_type=13)
        d = s.to_dict()
        self.assertEqual((d["result"], d["eap_name"], d["onex_identity_ru"]), ("fail", "EAP-TLS", "компьютер"))
        self.assertIn("получен отказ", d["reason"])
        self.assertEqual(d["onex_error_code"], 0x80420112)
        self.assertEqual(tr.summary()["onex_fail"], 1)

    def test_success_and_restart(self):
        tr = SessionTracker()
        tr.stage(1, "start", ssid="CORP")
        tr.onex(1.5, 1, restarted=True)
        s = tr.onex(2.0, 3, eap_type=25)
        self.assertEqual((s.onex_status, s.onex_restarts, s.result), (3, 1, "in_progress"))
        self.assertEqual(s.to_dict()["onex_status_ru"], "успех")

    def test_no_authenticator(self):
        tr = SessionTracker()
        tr.stage(1, "start", ssid="CORP")
        s = tr.onex(30, 2)
        self.assertEqual(s.result, "fail")


class IpTests(unittest.TestCase):
    def connected(self, tr, t=100.0):
        tr.stage(t, "start", ssid="CORP")
        tr.stage(t + 0.1, "associating", "CORP", A)
        tr.stage(t + 0.2, "associated", "CORP", A)
        tr.stage(t + 0.2, "authenticating", "CORP", A)
        tr.stage(t + 0.5, "connected", "CORP", A)
        return tr.stage(t + 0.6, "complete", "CORP", A)

    def test_new_dhcp_lease_gives_time_to_ip(self):
        tr = SessionTracker()
        tr.ip_update(90, "0.0.0.0", True, "", 50.0)        # до подключения: старая аренда
        s = self.connected(tr)
        tr.ip_update(101, "0.0.0.0", True, "", 50.0)
        tr.ip_update(102, "10.0.0.5", True, "10.0.0.1", 101.0)
        d = s.to_dict()
        self.assertEqual((d["ip"], d["dhcp_server"], d["ip_note"]), ("10.0.0.5", "10.0.0.1", "новая аренда DHCP"))
        self.assertEqual(d["ip_ms"], 500)                  # аренда 101.0, подключение 100.5
        self.assertEqual(d["stages"][-1]["stage"], "dhcp")

    def test_kept_address_without_new_lease(self):
        tr = SessionTracker()
        tr.ip_update(90, "10.0.0.5", True, "10.0.0.1", 50.0)
        s = self.connected(tr)
        tr.ip_update(102, "10.0.0.5", True, "10.0.0.1", 50.0)
        self.assertFalse(s.ip_checked)                     # ещё ждём: DHCP может прийти позже
        tr.ip_update(111, "10.0.0.5", True, "10.0.0.1", 50.0)
        self.assertTrue(s.ip_checked)
        self.assertIsNone(s.to_dict()["ip_ms"])
        self.assertIn("сохранился", s.ip_note)

    def test_apipa(self):
        tr = SessionTracker()
        tr.ip_update(90, "0.0.0.0", True, "", None)
        s = self.connected(tr)
        tr.ip_update(110, "169.254.3.4", True, "", None)
        self.assertIn("APIPA", s.ip_note)

    def test_ip_ignored_long_after_connect(self):
        tr = SessionTracker()
        s = self.connected(tr)
        self.assertIsNone(tr.ip_update(400, "10.0.0.9", True, "", 399.0))
        self.assertFalse(s.ip_checked)


if __name__ == "__main__":
    unittest.main()
