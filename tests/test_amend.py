import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_beacon_scanner import amend
from wifi_beacon_scanner.demo import build_demo_snapshot
from wifi_beacon_scanner.ie import describe_ies
from wifi_beacon_scanner.synth import (
    anqp_ie, country_ie, ext_caps_ie, he_cap_ie, hs20_ie, ie, interworking_ie, make_bss, mobility_domain_ie,
    power_constraint_ie, rm_caps_ie, rsn_ie, tpc_report_ie, wmm_ie,
)

F5 = 5_180_000


class StandardsTests(unittest.TestCase):
    def std(self, ies, cap=0x0011):
        return amend.standards(make_bss("00:11:22:33:44:55", "X", F5, -50, ies, capability=cap))

    def test_nothing_declared(self):
        self.assertEqual(self.std(b"", cap=0x0001), {})

    def test_d_country(self):
        self.assertEqual(self.std(country_ie("RU"))["d"], "страна RU")

    def test_e_from_wmm_edca_or_capability(self):
        self.assertIn("WMM", self.std(wmm_ie())["e"])
        self.assertIn("EDCA", self.std(ie(12, b"\x00" * 18))["e"])
        self.assertIn("QoS", self.std(b"", cap=0x0211)["e"])

    def test_h_spectrum_mgmt_power_constraint_tpc(self):
        st = self.std(power_constraint_ie(6) + tpc_report_ie(-3), cap=0x0111)
        self.assertEqual(st["h"], "Spectrum Management, Power Constraint 6 дБ, TPC Report -3 дБм")
        self.assertIn("CSA", self.std(ie(37, bytes([1, 52, 5])))["h"])

    def test_i_and_w(self):
        st = self.std(rsn_ie([8], mfpc=True, mfpr=True))
        self.assertEqual((st["i"], st["w"]), ("SAE", "обязательна"))
        st = self.std(rsn_ie([2]))
        self.assertIn("i", st)
        self.assertNotIn("w", st)
        self.assertEqual(self.std(rsn_ie([1], mfpc=True))["w"], "поддерживается")

    def test_k_r_v(self):
        st = self.std(rm_caps_ie(False) + mobility_domain_ie(0x4F52, ft_over_ds=False) + ext_caps_ie(bits=(12, 17)))
        self.assertEqual(st["k"], "без neighbor report")
        self.assertEqual(st["r"], "MDID 0x4F52")
        self.assertEqual(st["v"], "BTM, Proxy ARP, WNM Sleep")

    def test_u_interworking_and_hotspot(self):
        st = self.std(interworking_ie(3, internet=True) + anqp_ie() + hs20_ie())
        self.assertEqual(st["u"], "бесплатная публичная, интернет, ANQP")
        self.assertEqual(st["hs"], "Passpoint")
        self.assertEqual(self.std(ext_caps_ie(False, bits=(31,)))["u"], "Interworking")

    def test_ext_cap_bits_mc_ai_twt_mbssid(self):
        st = self.std(ext_caps_ie(False, bits=(22, 70, 71, 72, 78)))
        self.assertEqual(st["mc"], "FTM responder, initiator")
        self.assertEqual((st["ai"], st["twt"], st["mbssid"]), ("FILS", "TWT responder", "Multiple BSSID"))

    def test_twt_from_he_mac_caps_and_mesh(self):
        self.assertIn("twt", self.std(he_cap_ie(twt=True)))
        self.assertNotIn("twt", self.std(he_cap_ie()))
        self.assertEqual(self.std(ie(114, b"MESH"))["s"], "Mesh ID MESH")

    def test_short_keeps_standard_order(self):
        st = self.std(he_cap_ie(twt=True) + rsn_ie([1], mfpc=True) + country_ie() + wmm_ie())
        self.assertEqual(amend.short(st), "d e i w TWT")

    def test_truncated_ext_caps_is_safe(self):
        st = self.std(ie(127, b"\x00"))
        self.assertNotIn("v", st)
        self.assertNotIn("mc", st)

    def test_beacon_view_names_new_elements(self):
        tree = describe_ies(make_bss("00:11:22:33:44:55", "X", F5, -50, interworking_ie(2) + power_constraint_ie(3)
                                     + ext_caps_ie(bits=(31, 70))).ie_raw)
        names = {t["name"]: t for t in tree}
        self.assertIn("Interworking (802.11u)", names)
        self.assertIn("платная публичная", names["Interworking (802.11u)"]["summary"])
        self.assertIn("Power Constraint (802.11h)", names)
        ext = names["Extended Capabilities"]
        self.assertIn("FTM Responder (802.11mc)", [v for _, v in ext["fields"]])

    def test_demo_has_variety(self):
        seen = set()
        for b in build_demo_snapshot().bss:
            seen.update(amend.standards(b))
        for c in ("d", "e", "h", "i", "k", "r", "u", "v", "w", "mc", "twt", "hs"):
            self.assertIn(c, seen)


class StandardsExportTests(unittest.TestCase):
    def test_csv_and_state_include_standards(self):
        from wifi_beacon_scanner import report
        from wifi_beacon_scanner.web.state import bss_to_dict
        snap = build_demo_snapshot()
        csv_text = report.render_csv(snap.bss)
        head = csv_text.splitlines()[0].split(";")
        self.assertIn("standards", head)
        d = bss_to_dict(snap.bss[1])
        self.assertIn("h", d["std"])
        self.assertTrue(d["k"])                 # старые поля остаются для совместимости

    def test_prefs_keep_autoscan(self):
        from wifi_beacon_scanner.web.state import sanitize_prefs
        out = sanitize_prefs({"auto": False, "interval": 5, "std": ["k"]})
        self.assertEqual(out, {"auto": False, "interval": 5})      # фильтры таблицы не запоминаются
        self.assertEqual(sanitize_prefs({"interval": 7, "auto": "yes"}), {})


if __name__ == "__main__":
    unittest.main()
