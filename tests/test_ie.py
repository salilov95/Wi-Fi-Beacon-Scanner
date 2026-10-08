import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest

from wifi_diag.ie import iter_elements, parse_ies
from wifi_diag.model import freq_to_band, freq_to_channel

from ie_builder import *  # noqa: F401,F403


class IeParserTests(unittest.TestCase):
    def test_iter_elements_drops_truncated_tail(self):
        data = ie(3, b"\x06") + bytes([221, 10, 1, 2])   # второй IE обрезан
        self.assertEqual(list(iter_elements(data)), [(3, b"\x06")])

    def test_wpa2_personal(self):
        i = parse_ies(rsn_ie([2]))
        self.assertEqual(i.rsn.akm, ["PSK"])
        self.assertEqual(i.rsn.pairwise, ["CCMP"])
        self.assertFalse(i.rsn.mfp_capable)

    def test_wpa3_sae_with_pmf(self):
        i = parse_ies(rsn_ie([8], mfpc=True, mfpr=True))
        self.assertEqual(i.rsn.akm, ["SAE"])
        self.assertTrue(i.rsn.mfp_capable and i.rsn.mfp_required)

    def test_enterprise_with_ft(self):
        i = parse_ies(rsn_ie([1, 3], pairwise=[4, 2]) + mobility_domain_ie(0xABCD, True))
        self.assertEqual(i.rsn.akm, ["802.1X", "FT-802.1X"])
        self.assertEqual(i.rsn.pairwise, ["CCMP", "TKIP"])
        self.assertTrue(i.dot11r)
        self.assertEqual(i.mdid, 0xABCD)
        self.assertTrue(i.ft_over_ds)

    def test_wpa1_vendor_ie(self):
        i = parse_ies(wpa1_ie(akm=2, cipher=2))
        self.assertIsNone(i.rsn)
        self.assertEqual(i.wpa1.akm, ["PSK"])
        self.assertEqual(i.wpa1.pairwise, ["TKIP"])

    def test_dot11k_and_v(self):
        i = parse_ies(rm_caps_ie(True) + ext_caps_ie(True))
        self.assertTrue(i.dot11k and i.neighbor_report and i.dot11v)
        j = parse_ies(rm_caps_ie(False) + ext_caps_ie(False))
        self.assertTrue(j.dot11k)
        self.assertFalse(j.neighbor_report or j.dot11v)

    def test_bss_transition_is_bit_19_only(self):
        # установлен бит 18, а не 19 - 11v быть не должно
        b = bytearray(8)
        b[2] |= 1 << 2
        self.assertFalse(parse_ies(ie(127, bytes(b))).dot11v)

    def test_qbss_load(self):
        i = parse_ies(qbss_ie(stations=17, util_255=128))
        self.assertEqual(i.qbss_stations, 17)
        self.assertAlmostEqual(i.qbss_util_pct, 50.2, places=1)

    def test_country_dtim_ds(self):
        i = parse_ies(country_ie("RU") + tim_ie(3) + ds_ie(6))
        self.assertEqual((i.country, i.dtim_period, i.ds_channel), ("RU", 3, 6))

    def test_rates_basic_flag(self):
        i = parse_ies(rates_ie([1, 2, 5.5, 11, 6], basic=[1, 2]))
        self.assertEqual(i.rates, [(1.0, True), (2.0, True), (5.5, False), (11.0, False), (6.0, False)])

    def test_ht_width_and_streams(self):
        i = parse_ies(ht_cap_ie(streams=3) + ht_op_ie(36, width40=True, sec_offset=1, protection=2))
        self.assertEqual(i.ht_streams, 3)
        self.assertEqual(i.width_mhz, 40)
        self.assertEqual(i.ht_protection, 2)
        self.assertEqual(i.generation, 4)

    def test_ht_width40_flag_without_offset_stays_20(self):
        i = parse_ies(ht_op_ie(36, width40=True, sec_offset=0))
        self.assertEqual(i.width_mhz, 20)

    def test_vht_80_and_160(self):
        i80 = parse_ies(ht_op_ie(36, True, 1) + vht_cap_ie(2) + vht_op_ie(1, 42, 0))
        self.assertEqual((i80.width_mhz, i80.vht_streams, i80.generation), (80, 2, 5))
        i160 = parse_ies(ht_op_ie(36, True, 1) + vht_cap_ie(4) + vht_op_ie(1, 50, 42))
        self.assertEqual((i160.width_mhz, i160.vht_streams), (160, 4))

    def test_he_makes_wifi6(self):
        self.assertEqual(parse_ies(ht_cap_ie() + vht_cap_ie() + he_cap_ie()).generation, 6)

    def test_wps_wmm_and_unknown_vendor_ie(self):
        ms = b"\x00\x50\xf2"
        i = parse_ies(vendor_ie(ms, 4) + vendor_ie(ms, 2) + vendor_ie(b"\x00\xe0\xfc", 3, b"\xaa\xbb"))
        self.assertTrue(i.wps and i.wmm)
        self.assertEqual(i.vendor_ies, [("00-e0-fc", 3, b"\xaa\xbb")])

    def test_garbage_does_not_crash(self):
        parse_ies(b"\x30\x02\x01")                 # RSN, обрезан
        parse_ies(ie(48, b"\x01\x00"))             # RSN только с версией
        parse_ies(ie(48, b"\x01\x00" + b"\x00\x0f\xac\x04\x09\x00"))  # заявлено 9 шифров, данных нет
        parse_ies(b"")


class FrequencyTests(unittest.TestCase):
    def test_channels(self):
        cases = [(2_412_000, "2.4", 1), (2_437_000, "2.4", 6), (2_472_000, "2.4", 13), (2_484_000, "2.4", 14),
                 (5_180_000, "5", 36), (5_500_000, "5", 100), (5_825_000, "5", 165),
                 (5_955_000, "6", 1), (6_415_000, "6", 93)]
        for f, band, ch in cases:
            self.assertEqual((freq_to_band(f), freq_to_channel(f)), (band, ch), f)


class DescribeTests(unittest.TestCase):
    def test_tree_decodes_names_and_fields(self):
        from wifi_diag.ie import describe_ies
        data = ssid_ie("CORP") + rsn_ie([1, 3], pairwise=[4], mfpc=True) + ht_op_ie(36, True, 1)
        tree = describe_ies(data)
        self.assertEqual(tree[0]["name"], "SSID")
        self.assertEqual(tree[0]["fields"], [["SSID", "CORP"]])
        rsn = next(t for t in tree if t["id"] == 48)
        self.assertIn(["AKM", "802.1X, FT-802.1X"], rsn["fields"])
        self.assertIn("40 МГц", next(t for t in tree if t["id"] == 61)["summary"])
        self.assertTrue(all(isinstance(v, str) for t in tree for _, v in t["fields"]))

    def test_broken_ie_does_not_break_tree(self):
        from wifi_diag.ie import describe_ies
        tree = describe_ies(ie(48, b"\x01\x00") + ie(127, b"\x00"))
        self.assertEqual([t["id"] for t in tree], [48, 127])


if __name__ == "__main__":
    unittest.main()
