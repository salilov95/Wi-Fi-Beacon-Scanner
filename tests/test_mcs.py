import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_diag import report
from wifi_diag.backends import DemoBackend
from wifi_diag.ie import describe_ies, parse_ies
from wifi_diag.mcs import capability, phy_rate, rate_to_mcs, vht_valid
from wifi_diag.model import Snapshot
from wifi_diag.synth import (
    ds_ie, he_cap_ie, he_op_ie, ht_cap_ie, ht_op_ie, make_bss, rates_ie, vht_cap_ie, vht_op_ie,
)
from wifi_diag.web.state import AppState
from wifi_diag.xlsx import build_xlsx


def r1(x):
    return round(x, 1)


class RateTableTests(unittest.TestCase):
    """Эталонные значения из таблиц MCS 802.11n/ac/ax."""

    def test_known_rates(self):
        cases = [
            (("HT", 7, 1, 20, 0.8), 65.0), (("HT", 7, 1, 20, 0.4), 72.2), (("HT", 7, 2, 40, 0.4), 300.0),
            (("HT", 0, 1, 20, 0.8), 6.5),
            (("VHT", 9, 2, 80, 0.4), 866.7), (("VHT", 9, 1, 160, 0.4), 866.7), (("VHT", 9, 4, 160, 0.4), 3466.7),
            (("VHT", 8, 1, 20, 0.8), 78.0),
            (("HE", 11, 2, 80, 0.8), 1201.0), (("HE", 11, 2, 160, 0.8), 2402.0), (("HE", 11, 1, 20, 0.8), 143.4),
            (("HE", 0, 1, 20, 3.2), 7.3), (("HE", 7, 2, 40, 0.8), 344.1),
        ]
        for args, want in cases:
            self.assertEqual(r1(phy_rate(*args)), want, args)

    def test_invalid_combinations(self):
        self.assertFalse(vht_valid(9, 1, 20))
        self.assertTrue(vht_valid(9, 3, 20))
        self.assertFalse(vht_valid(9, 6, 80))
        self.assertIsNone(phy_rate("HT", 9, 1, 20))          # для HT индекс внутри потока 0..7
        self.assertIsNone(phy_rate("HT", 7, 1, 80))          # HT не бывает 80 МГц


class ParseTests(unittest.TestCase):
    def test_ht_vht_fields(self):
        i = parse_ies(ht_cap_ie(3) + ht_op_ie(36, True, 1, basic_mcs=0x00FF) + vht_cap_ie(3, val=1)
                      + vht_op_ie(1, 42, basic=0xFFFC))
        self.assertEqual((i.ht_mcs_max, i.ht_sgi20, i.ht_sgi40, i.ht_basic_mcs), (23, True, True, 0xFF))
        self.assertEqual((i.vht_streams, i.vht_sgi80, i.vht_sgi160, i.vht_widths), (3, True, False, 0))
        self.assertEqual(i.vht_basic_map, 0xFFFC)
        c = capability(i)
        # VHT 80 МГц, 3 потока, MCS 0-8; SGI 80 есть
        self.assertEqual((c["phy"], c["nss"], c["mcs"], c["width"], c["gi"]), ("VHT", 3, 8, 80, 0.4))
        self.assertEqual(r1(c["rate"]), 1170.0)

    def test_vht_invalid_mcs_steps_down(self):
        i = parse_ies(ht_cap_ie(1) + ht_op_ie(36) + vht_cap_ie(1, val=2) + vht_op_ie(0, 0))
        c = capability(i)
        self.assertEqual((c["phy"], c["width"], c["mcs"]), ("VHT", 20, 8))    # MCS 9 на 20 МГц x1 запрещён

    def test_he_fields_and_6ghz_width(self):
        i = parse_ies(he_cap_ie(4, val=1, w160=True) + he_op_ie(color=33, six=(69, 3, 71, 79)))
        self.assertEqual((i.he_streams, i.max_streams, i.he_bss_color), (4, 4, 33))
        self.assertIsNotNone(i.he_rx160)
        self.assertEqual((i.width_mhz, i.he6_primary, i.he6_ccfs1), (160, 69, 79))
        c = capability(i)
        self.assertEqual((c["phy"], c["nss"], c["mcs"], c["width"]), ("HE", 4, 9, 160))
        b = make_bss("00:00:00:00:00:66", "six", 5_950_000 + 69 * 5000, -60,
                     he_cap_ie(2, w160=True) + he_op_ie(six=(69, 2, 71, 0)))
        self.assertEqual((b.band, b.channel, b.info.width_mhz, b.center_channel), ("6", 69, 80, 71.0))

    def test_he_160_without_map_falls_back_to_80(self):
        i = parse_ies(he_cap_ie(2, w160=False) + he_op_ie(six=(69, 3, 71, 79)))
        self.assertEqual(capability(i)["width"], 80)

    def test_ht_only_and_legacy(self):
        c = capability(parse_ies(ht_cap_ie(2) + ht_op_ie(6, True, 1)))
        self.assertEqual((c["phy"], c["nss"], c["mcs"], r1(c["rate"])), ("HT", 2, 7, 300.0))
        c = capability(parse_ies(ds_ie(1) + rates_ie([1, 2, 5.5, 11])))
        self.assertEqual((c["phy"], c["mcs"], c["rate"]), ("legacy", None, 11.0))

    def test_describe_shows_mcs(self):
        tree = describe_ies(ht_cap_ie(2) + ht_op_ie(36, basic_mcs=0xFF) + vht_cap_ie(2) + he_cap_ie() + he_op_ie(7))
        flat = {(e["name"], k): v for e in tree for k, v in e["fields"]}
        self.assertEqual(flat[("HT Capabilities", "Rx MCS (bitmask)")], "MCS 0-15")
        self.assertEqual(flat[("HT Operation", "Basic MCS Set (обязательные)")], "MCS 0-7")
        self.assertEqual(flat[("VHT Capabilities", "Rx VHT-MCS")], "MCS 0-9, потоков 2")
        self.assertEqual(flat[("Extension: HE Capabilities", "Rx HE-MCS, до 80 МГц")], "MCS 0-11, потоков 2")
        self.assertEqual(flat[("Extension: HE Operation", "BSS Color")], "7")

    def test_truncated_he_does_not_crash(self):
        i = parse_ies(bytes([255, 5, 35, 0, 0, 0, 0]) + bytes([255, 3, 36, 0, 0]))
        self.assertTrue(i.he)
        self.assertIsNone(i.he_rx80)
        self.assertEqual(capability(i)["phy"], "legacy")


class RateToMcsTests(unittest.TestCase):
    def test_unique_matches(self):
        c = rate_to_mcs(866.7, "VHT", 80, "5")[0]
        self.assertEqual((c["phy"], c["mcs"], c["nss"], c["width"], c["gi"]), ("VHT", 9, 2, 80, 0.4))
        c = rate_to_mcs(1201, "HE", 80, "5")[0]
        self.assertEqual((c["phy"], c["mcs"], c["nss"], c["width"]), ("HE", 11, 2, 80))
        c = rate_to_mcs(144.4, "HT", 20, "2.4")[0]
        self.assertEqual((c["phy"], c["mcs"], c["nss"]), ("HT", 7, 2))

    def test_prefers_bss_phy_and_width(self):
        # 6.5 Мбит/с: HT MCS 0 на 20 МГц; ширину BSS ставим первой
        c = rate_to_mcs(6.5, "HT", 20, "2.4")[0]
        self.assertEqual((c["phy"], c["mcs"], c["width"]), ("HT", 0, 20))

    def test_legacy_and_empty(self):
        self.assertIn("legacy", [c["phy"] for c in rate_to_mcs(54, "HT", 20, "2.4", limit=10)])
        self.assertEqual(rate_to_mcs(0, "HE"), [])
        self.assertEqual(rate_to_mcs(None, "HE"), [])
        self.assertEqual(rate_to_mcs(3.3, "HE", 80, "5"), [])
        self.assertTrue(all(c["phy"] == "HE" for c in rate_to_mcs(1201, "HE", 160, "6", limit=10)))


class OutputTests(unittest.TestCase):
    def test_state_and_conn_estimate(self):
        st = AppState(DemoBackend(seed=1), None)
        st.refresh_interfaces()
        st.snapshot = st.backend.scan(0, 0)
        b5 = next(b for b in st.snapshot.bss if b.ssid == "CORP" and b.band == "5")
        from wifi_diag.web.state import bss_to_dict
        d = bss_to_dict(b5)
        self.assertEqual((d["phy"], d["mcs"], d["nss"], d["rate"]), ("HE", 11, 2, 1201.0))
        rx, tx = st._estimate_mcs({"bssid": b5.bssid, "rx_mbps": 1201.0, "tx_mbps": 720.6})
        self.assertEqual((rx[0]["mcs"], rx[0]["nss"]), (11, 2))
        self.assertEqual((tx[0]["mcs"], tx[0]["nss"], tx[0]["width"]), (7, 2, 80))
        self.assertIn("MCS 11", rx[0]["text"])
        self.assertEqual(st._estimate_mcs({"bssid": "ff:ff:ff:ff:ff:ff", "rx_mbps": 1}), ([], []))

    def test_csv_and_html_have_mcs_and_colors(self):
        snap = DemoBackend(seed=1).scan(0, 0)
        csv_text = report.render_csv(snap.bss)
        head = csv_text.splitlines()[0].split(";")
        self.assertIn("max_mcs", head)
        self.assertIn("max_rate_mbps", head)
        html = report.render_html(snap, [], [])
        self.assertIn("Макс. MCS", html)
        self.assertIn("color:hsl(", html)

    def test_rssi_colors_go_red_to_green(self):
        self.assertEqual(report.rssi_hue(-95), 0)
        self.assertEqual(report.rssi_hue(-40), 130)
        hues = [report.rssi_hue(r) for r in range(-90, -45)]
        self.assertEqual(hues, sorted(hues))

    def test_xlsx_color_scales(self):
        data = build_xlsx([("BSS", [["ssid", "rssi_dbm", "util_pct", "channel"], ["a", -60, 20, 1], ["b", -80, 70, 6]])])
        x = zipfile.ZipFile(io.BytesIO(data)).read("xl/worksheets/sheet1.xml").decode()
        self.assertIn('<conditionalFormatting sqref="B2:B3">', x)
        self.assertIn('<conditionalFormatting sqref="C2:C3">', x)
        self.assertNotIn('sqref="D2', x)
        self.assertLess(x.index("<autoFilter"), x.index("<conditionalFormatting"))   # порядок по схеме


if __name__ == "__main__":
    unittest.main()
