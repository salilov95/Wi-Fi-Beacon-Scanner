import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os
import tempfile
import unittest

from wifi_diag import oui, report
from wifi_diag.model import Snapshot
from wifi_diag.rules import CRITICAL, INFO, WARNING, Thresholds, analyze

from ie_builder import *  # noqa: F401,F403

COUNTRY = country_ie("RU")


def codes(findings):
    return {f.code for f in findings}


def ent_ies(ft=True, k=True, v=True, pmf=True, extra=b""):
    ies = rsn_ie([1, 3] if ft else [1], mfpc=pmf) + COUNTRY + ht_cap_ie() + ht_op_ie(36)
    if ft:
        ies += mobility_domain_ie()
    if k:
        ies += rm_caps_ie()
    if v:
        ies += ext_caps_ie()
    return ies + extra


class SecurityRules(unittest.TestCase):
    def test_open_wep_wpa1(self):
        open_ = make_bss("02:00:00:00:00:01", "guest", CH1, -50, b"", capability=0x0401)
        wep = make_bss("02:00:00:00:00:02", "old", CH6, -50, b"", capability=0x0411)
        wpa1 = make_bss("02:00:00:00:00:03", "legacy", CH11, -50, wpa1_ie())
        f = analyze([open_, wep, wpa1])
        self.assertEqual(open_.security, "Open")
        self.assertEqual(wep.security, "WEP")
        self.assertEqual(wpa1.security, "WPA1-Personal")
        self.assertTrue({"SEC_OPEN", "SEC_WEP", "SEC_WPA1_ONLY"} <= codes(f))
        self.assertEqual(next(x for x in f if x.code == "SEC_WEP").severity, CRITICAL)

    def test_tkip_and_mixed_wpa1(self):
        b = make_bss("02:00:00:00:00:04", "mix", CH6, -50, rsn_ie([2], pairwise=[4, 2]) + wpa1_ie())
        self.assertEqual(b.security, "WPA2-Personal+WPA1")
        self.assertTrue({"SEC_TKIP", "SEC_WPA1_MIXED"} <= codes(analyze([b])))

    def test_clean_wpa2_has_no_security_findings(self):
        b = make_bss("02:00:00:00:00:05", "ok", CH36, -50, rsn_ie([2], mfpc=True) + ht_cap_ie() + ht_op_ie(36))
        self.assertFalse([f for f in analyze([b]) if f.code.startswith("SEC_")])

    def test_labels(self):
        t = lambda ies: make_bss("02:00:00:00:00:06", "x", CH36, -50, ies).security
        self.assertEqual(t(rsn_ie([8], mfpc=True, mfpr=True)), "WPA3-Personal")
        self.assertEqual(t(rsn_ie([2, 8], mfpc=True)), "WPA2/WPA3-Personal")
        self.assertEqual(t(rsn_ie([1])), "WPA2-Enterprise")
        self.assertEqual(t(rsn_ie([18], mfpc=True, mfpr=True)), "OWE")

    def test_enterprise_without_pmf(self):
        b = make_bss("02:00:00:00:00:07", "corp", CH36, -50, ent_ies(pmf=False))
        self.assertIn("SEC_NO_PMF", codes(analyze([b])))


class RoamingRules(unittest.TestCase):
    def two(self, a, b):
        return [make_bss("02:00:00:00:01:01", "CORP", CH36, -55, a),
                make_bss("02:00:00:00:01:02", "CORP", CH100, -60, b)]

    def test_all_features_present_no_roaming_findings(self):
        f = analyze(self.two(ent_ies(), ent_ies()), focus_ssids=["CORP"])
        self.assertFalse([x for x in f if x.code.startswith("ROAM")])

    def test_partial_11r(self):
        f = analyze(self.two(ent_ies(ft=True), ent_ies(ft=False)), focus_ssids=["CORP"])
        hit = [x for x in f if x.code == "ROAM_11R_PARTIAL"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].bssids, ["02:00:00:00:01:02"])

    def test_no_11r_on_enterprise_is_info(self):
        f = analyze(self.two(ent_ies(ft=False), ent_ies(ft=False)), focus_ssids=["CORP"])
        hit = [x for x in f if x.code == "ROAM_11R_OFF"]
        self.assertEqual([x.severity for x in hit], [INFO])

    def test_security_and_country_mismatch(self):
        a = ent_ies()
        b = rsn_ie([2]) + country_ie("US") + ht_cap_ie() + ht_op_ie(36)
        f = analyze(self.two(a, b), focus_ssids=["CORP"])
        self.assertTrue({"ROAM_SEC_MISMATCH", "ROAM_COUNTRY_MISMATCH"} <= codes(f))

    def test_single_bss_ssid_skipped(self):
        one = [make_bss("02:00:00:00:02:01", "CORP", CH36, -55, ent_ies(ft=False, k=False, v=False))]
        self.assertFalse([x for x in analyze(one, focus_ssids=["CORP"]) if x.code.startswith("ROAM")])


class RfRules(unittest.TestCase):
    def test_weak_signal_only_for_focus(self):
        ours = make_bss("02:00:00:00:03:01", "CORP", CH36, -82, ent_ies())
        other = make_bss("02:00:00:00:03:02", "neighbor", CH36, -90, rsn_ie([2]) + ht_cap_ie() + ht_op_ie(36))
        f = analyze([ours, other], focus_ssids=["CORP"])
        weak = [x for x in f if x.code == "RF_WEAK"]
        self.assertEqual([x.ssid for x in weak], ["CORP"])

    def test_utilization_thresholds(self):
        mk = lambda mac, u: make_bss(mac, "CORP", CH36, -50, ent_ies(extra=qbss_ie(10, u)))
        f = analyze([mk("02:00:00:00:04:01", 100), mk("02:00:00:00:04:02", 150), mk("02:00:00:00:04:03", 200)])
        sev = {x.bssids[0]: x.severity for x in f if x.code == "RF_UTIL"}
        self.assertNotIn("02:00:00:00:04:01", sev)       # 39%
        self.assertEqual(sev["02:00:00:00:04:02"], WARNING)  # 59%
        self.assertEqual(sev["02:00:00:00:04:03"], CRITICAL)  # 78%

    def test_cochannel_count(self):
        many = [make_bss("02:00:00:00:05:%02x" % i, "n%d" % i, CH6, -60, rsn_ie([2])) for i in range(4)]
        self.assertIn("RF_COCHANNEL", codes(analyze(many)))
        self.assertNotIn("RF_COCHANNEL", codes(analyze(many[:3])))
        weak = [make_bss("02:00:00:00:06:%02x" % i, "n%d" % i, CH6, -90, rsn_ie([2])) for i in range(6)]
        self.assertNotIn("RF_COCHANNEL", codes(analyze(weak)))

    def test_24ghz_channels_width_overlap(self):
        a = make_bss("02:00:00:00:07:01", "a", 2_422_000, -50, rsn_ie([2]) + ht_op_ie(3, True, 1))  # канал 3, 40 МГц
        b = make_bss("02:00:00:00:07:02", "b", CH1, -55, rsn_ie([2]))
        c = analyze([a, b])
        self.assertTrue({"RF_24_NONSTD", "RF_24_40MHZ", "RF_24_OVERLAP"} <= codes(c))
        ok = analyze([make_bss("02:00:00:00:07:03", "c", CH1, -50, rsn_ie([2])),
                      make_bss("02:00:00:00:07:04", "d", CH6, -50, rsn_ie([2]))])
        self.assertFalse({"RF_24_NONSTD", "RF_24_40MHZ", "RF_24_OVERLAP"} & codes(ok))

    def test_dfs(self):
        self.assertIn("RF_DFS", codes(analyze([make_bss("02:00:00:00:08:01", "x", CH100, -50, rsn_ie([2]))])))
        self.assertNotIn("RF_DFS", codes(analyze([make_bss("02:00:00:00:08:02", "x", CH36, -50, rsn_ie([2]))])))


class HygieneRules(unittest.TestCase):
    def test_b_rates_basic_on_24(self):
        b = make_bss("02:00:00:00:09:01", "x", CH6, -50, rsn_ie([2]) + rates_ie([1, 2, 5.5, 11], basic=[1, 2]))
        self.assertIn("HYG_BASIC_RATES", codes(analyze([b])))
        g = make_bss("02:00:00:00:09:02", "x", CH6, -50, rsn_ie([2]) + rates_ie([6, 9, 12], basic=[6]))
        self.assertNotIn("HYG_BASIC_RATES", codes(analyze([g])))

    def test_24_only_and_legacy_and_hidden(self):
        b = make_bss("02:00:00:00:09:03", "only24", CH1, -50, rsn_ie([2]))
        h = make_bss("02:00:00:00:09:04", "", CH1, -50, rsn_ie([2]))
        c = codes(analyze([b, h]))
        self.assertTrue({"HYG_24_ONLY", "HYG_LEGACY_PHY", "HYG_HIDDEN"} <= c)


class GeometryTests(unittest.TestCase):
    def test_center_channel(self):
        mk = lambda ies, f=CH36: make_bss("02:00:00:00:0b:01", "x", f, -50, ies)
        self.assertEqual(mk(ht_op_ie(36)).center_channel, 36)
        self.assertEqual(mk(ht_op_ie(36, True, 1)).center_channel, 38)            # 40 МГц, вторичный выше
        self.assertEqual(mk(ht_op_ie(40, True, 3), 5_200_000).center_channel, 38)  # вторичный ниже
        self.assertEqual(mk(ht_op_ie(36, True, 1) + vht_op_ie(1, 42)).center_channel, 42)      # 80 МГц
        self.assertEqual(mk(ht_op_ie(36, True, 1) + vht_op_ie(1, 50, 42)).center_channel, 42)  # 160 МГц


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.bss = [make_bss("00:11:22:00:00:01", "CORP <b>", CH36, -55, ent_ies()),
                    make_bss("02:00:00:00:0a:02", "guest", CH6, -70, b"", capability=0x0401)]
        self.snap = Snapshot("2026-10-08T00:00:00+03:00", "Test adapter", self.bss)

    def test_snapshot_roundtrip(self):
        snap2 = Snapshot.from_json(self.snap.to_json())
        self.assertEqual([(b.bssid, b.ssid, b.rssi, b.ie_raw) for b in snap2.bss],
                         [(b.bssid, b.ssid, b.rssi, b.ie_raw) for b in self.bss])
        self.assertEqual(snap2.bss[0].security, self.bss[0].security)

    def test_html_escapes_and_csv_columns(self):
        with tempfile.TemporaryDirectory() as d:
            h, c = os.path.join(d, "r.html"), os.path.join(d, "r.csv")
            f = analyze(self.bss)
            report.write_html(h, self.snap, f, [])
            report.write_csv(c, self.bss)
            with open(h, encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("<b>", text.split("<tbody>")[1].split("</tbody>")[0])
            self.assertIn("CORP &lt;b&gt;", text)
            with open(c, encoding="utf-8-sig") as fc:
                rows = fc.read().splitlines()
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0].split(";"), report.CSV_COLUMNS)

    def test_oui_longest_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "manuf")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# comment\n00:11:22\tShortA\tVendor A Inc\n"
                        "00:11:22:33:40:00/36\tShortB\tVendor B Ltd\n")
            db = oui.OuiDb()
            db.load(p)
            self.assertEqual(db.lookup("00:11:22:99:99:99"), "Vendor A Inc")
            self.assertEqual(db.lookup("00:11:22:33:4f:ff"), "Vendor B Ltd")
            self.assertIsNone(db.lookup("aa:bb:cc:00:00:00"))


class AdviceTests(unittest.TestCase):
    def test_channel_advice_prefers_free_channel(self):
        from wifi_diag.rules import channel_advice
        bss = [make_bss("02:00:00:00:0c:01", "a", CH1, -50, rsn_ie([2])),
               make_bss("02:00:00:00:0c:02", "b", CH1, -60, rsn_ie([2]))]
        rows = channel_advice(bss, "2.4")
        self.assertEqual([r["channel"] for r in rows if r["best"]], [6])
        self.assertEqual(rows[-1]["channel"], 1)
        self.assertGreater(rows[-1]["count"], 0)
        self.assertEqual(channel_advice(bss, "6"), [])

    def test_wide_5ghz_bss_covers_all_its_channels(self):
        from wifi_diag.rules import channel_advice
        wide = make_bss("02:00:00:00:0d:10", "w", CH36, -50, ht_op_ie(36, True, 1) + vht_op_ie(1, 42))   # 80 МГц: 36-48
        self.assertEqual(wide.center_channel, 42)
        rows = {r["channel"]: r for r in channel_advice([wide], "5")}
        self.assertEqual([rows[c]["count"] for c in (36, 40, 44, 48)], [1, 1, 1, 1])
        self.assertEqual([rows[c]["count"] for c in (149, 153, 157, 161)], [0, 0, 0, 0])
        self.assertIn(next(c for c, r in rows.items() if r["best"]), (149, 153, 157, 161))
        narrow = make_bss("02:00:00:00:0d:11", "n", CH36, -50, ht_op_ie(36))                             # 20 МГц: только 36
        rows = {r["channel"]: r["count"] for r in channel_advice([narrow], "5")}
        self.assertEqual((rows[36], rows[40]), (1, 0))

    def test_24ghz_overlap_window(self):
        from wifi_diag.rules import channel_advice
        mk = lambda f: make_bss("02:00:00:00:0d:12", "x", f, -50, ht_op_ie(1))
        cnt = lambda f: {r["channel"]: r["count"] for r in channel_advice([mk(f)], "2.4")}
        self.assertEqual(cnt(2_432_000), {1: 1, 6: 1, 11: 0})     # канал 5 задевает и 1, и 6
        self.assertEqual(cnt(2_437_000), {1: 0, 6: 1, 11: 0})     # канал 6 не задевает 1 и 11

    def test_busy_channel_is_not_recommended_even_if_quiet(self):
        from wifi_diag.rules import channel_advice
        bss = [make_bss("02:00:00:00:0d:01", "quiet-but-busy", CH11, -80, rsn_ie([2]) + qbss_ie(30, 204)),  # 80%
               make_bss("02:00:00:00:0d:02", "loud", CH1, -45, rsn_ie([2]) + qbss_ie(3, 25)),
               make_bss("02:00:00:00:0d:03", "mid", CH6, -60, rsn_ie([2]) + qbss_ie(3, 25))]
        rows = channel_advice(bss, "2.4")
        self.assertEqual([r["channel"] for r in rows], [6, 1, 11])
        self.assertTrue(rows[-1]["busy"])


class DiffTests(unittest.TestCase):
    def test_diff_added_removed_changed_rssi(self):
        from wifi_diag.diff import diff_snapshots
        old = [make_bss("02:00:00:00:0e:01", "CORP", CH1, -50, ent_ies(ft=False)),
               make_bss("02:00:00:00:0e:02", "CORP", CH6, -60, ent_ies()),
               make_bss("02:00:00:00:0e:03", "gone", CH11, -70, rsn_ie([2]))]
        new = [make_bss("02:00:00:00:0e:01", "CORP", CH6, -52, ent_ies(ft=True)),     # канал и 11r изменились
               make_bss("02:00:00:00:0e:02", "CORP", CH6, -75, ent_ies()),            # только сигнал просел
               make_bss("02:00:00:00:0e:04", "new", CH36, -55, rsn_ie([8], mfpc=True, mfpr=True))]
        d = diff_snapshots(old, new)
        self.assertEqual([x["bssid"] for x in d["added"]], ["02:00:00:00:0e:04"])
        self.assertEqual([x["bssid"] for x in d["removed"]], ["02:00:00:00:0e:03"])
        self.assertEqual(len(d["changed"]), 1)
        fields = {c["field"]: (c["old"], c["new"]) for c in d["changed"][0]["changes"]}
        self.assertEqual(fields["Канал"], ("1", "6"))
        self.assertEqual(fields["802.11r"], ("нет", "да"))
        self.assertEqual([(r["bssid"], r["delta"]) for r in d["rssi"]], [("02:00:00:00:0e:02", -15)])
        self.assertEqual(d["same"], 1)

    def test_identical_snapshots_have_empty_diff(self):
        from wifi_diag.diff import diff_snapshots
        a = [make_bss("02:00:00:00:0e:05", "x", CH1, -50, rsn_ie([2]))]
        d = diff_snapshots(a, a)
        self.assertEqual((d["added"], d["removed"], d["changed"], d["rssi"]), ([], [], [], []))


class UtilizationTests(unittest.TestCase):
    def test_per_channel_max_levels_and_no_data(self):
        from wifi_diag.rules import channel_utilization
        bss = [make_bss("02:00:00:00:10:01", "a", CH6, -50, qbss_ie(10, 204)),     # 80%
               make_bss("02:00:00:00:10:02", "b", CH6, -60, qbss_ie(3, 51)),      # 20%
               make_bss("02:00:00:00:10:03", "c", CH1, -60, qbss_ie(2, 64)),      # 25%
               make_bss("02:00:00:00:10:04", "d", CH36, -60, b""),                # без QBSS Load
               make_bss("02:00:00:00:10:05", "e", CH11, -60, qbss_ie(5, 115))]    # 45%
        hist = {"02:00:00:00:10:01": [(1.0, -50, 70.0), (2.0, -50, 80.0)], "02:00:00:00:10:02": [(1.0, -60, 75.0), (2.0, -60, 20.0)]}
        u = channel_utilization(bss, hist)
        ch = {(c["band"], c["channel"]): c for c in u["channels"]}
        self.assertEqual([(c["channel"], c["level"]) for c in u["channels"]], [(6, "crit"), (11, "mid"), (1, "low")])
        self.assertEqual((ch[("2.4", 6)]["reporting"], ch[("2.4", 6)]["stations"]), (2, 13))
        self.assertEqual(ch[("2.4", 6)]["aps"][0]["ssid"], "a")
        self.assertEqual(ch[("2.4", 6)]["series"], [[1.0, 75.0], [2.0, 80.0]])    # максимум по AP канала на момент скана
        self.assertEqual(u["no_data"], [{"band": "5", "channel": 36, "bss": 1}])

    def test_levels_boundaries(self):
        from wifi_diag.rules import util_level
        self.assertEqual([util_level(x)[0] for x in (0, 29.9, 30, 49.9, 50, 69.9, 70, 100)],
                         ["low", "low", "mid", "mid", "high", "high", "crit", "crit"])


if __name__ == "__main__":
    unittest.main()
