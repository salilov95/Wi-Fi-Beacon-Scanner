"""1.0.1: служебные коды в Supported Rates, устаревшая ширина VHT, новые AKM, канал 2 в 6 ГГц."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest

from wifi_beacon_scanner.ie import describe_ies, parse_ies
from wifi_beacon_scanner.mcs import capability
from wifi_beacon_scanner.model import freq_to_band, freq_to_channel
from wifi_beacon_scanner.rules import CRITICAL, analyze, rule_hygiene

from ie_builder import *  # noqa: F401,F403

HT_SEL, VHT_SEL, H2E_SEL, HE_SEL, EHT_SEL = 0xFF, 0xFE, 0xFB, 0xFA, 0xF9   # селектор | бит basic


def codes(findings):
    return {f.code for f in findings}


class MembershipSelectorTests(unittest.TestCase):
    def test_selectors_are_not_rates(self):
        i = parse_ies(ie(1, bytes([0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C, HT_SEL, H2E_SEL])))
        self.assertEqual([r for r, _ in i.rates], [6, 9, 12, 18, 24, 36, 48, 54])
        self.assertEqual(i.selectors, [127, 123])
        self.assertTrue(i.sae_h2e_only)
        self.assertNotIn(63.5, [r for r, _ in i.rates])

    def test_extended_rates_with_selectors_only(self):
        i = parse_ies(rates_ie([6, 12, 24], basic=[6]) + ie(50, bytes([VHT_SEL, HE_SEL, EHT_SEL])))
        self.assertEqual([r for r, _ in i.rates], [6, 12, 24])
        self.assertEqual(i.selectors, [126, 122, 121])
        self.assertFalse(i.sae_h2e_only)

    def test_plain_rates_unchanged(self):
        i = parse_ies(rates_ie([1, 2, 5.5, 11, 6, 54], basic=[1, 2]))
        self.assertEqual(i.rates, [(1, True), (2, True), (5.5, False), (11, False), (6, False), (54, False)])
        self.assertEqual(i.selectors, [])

    def test_beacon_tab_text(self):
        d = describe_ies(ie(1, bytes([0x8C, 0x12, HT_SEL, H2E_SEL])))[0]
        fields = dict(d["fields"])
        self.assertEqual(fields["Скорости (* = basic)"], "6* 9 Мбит/с")
        self.assertEqual(fields["BSS membership selectors"], "HT PHY, SAE H2E only")
        self.assertNotIn("63.5", d["summary"])
        only = describe_ies(ie(50, bytes([HT_SEL])))[0]
        self.assertEqual(only["summary"], "требуется: HT PHY")

    def test_legacy_rate_ignores_selector(self):
        # legacy AP (без HT) с селектором SAE H2E: максимальная скорость 54, а не 61.5
        cap = capability(parse_ies(ie(1, bytes([0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C, H2E_SEL]))))
        self.assertEqual(cap["rate"], 54)

    def test_basic_rate_rule_still_works(self):
        b = make_bss("aa:00:00:00:00:01", "X", CH1, -50, rates_ie([1, 2, 5.5, 11], basic=[1, 2]) + ie(50, bytes([HT_SEL])))
        self.assertEqual([f.code for f in rule_hygiene([b], None, set()) if f.code == "HYG_BASIC_RATES"], ["HYG_BASIC_RATES"])


class VhtLegacyWidthTests(unittest.TestCase):
    def _bss(self, op):
        return make_bss("aa:00:00:00:00:02", "W", CH36, -50,
                        ht_cap_ie(2) + ht_op_ie(36, True, 1) + vht_cap_ie(2) + op)

    def test_deprecated_160(self):
        b = self._bss(vht_op_ie(2, 50))
        self.assertEqual(b.info.width_mhz, 160)
        self.assertEqual(b.center_channel, 50.0)
        self.assertEqual(capability(b.info)["width"], 160)

    def test_deprecated_80p80(self):
        b = self._bss(vht_op_ie(3, 42, 106))
        self.assertEqual(b.info.width_mhz, 160)
        self.assertEqual(b.center_channel, 42.0)

    def test_current_encoding_unchanged(self):
        self.assertEqual(self._bss(vht_op_ie(1, 42)).info.width_mhz, 80)
        b = self._bss(vht_op_ie(1, 42, 50))
        self.assertEqual((b.info.width_mhz, b.center_channel), (160, 50.0))
        self.assertEqual(self._bss(vht_op_ie(0, 0)).info.width_mhz, 40)


class NewAkmTests(unittest.TestCase):
    def _sec(self, akms, mfpc=True, mfpr=False):
        return make_bss("aa:00:00:00:00:03", "S", CH36, -50, rsn_ie(akms, mfpc=mfpc, mfpr=mfpr)).security

    def test_names(self):
        i = parse_ies(rsn_ie([14, 15, 16, 17, 23, 24, 25]))
        self.assertEqual(i.rsn.akm, ["FILS-SHA256", "FILS-SHA384", "FT-FILS-SHA256", "FT-FILS-SHA384",
                                     "802.1X-SHA384", "SAE-EXT-KEY", "FT-SAE-EXT-KEY"])

    def test_sae_ext_key_is_wpa3_personal(self):
        self.assertEqual(self._sec([24], mfpr=True), "WPA3-Personal")
        self.assertEqual(self._sec([25], mfpr=True), "WPA3-Personal")
        self.assertEqual(self._sec([8, 24], mfpr=True), "WPA3-Personal")
        self.assertEqual(self._sec([2, 24]), "WPA2/WPA3-Personal")

    def test_enterprise_variants(self):
        self.assertEqual(self._sec([23]), "WPA2-Enterprise")
        self.assertEqual(self._sec([23], mfpr=True), "WPA2/3-Enterprise")
        self.assertEqual(self._sec([1, 14, 16]), "WPA2-Enterprise")

    def test_old_labels_unchanged(self):
        self.assertEqual(self._sec([2], mfpc=False), "WPA2-Personal")
        self.assertEqual(self._sec([8], mfpr=True), "WPA3-Personal")
        self.assertEqual(self._sec([2, 8]), "WPA2/WPA3-Personal")
        self.assertEqual(self._sec([12], mfpr=True), "WPA3-Enterprise 192")
        self.assertEqual(self._sec([18], mfpr=True), "OWE")
        self.assertEqual(self._sec([7]), "RSN(type7)")


class RadioGroupingTests(unittest.TestCase):
    """Несколько SSID одного радио - один передатчик в RF_COCHANNEL, channel_advice и RF_UTIL."""

    @staticmethod
    def one_ap(n=4, f=CH6, rssi=-55, util=None, base="0c:45:ba:00:03:4"):
        extra = qbss_ie(4, util) if util is not None else b""
        return [make_bss("%s%x" % (base, k), "S%d" % k, f, rssi, rsn_ie([2]) + extra) for k in range(n)]

    def test_key(self):
        from wifi_beacon_scanner.rules import radio_key
        a, b = make_bss("0c:45:ba:00:03:40", "A", CH6, -50, b""), make_bss("0C:45:BA:00:03:4F", "B", CH6, -60, b"")
        self.assertEqual(radio_key(a), radio_key(b))                   # регистр и младший полубайт не важны
        for other in (make_bss("0c:45:ba:00:03:50", "C", CH6, -50, b""),     # другой старший полубайт
                      make_bss("0c:45:ba:00:04:40", "D", CH6, -50, b""),     # другой 5-й октет
                      make_bss("0c:45:ba:00:03:41", "E", CH11, -50, b""),    # другой канал
                      make_bss("0c:45:ba:00:03:42", "F", CH36, -50, ht_op_ie(36, True, 1))):  # другой диапазон/ширина
            self.assertNotEqual(radio_key(a), radio_key(other))

    def test_one_ap_four_ssids_is_not_cochannel(self):
        self.assertNotIn("RF_COCHANNEL", codes(analyze(self.one_ap())))

    def test_four_aps_still_cochannel(self):
        aps = [make_bss("0c:45:ba:00:%02x:40" % k, "S%d" % k, CH6, -55, rsn_ie([2])) for k in range(4)]
        f = [x for x in analyze(aps) if x.code == "RF_COCHANNEL"]
        self.assertEqual(len(f), 1)
        self.assertIn("слышно 4 BSS сильнее", f[0].detail)            # текст как в 1.0.0

    def test_cochannel_text_counts_radios(self):
        bss = self.one_ap() + [make_bss("0c:45:ba:00:%02x:40" % k, "N%d" % k, CH6, -60, rsn_ie([2])) for k in range(5, 8)]
        f = [x for x in analyze(bss) if x.code == "RF_COCHANNEL"]
        self.assertEqual(len(f), 1)
        self.assertIn("слышно 4 радио (BSS: 7)", f[0].detail)
        self.assertEqual(len(f[0].bssids), 7)

    def test_advice_energy_per_radio(self):
        from wifi_beacon_scanner.rules import channel_advice
        one = {r["channel"]: r for r in channel_advice(self.one_ap(rssi=-50), "2.4")}
        self.assertEqual((one[6]["dbm"], one[6]["count"], one[6]["radios"]), (-50.0, 4, 1))   # не -44 дБм
        two = [make_bss("0c:45:ba:00:%02x:40" % k, "S", CH6, -50, rsn_ie([2])) for k in range(2)]
        r = {x["channel"]: x for x in channel_advice(two, "2.4")}[6]
        self.assertEqual((r["dbm"], r["count"], r["radios"]), (-47.0, 2, 2))               # два передатчика: +3 дБ

    def test_util_one_finding_per_radio(self):
        f = [x for x in analyze(self.one_ap(util=190)) if x.code == "RF_UTIL"]   # 75%
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, CRITICAL)
        self.assertEqual(len(f[0].bssids), 4)
        self.assertIn("одно радио, BSS: 4", f[0].detail)

    def test_util_focus_single_bss_text_unchanged(self):
        f = [x for x in analyze(self.one_ap(util=190), focus_ssids=["S1"]) if x.code == "RF_UTIL"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].detail, "S1 (0c:45:ba:00:03:41, канал 6, 2.4 ГГц): занято 74% эфира, станций: 4.")


class HistoryPruneTests(unittest.TestCase):
    """История BSSID, которых давно не слышно, очищается, а всё, что видно на графиках, остаётся."""

    def setUp(self):
        from wifi_beacon_scanner.backends import DemoBackend
        from wifi_beacon_scanner.web import state as st_mod
        self.st_mod = st_mod
        self.st = st_mod.AppState(DemoBackend(seed=1), None)

    def scan(self, t, macs):
        from wifi_beacon_scanner.model import Snapshot
        self.st._apply(Snapshot("t", "x", [make_bss(m, "S", CH6, -60, rsn_ie([2])) for m in macs]),
                       record_history=True, ts=t)

    def test_walk_keeps_history_bounded(self):
        # обход: каждые 5 с слышно 10 BSSID, каждые 10 сканов набор полностью меняется; 2000 сканов (~2.8 ч)
        for i in range(2000):
            grp = i // 10
            self.scan(1000 + i * 5, ["02:00:%02x:%02x:00:%02x" % (grp // 256, grp % 256, k) for k in range(10)])
        # глубже 240 сканов и 30 минут ничего не хранится: 30 мин = 360 сканов = 36 групп по 10 BSSID (+1 на границе)
        self.assertLessEqual(len(self.st.history), 37 * 10)
        self.assertEqual(self.st.scan_count, 2000)
        d = self.st.to_dict()
        self.assertEqual(len(d["bss"]), 10)
        self.assertTrue(all(r["seen"] == 10 for r in d["bss"]))

    def test_nothing_pruned_within_window(self):
        for i in range(239):
            self.scan(1000 + i * 5, ["02:00:00:00:00:01"] if i == 0 else ["02:00:00:00:00:02"])
        self.assertIn("02:00:00:00:00:01", self.st.history)        # 239 сканов: окно ещё не заполнено

    def test_ttl_protects_recent_bssid_on_slow_scans(self):
        # сканы раз в секунду: окно 240 сканов = 4 минуты, оно короче TTL - держит TTL
        for i in range(300):
            self.scan(1000 + i * 1, ["02:00:00:00:00:01"] if i < 10 else ["02:00:00:00:00:02"])
        # BSSID 01 не слышно ~290 с: из окна 240 сканов он вышел, но 30 минут не прошло - остаётся
        self.assertIn("02:00:00:00:00:01", self.st.history)

    def test_pruned_only_when_both_conditions(self):
        for i in range(600):
            self.scan(1000 + i * 5, ["02:00:00:00:00:01"] if i < 10 else ["02:00:00:00:00:02"])
        # не слышно ~2950 с (> 1800) и нет в последних 240 сканах - убран
        self.assertNotIn("02:00:00:00:00:01", self.st.history)
        self.assertIn("02:00:00:00:00:02", self.st.history)
        self.assertEqual(len(self.st.history["02:00:00:00:00:02"]), self.st_mod.HISTORY_POINTS)

    def test_load_snapshot_resets_window(self):
        from wifi_beacon_scanner.model import Snapshot
        for i in range(300):
            self.scan(1000 + i * 5, ["02:00:00:00:00:02"])
        self.st.load_snapshot(Snapshot("t", "x", [make_bss("02:00:00:00:00:03", "S", CH6, -60, b"")]))
        self.assertEqual(len(self.st._scan_times), 1)
        self.assertEqual(list(self.st.history), ["02:00:00:00:00:03"])


class SixGhzChannel2Tests(unittest.TestCase):
    def test_channel_2(self):
        self.assertEqual((freq_to_band(5_935_000), freq_to_channel(5_935_000)), ("6", 2))

    def test_neighbours_unchanged(self):
        self.assertEqual((freq_to_band(5_955_000), freq_to_channel(5_955_000)), ("6", 1))
        self.assertEqual((freq_to_band(5_975_000), freq_to_channel(5_975_000)), ("6", 5))
        self.assertEqual((freq_to_band(5_885_000), freq_to_channel(5_885_000)), ("5", 177))
        self.assertEqual(freq_to_channel(2_484_000), 14)


if __name__ == "__main__":
    unittest.main()
