"""Контракт (contract/): эталоны совпадают с программой, схема и сравнение ловят ошибки, обезличивание не течёт."""
import copy
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import unittest

import anonymize_snapshot as anon  # noqa: E402
import golden  # noqa: E402
from wifi_beacon_scanner import i18n  # noqa: E402
from wifi_beacon_scanner.model import Snapshot  # noqa: E402
from wifi_beacon_scanner.rules import analyze, radio_key  # noqa: E402

from ie_builder import *  # noqa: F401,F403,E402


class GoldenTests(unittest.TestCase):
    def test_golden_matches_program(self):
        problems = golden.check(verbose=True)
        self.assertEqual(problems, [], "\n".join(problems[:40]) +
                         "\nЕсли изменение задумано: python tools/golden.py update и описать его в CHANGELOG")

    def test_every_fixture_has_both_languages(self):
        for name in golden.fixtures():
            for lang in golden.LANGS:
                self.assertTrue(os.path.exists(golden.golden_path(name, lang)), (name, lang))

    def test_demo_base_is_current(self):
        # 2.x в --demo крутит contract/fixtures/demo-base.json: он должен быть ровно build_demo_snapshot() из 1.x
        import make_contract_fixtures
        with open(make_contract_fixtures.DEMO_BASE, encoding="utf-8") as f:
            self.assertEqual(json.load(f), make_contract_fixtures.demo_base(),
                             "демо 1.x изменилось: python tools/make_contract_fixtures.py и python tools/golden.py update")

    def test_real_fixture_present(self):
        self.assertIn("real-home-01", golden.fixtures())     # хотя бы один снапшот с реального адаптера

    def test_language_restored(self):
        before = i18n.get_lang()
        golden.compute("synthetic-edge", "en" if before == "ru" else "ru")
        self.assertEqual(i18n.get_lang(), before)

    def test_english_golden_has_no_cyrillic_in_findings(self):
        with open(golden.golden_path("demo-office", "en"), encoding="utf-8") as f:
            g = json.load(f)
        text = json.dumps(g["findings"], ensure_ascii=False)
        self.assertFalse(any("а" <= ch.lower() <= "я" for ch in text))


class JournalContractTests(unittest.TestCase):
    def test_journal_golden_matches_program(self):
        """contract/journal (журнал подключения и сессии для версии на Rust) совпадает с conn.py/session.py.
        Отдельным процессом: инструмент переводит часы процесса в UTC."""
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "journal_contract.py"), "check"],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class CatalogTests(unittest.TestCase):
    def test_exported_catalog_is_current(self):
        """contract/i18n/en.json (его читает версия на Rust) совпадает с i18n_en.py."""
        import export_i18n
        with open(export_i18n.PATH, encoding="utf-8") as f:
            self.assertEqual(f.read(), export_i18n.render(), "python tools/export_i18n.py")


class SchemaAndDiffTests(unittest.TestCase):
    """Проверяем сами проверки: схема и сравнение должны находить порчу."""

    @classmethod
    def setUpClass(cls):
        cls.schema = golden.load_schema()
        with open(golden.golden_path("synthetic-edge", "ru"), encoding="utf-8") as f:
            cls.good = json.load(f)

    def test_good_passes(self):
        self.assertEqual(golden.validate(self.good, self.schema), [])

    def test_schema_catches_damage(self):
        cases = [
            (lambda g: g["bss"][0].pop("rssi"), "нет обязательного поля rssi"),
            (lambda g: g["bss"][0].__setitem__("rssi", "-50"), "ожидался тип integer"),
            (lambda g: g["bss"][0].__setitem__("width", 30), "не из"),
            (lambda g: g["bss"][0].__setitem__("extra", 1), "лишнее поле extra"),
            (lambda g: g["findings"][0].__setitem__("severity", "fatal"), "не из"),
            (lambda g: g["bss"][0]["ie_tree"][0]["fields"].append(["один"]), "ожидалось 2 элементов"),
            (lambda g: g["advice"]["5"][0].__setitem__("best", 1), "ожидался тип boolean"),
        ]
        for spoil, expect in cases:
            g = copy.deepcopy(self.good)
            spoil(g)
            errs = golden.validate(g, self.schema)
            self.assertTrue(any(expect in e for e in errs), (expect, errs))

    def test_differences(self):
        g = copy.deepcopy(self.good)
        self.assertEqual(golden.differences(self.good, g), [])
        g["advice"]["5"][0]["dbm"] += 1e-9                        # шум последнего бита - не отличие
        self.assertEqual(golden.differences(self.good, g), [])
        g["advice"]["5"][0]["dbm"] += 0.1
        g["bss"][1]["security"] = "Open"
        g["findings"].pop()
        d = golden.differences(self.good, g)
        self.assertTrue(any("/advice/5[0]/dbm" in x for x in d), d)
        self.assertTrue(any("/bss[1]/security" in x for x in d), d)
        self.assertTrue(any("/findings: длина" in x for x in d), d)
        self.assertTrue(golden.differences({"a": 1}, {"a": True}))   # bool - не число


class AnonymizerTests(unittest.TestCase):
    """Снапшот с «опасными» данными: имена, WPS с моделью и серийником, текст в vendor IE, SSID в MBSSID."""

    @staticmethod
    def wps_ie():
        attrs = b""
        for t, v in ((0x104A, b"\x10"), (0x1044, b"\x02"), (0x1021, b"Keenetic Ltd."), (0x1023, b"Racer KN-4010"),
                     (0x1042, b"SN123456789"), (0x1047, bytes(range(16))), (0x1011, b"MyRouter"),
                     (0x1049, b"\x00\x01\x37\x10\x06\x00\x04SECRETID")):
            attrs += t.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v
        return ie(221, b"\x00\x50\xf2\x04" + attrs)

    def make(self):
        mbssid = ie(71, b"\x03" + bytes([0, len(ssid_ie("Hidden-Corp"))]) + ssid_ie("Hidden-Corp"))
        bss = [
            make_bss("00:e0:fc:12:34:50", "Corp-WiFi", CH36, -50, rsn_ie([1]) + self.wps_ie() + mbssid),
            make_bss("00:e0:fc:12:34:51", "Corp-Guest", CH36, -51, rsn_ie([2]) + vendor_ie(b"\x00\x0c\xe7", 8, b"\x01AP-FLOOR3-ROOM42")),
            make_bss("00:e0:fc:12:34:60", "Corp-WiFi", CH36, -60, rsn_ie([1])),                # другое радио
            make_bss("02:11:22:33:44:55", "Phone-Hotspot", CH6, -70, rsn_ie([8], mfpc=True, mfpr=True)),
            make_bss("00:e0:fc:12:34:70", "", CH6, -75, rsn_ie([2])),                          # скрытая
        ]
        return json.loads(Snapshot("2026-10-15T00:00:00+03:00", "test", bss).to_json())

    def test_no_leaks_and_same_analysis(self):
        src = self.make()
        a = anon.Anonymizer()
        dst = a.snapshot(src)
        self.assertEqual(a.leaks(dst), [])
        blob = json.dumps(dst) + "".join(bytes.fromhex(x["ie_hex"]).decode("latin-1") for x in dst["bss"])
        for secret in ("Corp-WiFi", "Corp-Guest", "Hidden-Corp", "Phone-Hotspot", "Keenetic", "Racer", "SN123456789",
                       "MyRouter", "SECRETID", "AP-FLOOR3", "12:34:5", "123450", "00e0fc123450"):
            self.assertNotIn(secret, blob, secret)
        s0, s1 = Snapshot.from_json(json.dumps(src)), Snapshot.from_json(json.dumps(dst))
        # разбор и находки те же, кроме имён
        for x, y in zip(s0.bss, s1.bss):
            self.assertEqual((x.band, x.channel, x.rssi, x.security, x.info.width_mhz, x.hidden, x.locally_administered,
                              x.info.wps),
                             (y.band, y.channel, y.rssi, y.security, y.info.width_mhz, y.hidden, y.locally_administered,
                              y.info.wps))
            # OUI вендора сохраняется; у случайного адреса - только первый октет (биты LA и групповой)
            keep = 2 if x.locally_administered else 8
            self.assertEqual(x.bssid[:keep], y.bssid[:keep])
            self.assertEqual(x.bssid[-1], y.bssid[-1])                     # младший полубайт сохранён
        self.assertEqual(sorted((f.code, f.severity, len(f.bssids)) for f in analyze(s0.bss)),
                         sorted((f.code, f.severity, len(f.bssids)) for f in analyze(s1.bss)))
        # группировка в радио не меняется: 50/51 - одно радио, 60 - другое
        k = [radio_key(b) for b in s1.bss]
        self.assertEqual(k[0], k[1])
        self.assertNotEqual(k[0], k[2])
        self.assertEqual(s1.bss[0].ssid, s1.bss[2].ssid)                   # одинаковые SSID - одинаковая замена
        self.assertEqual(s1.bss[4].ssid_display, "<hidden>")

    def test_deterministic(self):
        src = self.make()
        self.assertEqual(anon.Anonymizer().snapshot(src), anon.Anonymizer().snapshot(src))

    def test_committed_real_fixture_is_clean(self):
        """В репозитории лежит только обезличенный снапшот: SSID вида net-NN, текста в vendor IE нет."""
        import re
        with open(os.path.join(golden.FIXTURES, "real-home-01.json"), encoding="utf-8") as f:
            d = json.load(f)
        for x in d["bss"]:
            s = bytes.fromhex(x["ssid_hex"])
            self.assertTrue(s == b"" or set(s) == {0} or re.fullmatch(rb"net-\d\d", s), s)
            from wifi_beacon_scanner.ie import iter_elements
            for eid, body in iter_elements(bytes.fromhex(x["ie_hex"])):
                if eid == 221 and body[:4] not in (b"\x00\x50\xf2\x01", b"\x00\x50\xf2\x02"):
                    runs = [m for m in re.findall(rb"[\x20-\x7e]{4,}", body[4:]) if m.strip(b"x")]
                    self.assertEqual(runs, [], (x["bssid"], runs))


if __name__ == "__main__":
    unittest.main()
