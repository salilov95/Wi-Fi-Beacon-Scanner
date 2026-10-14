"""1.1.0: интерфейс и отчёты на двух языках."""
import io
import os
import re
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import i18n_scan  # noqa: E402

from wifi_beacon_scanner import i18n, report  # noqa: E402
from wifi_beacon_scanner.backends import DemoBackend  # noqa: E402
from wifi_beacon_scanner.i18n_en import EN  # noqa: E402
from wifi_beacon_scanner.web.server import make_server  # noqa: E402
from wifi_beacon_scanner.web.state import AppState  # noqa: E402

from test_diag import wait_scan  # noqa: E402
from test_web import Client  # noqa: E402

CYR = re.compile("[а-яА-ЯёЁ]")
SPEC = re.compile(r"%[-#0 +]*\d*(?:\.\d+)?[sdrgfxX%]")


class CatalogTests(unittest.TestCase):
    def test_python_catalog_complete(self):
        ids = set()
        for p in i18n_scan.py_files():
            ids.update(m for _, m in i18n_scan.analyze(p)[1])
        self.assertEqual(sorted(ids - set(EN)), [], "нет перевода: python tools/i18n_scan.py missing")

    def test_python_no_untranslated_literals(self):
        # кириллица вне tr()/N_() допустима только в кодах групп журнала Windows (их переводит страница)
        # и в сообщениях для разработчика при импорте не на Windows
        allowed = ("winlog.py", "_win.py", "xlsx.py")
        left = []
        for p in i18n_scan.py_files():
            if not p.endswith(allowed):
                left += ["%s:%d %s" % (os.path.basename(p), ln, t) for ln, _, t in i18n_scan.analyze(p)[0]]
        self.assertEqual(left, [])

    def test_python_translations_keep_placeholders(self):
        for k, v in EN.items():
            self.assertEqual(SPEC.findall(k), SPEC.findall(v), k)
            self.assertIsNone(CYR.search(v), v)

    def test_page_catalog_complete(self):
        miss = (i18n_scan.js_keys() | i18n_scan.html_keys()) - i18n_scan.js_catalog()
        self.assertEqual(sorted(miss), [], "нет перевода: python tools/i18n_scan.py js")

    def test_page_translations_keep_placeholders(self):
        src = i18n_scan._read(os.path.join(i18n_scan.STATIC, "i18n.js"))
        pairs = re.findall(i18n_scan._JS_STR + r"\s*:\s*" + i18n_scan._JS_STR, src)
        self.assertGreater(len(pairs), 400)
        for k, v in pairs:
            self.assertEqual(sorted(re.findall(r"\{\w+\}", k)), sorted(re.findall(r"\{\w+\}", v)), k)
            if k != "Русский":
                self.assertIsNone(CYR.search(v), v)


class LangTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_lang("ru")

    def test_tr_switch(self):
        self.assertEqual(i18n.tr("Слабый сигнал"), "Слабый сигнал")
        self.assertEqual(i18n.set_lang("en"), "en")
        self.assertEqual(i18n.tr("Слабый сигнал"), "Weak signal")
        self.assertEqual(i18n.tr("строка без перевода"), "строка без перевода")
        self.assertEqual(i18n.set_lang("de"), "ru")      # неизвестный язык - русский
        self.assertEqual(i18n.tr("Слабый сигнал"), "Слабый сигнал")

    def test_system_lang_is_known(self):
        self.assertIn(i18n.system_lang(), i18n.LANGS)

    def test_findings_and_reports_in_english(self):
        st = AppState(DemoBackend(seed=4), None, ["CORP"])
        st.start_scan(0, 0.0)
        wait_scan(st)
        ru_titles = [f.title for f in st.findings]
        self.assertTrue(any(CYR.search(t) for t in ru_titles))
        st.set_lang("en")
        self.assertTrue(st.findings)
        for f in st.findings:
            for text in (f.title, f.detail, f.recommendation):
                self.assertIsNone(CYR.search(text or ""), text)
        page = report.render_html(st.snapshot, st.findings, ["CORP"])
        self.assertIn("<html lang='en'>", page)
        self.assertIsNone(CYR.search(page), CYR.search(page) and page[CYR.search(page).start() - 80:][:160])
        data = report.build_xlsx_report(st.snapshot, st.findings, ["CORP"])
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                text = z.read(n).decode("utf-8")
                m = CYR.search(text)
                self.assertIsNone(m, "%s: %s" % (n, m and text[max(0, m.start() - 60):m.start() + 60]))
        st.set_lang("ru")
        self.assertEqual([f.title for f in st.findings], ru_titles)

    def test_prefs_switch_language_and_page(self):
        with tempfile.TemporaryDirectory() as d:
            st = AppState(DemoBackend(seed=1), None, prefs_path=os.path.join(d, "prefs.json"))
            server = make_server(st)
            import threading
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                c = Client(server, server.token)
                self.assertEqual(c.j("POST", "/api/prefs", {"lang": "en"})[1], {"lang": "en"})
                self.assertEqual(i18n.get_lang(), "en")
                self.assertIn(b'<html lang="en"', c.req("GET", "/")[2])
                self.assertEqual(c.j("GET", "/api/state")[1]["lang"], "en")
                js = c.req("GET", "/i18n.js")
                self.assertEqual(js[0], 200)
                self.assertIn(b"I18N_EN", js[2])
                self.assertEqual(c.j("POST", "/api/prefs", {"lang": "xx"})[1], {"lang": "en"})   # мусор не принимается
            finally:
                server.shutdown()
                server.server_close()
            self.assertEqual(AppState(DemoBackend(seed=1), None, prefs_path=os.path.join(d, "prefs.json")).prefs,
                             {"lang": "en"})            # язык запоминается до следующего запуска


if __name__ == "__main__":
    unittest.main()
