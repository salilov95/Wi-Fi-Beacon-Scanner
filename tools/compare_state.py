"""Сверка API версии 2.x (Rust) с 1.x (Python) на снапшотах контракта.

    cd rust && cargo build --example devserver
    python tools/compare_state.py rust/target/debug/examples/devserver

Что сравнивается: /api/state (строки таблицы с историей, проблемы с «Мои SSID» и порогом сигнала, свободность
и загрузка каналов, сравнение с базой, история) на русском и английском, выгрузки CSV и JSON, отчёты HTML и Excel
(все сети, «Мои SSID», выбранные строки) с журналом подключения (демо-сценарий contract/journal), CSV журнала и сессий.
Excel сравнивается по XML частей книги (zip у версий разный); время в листе истории - время загрузки, его не сравниваем.
Не сравниваются поля, которые зависят от времени и источника данных (now, first_seen, время в истории),
и то, что в 2.x ещё не перенесено (обход). Журнал подключения и сессии здесь пустые (монитор не запущен);
их логику проверяет tools/journal_contract.py. Выход 1 - есть расхождения.
"""
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

# время в отчётах - местное: обе версии считают в UTC (Rust devserver - смещение 0)
os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from wifi_beacon_scanner import report  # noqa: E402
from wifi_beacon_scanner.backends import DemoBackend  # noqa: E402
from wifi_beacon_scanner.i18n import set_lang  # noqa: E402
from wifi_beacon_scanner.model import Snapshot  # noqa: E402
from wifi_beacon_scanner.rules import analyze  # noqa: E402
from wifi_beacon_scanner.web.state import AppState  # noqa: E402

FX = os.path.join(ROOT, "contract", "fixtures")
FOCUS = ["net-01", "Cov-Roam"]
VOLATILE = ("now", "backend", "interfaces", "interfaces_error", "survey", "last_scan_ms", "scanning")


def fixture(name: str) -> str:
    with open(os.path.join(FX, name + ".json"), encoding="utf-8") as f:
        return f.read()


def changed_copy(name: str) -> str:
    """Снапшот с изменениями для проверки «до/после»: пропал BSS, появился новый, сменились канал,
    beacon interval, RSSI и набор IE."""
    d = json.loads(fixture(name))
    d["bss"] = d["bss"][1:]
    for i, b in enumerate(d["bss"]):
        if i % 3 == 0:
            b["rssi"] -= 11
        if i % 4 == 1:
            b["beacon_interval"] = 300
        if i % 5 == 2:
            b["freq_khz"] = 5_200_000
    d["bss"][3]["ie_hex"] = d["bss"][3]["ie_hex"][:40]
    d["bss"].append(dict(d["bss"][0], bssid="02:99:00:00:00:01"))
    return json.dumps(d)


def scrub(d):
    d = json.loads(json.dumps(d))
    for k in VOLATILE:
        d.pop(k, None)
    d["history"] = {k: [[r, u] for _, r, u in v] for k, v in d["history"].items()}
    for b in d["bss"]:
        b.pop("first_seen", None)
    for c in d["util"]["channels"]:
        c["series"] = [u for _, u in c["series"]]
    return d


def differences(a, b, path=""):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append("%s/%s: есть только в %s" % (path, k, "1.x" if k in a else "2.x"))
            else:
                out += differences(a[k], b[k], path + "/" + k)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("%s: длина %d и %d" % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            out += differences(x, y, "%s[%d]" % (path, i))
    elif isinstance(a, float) or isinstance(b, float):
        if type(a) is not type(b) or abs(a - b) > 1e-6:
            out.append("%s: %r и %r" % (path, a, b))
    elif a != b or type(a) is not type(b):
        out.append("%s: %r и %r" % (path, a, b))
    return out


class Rust:
    def __init__(self, exe: str, env=None, snap: str = "demo-office") -> None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.proc = subprocess.Popen([exe, os.path.join(FX, snap + ".json"), str(self.port)],
                                     stderr=subprocess.DEVNULL, env=dict(os.environ, **(env or {})))
        for _ in range(100):
            try:
                self.get("/api/prefs")
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("devserver не запустился")

    def raw(self, path: str, body=None) -> bytes:
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=None if body is None else body.encode("utf-8"),
                                     method="GET" if body is None else "POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read()

    def get(self, path: str, body=None):
        return json.loads(self.raw(path, body))

    def get_status(self, path: str, body=None) -> int:
        try:
            self.raw(path, body)
            return 200
        except urllib.error.HTTPError as e:
            return e.code

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(5)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    rs = Rust(sys.argv[1])
    problems = 0
    try:
        cases = [("real-home-01", "demo-office"), ("synthetic-coverage", "synthetic-edge"), ("demo-office", None),
                 ("synthetic-coverage", "changed")]
        for lang in ("ru", "en"):
            for main_name, base in cases:
                base_text = changed_copy(main_name) if base == "changed" else (fixture(base) if base else None)
                # devserver создан один раз на русском, язык потом меняется: так же и здесь
                # (тексты, собранные при создании, - «не запущен» у журнала - остаются на языке запуска)
                set_lang("ru")
                st = AppState(DemoBackend(), None)
                st.set_lang(lang)
                st.load_snapshot(Snapshot.from_json(fixture(main_name)))
                st.set_config(FOCUS, -72)
                if base_text:
                    st.set_baseline(Snapshot.from_json(base_text))
                py = scrub(st.to_dict())

                rs.get("/api/prefs", json.dumps({"lang": lang}))
                rs.get("/api/load", fixture(main_name))
                rs.get("/api/config", json.dumps({"focus": FOCUS, "weak_rssi": -72}))
                rs.get("/api/baseline", base_text or json.dumps({"clear": True}))
                d = differences(py, scrub(rs.get("/api/state")))
                problems += len(d)
                print("%s %-18s база %-18s BSS %2d проблем %2d -> расхождений %d"
                      % (lang, main_name, base or "-", len(py["bss"]), len(py["findings"]), len(d)))
                for x in d[:20]:
                    print("    " + x)
        set_lang("ru")
        rs.get("/api/prefs", json.dumps({"lang": "ru"}))
        for name in ("real-home-01", "synthetic-coverage", "synthetic-edge", "demo-office"):
            snap = Snapshot.from_json(fixture(name))
            rs.get("/api/load", fixture(name))
            csv_ok = rs.raw("/api/export/csv", '{"scope":"all"}') == report.render_csv(snap.bss).encode("utf-8-sig")
            json_ok = json.loads(rs.raw("/api/export/json", '{"scope":"all"}')) == json.loads(snap.to_json())
            problems += (not csv_ok) + (not json_ok)
            print("выгрузка %-18s CSV %s, JSON %s" % (name, "совпадает" if csv_ok else "ОТЛИЧАЕТСЯ",
                                                    "совпадает" if json_ok else "ОТЛИЧАЕТСЯ"))
    finally:
        rs.close()
    problems += compare_reports(sys.argv[1])
    problems += compare_survey(sys.argv[1])
    print("итого расхождений: %d" % problems)
    return 1 if problems else 0


SCEN = os.path.join(ROOT, "contract", "journal", "scenarios", "demo.json")
JOURNAL_END = 1_792_000_000.0
REPORT_FOCUS = ["CORP", "net-01", "Cov-Roam"]
_DT = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d")
# время снапшота: тестовый источник 2.x ставит время скана, источник 1.x здесь - время из файла
_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d")


def replay_journal(st) -> None:
    """Демо-сценарий журнала из contract/journal в 1.x - с тем же сдвигом времени, что у devserver."""
    from journal_contract import Obj, SAMPLE_KEYS
    from wifi_beacon_scanner.conn import ConnSample
    with open(SCEN, encoding="utf-8") as f:
        ops = json.load(f)["ops"]
    shift = JOURNAL_END - max(o["t"] for o in ops)
    trk = st.conn
    for o in ops:
        o = dict(o, t=o["t"] + shift)
        if o.get("lease") is not None:
            o["lease"] += shift
        k = o["op"]
        if k == "sample":
            trk.add_sample(ConnSample(**{x: o[x] for x in SAMPLE_KEYS}))
        elif k == "reason":
            trk.add_reason(o["t"], o["kind"], o["code"], o["reason"], o["ssid"], o["bssid"])
        elif k == "scan":
            trk.check_scan(o["t"], [Obj(*b) for b in o["bss"]])
        elif k == "stage":
            trk.sessions.stage(o["t"], o["stage"], o["ssid"], o["bssid"], o["code"], o["reason"])
        elif k == "onex":
            trk.sessions.onex(o["t"], o["status"], o["reason_code"], o["reason"], o["error_code"], o["error"],
                              o["eap_type"], o["identity"], o["restarted"])
        elif k == "ip":
            trk.sessions.ip_update(o["t"], o["ip"], o["dhcp"], o["server"], o["lease"])


def py_export(st, fmt, scope, bssids=None):
    """То же, что web/server.py `_export` для html и xlsx."""
    from wifi_beacon_scanner.rules import channel_utilization
    snap, findings, focus, hist, note = st.export_view(scope, bssids)
    extra = {"util": channel_utilization(snap.bss),
             "journal": dict(st.conn.to_dict(max_samples=0, max_events=100000),
                             sessions=st.conn.sessions.to_dict(max_sessions=100000)["sessions"]),
             "survey": [dict(p) for p in st.survey.points]}
    if fmt == "html":
        return report.render_html(snap, findings, focus, note, **extra).encode("utf-8")
    return report.build_xlsx_report(snap, findings, focus, note, history=hist, **extra)


def xlsx_parts(data: bytes, history_name: str):
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(data))
    parts = {n: z.read(n).decode("utf-8") for n in z.namelist()}
    names = re.findall(r'<sheet name="([^"]*)" sheetId="(\d+)"', parts.get("xl/workbook.xml", ""))
    for name, sid in names:
        if name == history_name:
            key = "xl/worksheets/sheet%s.xml" % sid
            parts[key] = _DT.sub("T", parts[key])
    return parts


def compare_reports(exe: str) -> int:
    from wifi_beacon_scanner.i18n import tr
    rs = Rust(exe, {"WBS_JOURNAL": SCEN, "WBS_JOURNAL_AT": repr(JOURNAL_END)})
    problems = 0
    try:
        for lang in ("ru", "en"):
            for name in ("demo-office", "real-home-01", "synthetic-coverage"):
                set_lang("ru")
                st = AppState(DemoBackend(), None)
                replay_journal(st)          # devserver проигрывает журнал при запуске, на русском
                st.set_lang(lang)
                st.load_snapshot(Snapshot.from_json(fixture(name)))
                st.set_config(REPORT_FOCUS, -72)
                rs.get("/api/prefs", json.dumps({"lang": lang}))
                rs.get("/api/load", fixture(name))
                rs.get("/api/config", json.dumps({"focus": REPORT_FOCUS, "weak_rssi": -72}))
                some = [b.bssid for b in st.snapshot.bss[::3]]
                for scope, bssids in (("all", None), ("focus", None), ("list", some)):
                    body = json.dumps({"scope": scope, "bssids": bssids})
                    try:
                        want_html = py_export(st, "html", scope, bssids)
                    except ValueError as e:
                        got = rs.get_status("/api/export/html", body)
                        ok = got == 400
                        print("%s %-18s %-5s отчёт: обе версии отказали (%s)" % (lang, name, scope, e) if ok else
                              "%s %-18s %-5s отчёт: 1.x отказала, 2.x - HTTP %s" % (lang, name, scope, got))
                        problems += not ok
                        continue
                    got_html = rs.raw("/api/export/html", body)
                    html_ok = want_html == got_html
                    if not html_ok:
                        a, b = want_html.decode(), got_html.decode()
                        i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
                        print("    HTML отличается с позиции %d:\n    1.x: %r\n    2.x: %r" % (i, a[i - 60:i + 120], b[i - 60:i + 120]))
                    hist_name = tr("История")
                    want_x = xlsx_parts(py_export(st, "xlsx", scope, bssids), hist_name)
                    got_x = xlsx_parts(rs.raw("/api/export/xlsx", body), hist_name)
                    bad_parts = sorted(k for k in set(want_x) | set(got_x) if want_x.get(k) != got_x.get(k))
                    for k in bad_parts[:3]:
                        a, b = want_x.get(k, ""), got_x.get(k, "")
                        i = next((n for n in range(min(len(a), len(b))) if a[n] != b[n]), min(len(a), len(b)))
                        print("    xlsx %s с позиции %d:\n    1.x: %r\n    2.x: %r" % (k, i, a[i - 60:i + 120], b[i - 60:i + 120]))
                    problems += (not html_ok) + len(bad_parts)
                    print("%s %-18s %-5s HTML %s, Excel %s" % (lang, name, scope, "совпадает" if html_ok else "ОТЛИЧАЕТСЯ",
                                                              "совпадает" if not bad_parts else "частей отличается: %d" % len(bad_parts)))
                for fmt, rows in (("journal", lambda: report.render_journal_csv(st.conn.to_dict(0, 100000)["events"])),
                                  ("sessions", lambda: report.render_sessions_csv(st.conn.sessions.to_dict(100000)["sessions"]))):
                    ok = rs.raw("/api/export/" + fmt) == rows().encode("utf-8-sig")
                    problems += not ok
                    if not ok or name == "demo-office":
                        print("%s %-18s CSV %s %s" % (lang, name, fmt, "совпадает" if ok else "ОТЛИЧАЕТСЯ"))
    finally:
        rs.close()
    return problems



# ---------------------------------------------------------------- обход
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAEElEQVR4nGP4z8AARAwQCgAf7gP9i18U1AAAAABJRU5ErkJggg=="
_T = re.compile(r'"(t|scan_t)": ?[0-9.e+]+')


class FixtureBackendPy:
    """Как FixtureBackend в Rust: каждый скан - тот же снапшот."""
    name = "fixture"

    def __init__(self, text: str) -> None:
        self.text = text

    def interfaces(self):
        return ["fixture"]

    def scan(self, interface_index, wait_s):
        return Snapshot.from_json(self.text)

    def start_conn_monitor(self, tracker, lock, interface_index=0):
        return None


def _wait_py(st) -> None:
    for _ in range(200):
        with st.lock:
            if not st.scanning and not st.survey.has_pending():
                return
        time.sleep(0.05)


def _wait_rs(rs) -> None:
    for _ in range(200):
        d = rs.get("/api/state")
        if not d["scanning"] and not d["survey"]["pending"]:
            return
        time.sleep(0.05)


def _norm(obj) -> str:
    """Без времени точек (у версий оно разное) и в одном формате JSON."""
    return _DT.sub("T", _T.sub(r'"\1": 0', json.dumps(obj, ensure_ascii=False, sort_keys=False)))


def compare_survey(exe: str) -> int:
    """План, точки (скан после клика), проект (выгрузка и загрузка), ошибки, таблица обхода в отчётах."""
    problems = 0
    for lang in ("ru", "en"):
        rs = Rust(exe, snap="real-home-01")       # свой devserver на язык: счётчики обхода с нуля, как у нового AppState
        try:
            problems += _survey_case(rs, lang)
        finally:
            rs.close()
    return problems


def _survey_case(rs, lang: str) -> int:
    text = fixture("real-home-01")
    set_lang("ru")
    st = AppState(FixtureBackendPy(text), None)
    st.set_lang(lang)
    st.load_snapshot(Snapshot.from_json(text))
    st.set_config(["net-01", "net-02"], None)
    rs.get("/api/prefs", json.dumps({"lang": lang}))
    rs.get("/api/load", text)
    rs.get("/api/config", json.dumps({"focus": ["net-01", "net-02"]}))
    results = []

    def both(path, body, py_call):
        try:
            want = py_call()
            want = (404 if path.endswith("/delete") and not want["ok"] else 200, want)
        except ValueError as e:
            want = (400, {"error": str(e)})
        try:
            got = (200, json.loads(rs.raw(path, json.dumps(body))))
        except urllib.error.HTTPError as e:
            got = (e.code, json.loads(e.read()))
        results.append((path, _norm(want), _norm(got)))

    def set_plan(mime, data, name=None):
        with st.lock:
            st.survey.set_plan(mime, data, name)
        return st.survey.summary()

    both("/api/survey/point", {"x": 0.5, "y": 0.5}, lambda: st.survey_point(0.5, 0.5))      # плана нет
    both("/api/survey/plan", {"mime": "image/gif", "data": PNG}, lambda: set_plan("image/gif", PNG))
    both("/api/survey/plan", {"mime": "image/png", "data": "!!"}, lambda: set_plan("image/png", "!!"))
    both("/api/survey/plan", {"mime": "image/jpeg", "data": PNG}, lambda: set_plan("image/jpeg", PNG))
    both("/api/survey/plan", {"mime": "image/png", "data": PNG, "name": "Этаж 3"}, lambda: set_plan("image/png", PNG, "Этаж 3"))
    for x, y in ((0.1, 0.2), (0.9, 0.95), (1.5, 0.5), (True, 0.1), (0, 1)):
        both("/api/survey/point", {"x": x, "y": y}, lambda: st.survey_point(x, y))
        _wait_py(st)
        _wait_rs(rs)
    both("/api/survey/delete", {"id": 2}, lambda: {"ok": st.survey.delete(2)})
    both("/api/survey/delete", {"id": 99}, lambda: {"ok": st.survey.delete(99)})
    results.append(("/api/survey/points", _norm(st.survey.points_dict()), _norm(rs.get("/api/survey/points"))))
    results.append(("survey summary", _norm(st.to_dict()["survey"]), _norm(rs.get("/api/state")["survey"])))
    proj = st.survey.to_project()
    results.append(("/api/survey/project", _norm(proj), _norm(json.loads(rs.raw("/api/survey/project")))))
    # проект 1.x загружается в 2.x; повреждённые проекты - те же ошибки
    damaged = dict(proj, points=[dict(p, results={"x" * 40: ["a", "2.4", 1, -50], "ok": [5, None, "z", -60.7],
                                                  "bad": [1, 2, 3]}, conn={"ssid": 1, "rssi": True})
                                 for p in proj["points"]])

    def load(body):
        with st.lock:
            st.survey.load_project(json.loads(json.dumps(body)))
        return st.survey.summary()

    for body in (damaged, dict(proj, version=2), dict(proj, format="x"), dict(proj, plan=None),
                 dict(proj, points="x"), dict(proj, points=[1])):
        both("/api/survey/project", body, lambda: load(body))
    results.append(("points после загрузки", _norm(st.survey.points_dict()), _norm(rs.get("/api/survey/points"))))
    both("/api/survey/project", proj, lambda: load(proj))
    # таблица обхода в отчётах
    body = json.dumps({"scope": "all"})
    norm = lambda t: _ISO.sub("T", _DT.sub("T", t))   # noqa: E731
    results.append(("отчёт HTML с обходом", norm(py_export(st, "html", "all").decode()),
                    norm(rs.raw("/api/export/html", body).decode())))
    want_x = {k: norm(v) for k, v in xlsx_parts(py_export(st, "xlsx", "all"), "").items()}
    got_x = {k: norm(v) for k, v in xlsx_parts(rs.raw("/api/export/xlsx", body), "").items()}
    results.append(("отчёт Excel с обходом", json.dumps(want_x, sort_keys=True), json.dumps(got_x, sort_keys=True)))
    bad = [(p, a, b) for p, a, b in results if a != b]
    print("%s обход: проверок %d, расхождений %d" % (lang, len(results), len(bad)))
    for p, a, b in bad[:6]:
        i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
        print("    %s с позиции %d:\n    1.x: %r\n    2.x: %r" % (p, i, a[max(0, i - 80):i + 120], b[max(0, i - 80):i + 120]))
    return len(bad)

if __name__ == "__main__":
    sys.exit(main())
