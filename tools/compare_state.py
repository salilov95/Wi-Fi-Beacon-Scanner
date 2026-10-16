"""Сверка API версии 2.x (Rust) с 1.x (Python) на снапшотах контракта.

    cd rust && cargo build --example devserver
    python tools/compare_state.py rust/target/debug/examples/devserver

Что сравнивается: /api/state (строки таблицы с историей, проблемы с «Мои SSID» и порогом сигнала, свободность
и загрузка каналов, сравнение с базой, история) на русском и английском, плюс выгрузки CSV и JSON.
Не сравниваются поля, которые зависят от времени и источника данных (now, first_seen, время в истории),
и то, что в 2.x ещё не перенесено (обход). Журнал подключения и сессии здесь пустые (монитор не запущен);
их логику проверяет tools/journal_contract.py. Выход 1 - есть расхождения.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
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
    def __init__(self, exe: str) -> None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.proc = subprocess.Popen([exe, os.path.join(FX, "demo-office.json"), str(self.port)],
                                     stderr=subprocess.DEVNULL)
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
    print("итого расхождений: %d" % problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
