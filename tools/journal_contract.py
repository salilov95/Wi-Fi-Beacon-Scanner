"""Контракт журнала подключения: сценарии событий и что из них должна собрать программа.

    python tools/journal_contract.py check     - пересчитать и сравнить с contract/journal/golden (ничего не пишет)
    python tools/journal_contract.py update    - перезаписать сценарии и эталоны (только если изменение задумано!)

Журнал (conn.py) и сессии (session.py) не зависят от Windows: на вход - замеры подключения раз в секунду,
уведомления ACM/MSM/802.1X и опрос IP, на выход - события, сессии, сводка. Сценарий - список таких входов
(contract/journal/scenarios/<имя>.json), эталон - результат 1.x на русском и английском
(contract/journal/golden/<имя>.<язык>.json): журнал (/api/state → conn), сессии (→ sessions), выгрузки CSV
журнала и сессий, разбор уведомлений 802.1X и оценка MCS по скорости подключения. Версия 2.x (Rust) прогоняет
те же сценарии и сравнивает результат с теми же эталонами.

Время в CSV - местное: эталоны считаются в UTC (TZ=UTC), Rust - со смещением 0.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time

os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from golden import differences, dump  # noqa: E402
from wifi_beacon_scanner import i18n, onex, report  # noqa: E402
from wifi_beacon_scanner.backends import DemoConnMonitor  # noqa: E402
from wifi_beacon_scanner.conn import ConnSample, ConnTracker  # noqa: E402
from wifi_beacon_scanner.demo import build_demo_snapshot  # noqa: E402
from wifi_beacon_scanner.mcs import mcs_text, rate_to_mcs  # noqa: E402
from wifi_beacon_scanner.session import SessionTracker  # noqa: E402

DIR = os.path.join(ROOT, "contract", "journal")
SCEN = os.path.join(DIR, "scenarios")
GOLD = os.path.join(DIR, "golden")
T0 = 1_792_000_000.0
LANGS = ("ru", "en")
SAMPLE_KEYS = ("t", "state", "ssid", "bssid", "rssi", "quality", "channel", "rx_mbps", "tx_mbps", "auth", "cipher",
               "onex", "profile")


# ---------------------------------------------------------------- запись сценария из демо-монитора
class RecSessions(SessionTracker):
    def __init__(self, ops):
        super().__init__()
        self.ops = ops

    def stage(self, t, stage, ssid="", bssid="", reason_code=None, reason=""):
        self.ops.append({"op": "stage", "t": t, "stage": stage, "ssid": ssid, "bssid": bssid, "code": reason_code,
                         "reason": reason})
        return super().stage(t, stage, ssid, bssid, reason_code, reason)

    def onex(self, t, status, reason_code=0, reason="", error_code=0, error="", eap_type=None, identity=None,
             restarted=False):
        self.ops.append({"op": "onex", "t": t, "status": status, "reason_code": reason_code, "reason": reason,
                         "error_code": error_code, "error": error, "eap_type": eap_type, "identity": identity,
                         "restarted": restarted})
        return super().onex(t, status, reason_code, reason, error_code, error, eap_type, identity, restarted)

    def ip_update(self, t, ip, dhcp=None, dhcp_server="", lease_obtained=None):
        self.ops.append({"op": "ip", "t": t, "ip": ip, "dhcp": dhcp, "server": dhcp_server, "lease": lease_obtained})
        return super().ip_update(t, ip, dhcp, dhcp_server, lease_obtained)


class RecTracker(ConnTracker):
    def __init__(self):
        self.ops = []
        super().__init__()
        self.sessions = RecSessions(self.ops)

    def add_sample(self, s):
        self.ops.append(dict({"op": "sample"}, **{k: getattr(s, k) for k in SAMPLE_KEYS}))
        return super().add_sample(s)

    def add_reason(self, t, kind, reason_code, reason, ssid="", bssid=""):
        self.ops.append({"op": "reason", "t": t, "kind": kind, "code": reason_code, "reason": reason, "ssid": ssid,
                         "bssid": bssid})
        return super().add_reason(t, kind, reason_code, reason, ssid, bssid)

    def check_scan(self, t, bss):
        self.ops.append({"op": "scan", "t": t, "bss": [[b.bssid, b.ssid, b.rssi] for b in bss]})
        return super().check_scan(t, bss)


def demo_ops():
    """5 минут демо-журнала 1.x: роуминги с FT и без, обрыв с причиной, отказ EAP-TLS, пинг-понг, залипание, DHCP."""
    i18n.set_lang("ru")
    trk = RecTracker()
    mon = DemoConnMonitor(trk, None, build_demo_snapshot(), seed=7)
    mon._prefill(T0 + 300)
    return trk.ops


# ---------------------------------------------------------------- сценарий крайних случаев
def S(t, state="connected", ssid="CORP", bssid="00:e0:fc:10:01:02", rssi=-55, **kw):
    d = {"op": "sample", "t": T0 + t, "state": state, "ssid": ssid if state == "connected" else "",
         "bssid": bssid if state == "connected" else "", "rssi": rssi if state == "connected" else None,
         "quality": 80 if state == "connected" else None, "channel": 36 if state == "connected" else None,
         "rx_mbps": 1201.0 if state == "connected" else None, "tx_mbps": 864.7 if state == "connected" else None,
         "auth": "WPA2 (RSNA)" if state == "connected" else "", "cipher": "CCMP" if state == "connected" else "",
         "onex": state == "connected", "profile": "CORP" if state == "connected" else ""}
    d.update(kw)
    return d


def ST(t, stage, ssid="CORP", bssid="", code=None, reason=""):
    return {"op": "stage", "t": T0 + t, "stage": stage, "ssid": ssid, "bssid": bssid, "code": code, "reason": reason}


def ONEX(t, status, reason_code=0, reason="", error_code=0, error="", eap_type=None, identity=None, restarted=False):
    return {"op": "onex", "t": T0 + t, "status": status, "reason_code": reason_code, "reason": reason,
            "error_code": error_code, "error": error, "eap_type": eap_type, "identity": identity, "restarted": restarted}


def IP(t, ip, dhcp=True, server="10.0.0.1", lease=None):
    return {"op": "ip", "t": T0 + t, "ip": ip, "dhcp": dhcp, "server": server,
            "lease": None if lease is None else T0 + lease}


def edge_ops():
    A, B, C = "00:e0:fc:10:01:02", "00:e0:fc:10:02:02", "00:e0:fc:10:03:02"
    ops = [
        S(0, "disconnected"), S(1, "discovering"),
        {"op": "raw", "t": T0 + 1.04, "source": 8, "code": 9, "name": "acm_connection_start"},
        ST(1.1, "start"), ST(1.2, "associating", bssid=A), ST(1.25, "associated", bssid=A),
        ST(1.3, "authenticating", bssid=A), ONEX(1.31, 1, eap_type=25, identity=2),
        ONEX(1.9, 3, eap_type=25, identity=2), ST(2.0, "connected", bssid=A), ST(2.05, "complete", bssid=A),
        S(2, rssi=-50), IP(2.5, "0.0.0.0", lease=-100), IP(3.4, "10.1.2.3", lease=2.6),
        S(3, rssi=-52), S(4, rssi=-58),
        # роуминг без roaming_start: associating при установленной связи
        ST(30, "associating", bssid=B), ST(30.03, "associated", bssid=B), ST(30.03, "authenticating", bssid=B),
        ST(30.06, "connected", bssid=B), S(30, bssid=B, rssi=-61), ST(31, "roam_end", bssid=B),
        # пинг-понг и обратно, неизвестный EAP
        S(40, bssid=A, rssi=-60), ONEX(40.5, 3, eap_type=99),
        # обрыв: причина пришла раньше опроса, потом после
        {"op": "reason", "t": T0 + 59.5, "kind": "disconnected", "code": 0x38003, "reason": "AP deauth", "ssid": "CORP",
         "bssid": ""},
        ST(59.6, "disconnected", bssid=A, code=0x38003, reason="AP deauth"),
        S(60, "disconnected"), S(61, "associating"),
        {"op": "reason", "t": T0 + 61.5, "kind": "attempt_fail", "code": 0x50005, "reason": "802.1X fail", "ssid": "",
         "bssid": ""},
        ST(62, "start"), ST(62.1, "associating", bssid=C), ONEX(62.2, 2, reason_code=0x10, reason="no 802.1X"),
        ST(62.3, "complete", bssid=C, code=0x50005, reason="802.1X fail"),
        # попытка без исхода: прерывается новой; потом брошенная по тайм-ауту
        ST(70, "start"), ST(70.1, "associating", bssid=C), ST(75, "start"), ST(75.1, "associating", bssid=A),
        ST(75.2, "associated", bssid=A), ST(75.3, "authenticating", bssid=A),
        ONEX(75.4, 1, restarted=True, reason="по запросу Windows (MSM)"),
        ONEX(75.6, 4, reason_code=0x50001, reason="", error_code=0x80092013, error="revocation", eap_type=13,
             identity=1),
        ST(200, "associated", bssid=A),
        # снова подключение, обрыв без причины, потом причина позже
        S(203, "connected", bssid=A, rssi=-62), ST(203, "start"), ST(203.1, "associating", bssid=A),
        ST(203.2, "connected", bssid=A), IP(204, "169.254.10.20", lease=None),
        S(210, "disconnected"),
        {"op": "reason", "t": T0 + 212, "kind": "disconnected", "code": 0x28002, "reason": "user", "ssid": "CORP",
         "bssid": A},
        {"op": "reason", "t": T0 + 240, "kind": "disconnected", "code": 0x28002, "reason": "late", "ssid": "CORP",
         "bssid": A},
        # подключение к другой сети, смена сети, статический адрес, сохранённый адрес
        S(250, ssid="Guest", bssid=C, rssi=-70), ST(250, "start", ssid="Guest"), ST(250.1, "connected", ssid="Guest", bssid=C),
        IP(251, "192.168.1.5", dhcp=False, server=""), IP(262, "192.168.1.5", dhcp=False, server=""),
        S(270, ssid="CORP", bssid=A, rssi=-78), ST(270, "start"), ST(270.2, "connected", bssid=A),
        IP(281, "192.168.1.5", dhcp=True, server="10.0.0.1", lease=-500),
        # залипание: подключение слабое, своего RSSI нет - берётся из скана; потом с RSSI
        S(300, bssid=A, rssi=None),
        {"op": "scan", "t": T0 + 300, "bss": [[A, "CORP", -80], [B, "CORP", -66], [C, "CORP", -60], ["x", "Other", -40]]},
        {"op": "scan", "t": T0 + 305, "bss": [[A, "CORP", -80], [B, "CORP", -66], [C, "CORP", -66]]},
        {"op": "scan", "t": T0 + 311, "bss": [[A, "CORP", -80], [B, "CORP", -66], [C, "CORP", -66]]},
        {"op": "scan", "t": T0 + 320, "bss": [[A, "CORP", -80], [B, "CORP", -60]]},
        S(321, bssid=A, rssi=-77), {"op": "scan", "t": T0 + 322, "bss": [[B, "CORP", -79]]},
        {"op": "raw", "t": T0 + 322.06, "source": 16, "code": 4105, "name": "msm_disassociating (x)"},
        S(323, bssid=A, rssi=-77, rx_mbps=None, tx_mbps=0.0),
        # хвост закрытой сессии и событие вне попытки
        ST(400, "complete", bssid=A), ST(401, "roam_end", bssid=A), ST(500, "fail", bssid=A),
        # границы: пинг-понг ровно через 30 с и через 31 с; длительность ровно x.5 мс (банковское округление);
        # аренда DHCP за 1.5 с до подключения (ещё «новая»)
        S(600, bssid=A, rssi=-60), S(601, bssid=B, rssi=-61), S(631, bssid=A, rssi=-60),
        S(640, bssid=B, rssi=-62), S(671, bssid=A, rssi=-60),
        ST(700, "start"), ST(700.0625, "associating", bssid=A), ST(700.125, "associated", bssid=A),
        ST(700.1875, "authenticating", bssid=A), ST(700.3125, "connected", bssid=A),
        IP(701, "10.9.9.9", lease=698.8125),
        ST(800, "start"), ST(800.0078125, "connected", bssid=B), IP(800.5, "10.9.9.10", lease=799.0078125),
    ]
    return ops


def clear_ops():
    """«Очистить» в журнале: всё сбрасывается, последний замер остаётся началом нового журнала."""
    return edge_ops()[:30] + [{"op": "clear"}, S(510, bssid="00:e0:fc:10:02:02", rssi=-50),
                              S(511, "disconnected"), ST(512, "start"), ST(512.5, "connected", bssid="b")]


def onex_cases():
    def le(*vals):
        return b"".join(v.to_bytes(4, "little") for v in vals)
    eap = le(0x80092013) + bytes([13]) + b"\x00" * 15 + le(0x50001)                 # EAP_ERROR, 24 байта
    auth = le(0, 0, 0, 2)                                                            # ONEX_AUTH_PARAMS, identity=2
    full = le(4, 0x50005, 0, 1, 1, 3, len(auth), 40 + 24, len(eap), 40) + eap + auth
    near = le(4, 0, 0, 0, 0, 2, 0, 0, len(eap), 36) + b"\x00" * 0 + eap                  # blob раньше 40-го байта
    return {
        "result": [b"".hex(), le(3).hex(), le(3, 0, 0).hex(), full.hex(), (full[:-4]).hex(), near.hex(),
                   le(4, 0, 5, 0, 0, 2, 0, 0, 24, 20).hex() + eap.hex(), le(1, 0, 0, 0, 0, 1, 16, 40, 0, 0).hex()
                   + le(0, 0, 0, 9).hex()],
        "restart": [b"".hex(), le(1).hex(), le(7).hex(), le(42).hex()],
    }


def mcs_cases():
    from wifi_beacon_scanner.mcs import phy_rate
    grid = []
    for phy, w, band, n in (("HE", 80, "5", 2), ("VHT", 40, "5", 1), ("HT", 20, "2.4", 2), ("HE", 20, "6", 1)):
        top = {"HE": 11, "VHT": 9, "HT": 7}[phy]
        for m in range(top + 1):
            r = phy_rate(phy, m, n, w)
            if r is not None:
                grid.append([round(r, 1), phy, w, band, n])
    return grid + [[1201.0, "HE", 80, "5", 2], [864.7, "HE", 80, "5", 2], [866.7, "VHT", 80, "5", 2], [144.4, "HT", 20, "2.4", 2],
            [54.0, "HE", 20, "2.4", 2], [6.0, "HE", 20, "6", 1], [0.0, "HE", 80, "5", 2], [None, "HE", 80, "5", 2],
            [2401.9, "HE", 160, "6", 2], [300.0, "HT", 40, "5", 3], [573.5, "HE", 40, "2.4", 4], [11.0, "HT", 20, "2.4", 1]]


# ---------------------------------------------------------------- прогон сценария в 1.x
class Obj:
    def __init__(self, bssid, ssid, rssi):
        self.bssid, self.ssid, self.rssi = bssid, ssid, rssi


def run(ops, lang):
    i18n.set_lang(lang)
    trk = ConnTracker()
    for o in ops:
        k = o["op"]
        if k == "sample":
            trk.add_sample(ConnSample(**{x: o[x] for x in SAMPLE_KEYS}))
        elif k == "reason":
            trk.add_reason(o["t"], o["kind"], o["code"], o["reason"], o["ssid"], o["bssid"])
        elif k == "scan":
            trk.check_scan(o["t"], [Obj(*b) for b in o["bss"]])
        elif k == "raw":
            trk.add_raw(o["t"], o["source"], o["code"], o["name"])
        elif k == "stage":
            trk.sessions.stage(o["t"], o["stage"], o["ssid"], o["bssid"], o["code"], o["reason"])
        elif k == "onex":
            trk.sessions.onex(o["t"], o["status"], o["reason_code"], o["reason"], o["error_code"], o["error"],
                              o["eap_type"], o["identity"], o["restarted"])
        elif k == "ip":
            trk.sessions.ip_update(o["t"], o["ip"], o["dhcp"], o["server"], o["lease"])
        elif k == "clear":
            trk.clear()
        else:
            raise ValueError(k)
    full = trk.to_dict(max_samples=0, max_events=100000)
    sessions_all = trk.sessions.to_dict(max_sessions=100000)["sessions"]
    return {
        "lang": lang,
        "conn": trk.to_dict(),
        "conn_small": trk.to_dict(max_samples=5, max_events=3),
        "sessions": trk.sessions.to_dict(),
        "sessions_small": trk.sessions.to_dict(max_sessions=2),
        "journal_csv": report.render_journal_csv(full["events"]),
        "sessions_csv": report.render_sessions_csv(sessions_all),
    }


def extras(lang):
    i18n.set_lang(lang)
    oc = onex_cases()
    return {
        "lang": lang,
        "onex_result": [onex.parse_result_update(bytes.fromhex(h)) for h in oc["result"]],
        "onex_restart": [onex.parse_restart(bytes.fromhex(h)) for h in oc["restart"]],
        "mcs": [[dict(c, text=mcs_text(c)) for c in rate_to_mcs(r, phy, w, band, max_nss=n, likely_nss=min(n, 2))]
                for r, phy, w, band, n in mcs_cases()],
    }


def scenarios():
    return {"demo": demo_ops(), "edges": edge_ops(), "clear": clear_ops()}


def main(argv) -> int:
    mode = argv[1] if len(argv) > 1 else "check"
    if mode not in ("check", "update"):
        print(__doc__)
        return 2
    prev = i18n.get_lang()
    docs = {}
    if mode == "update":
        os.makedirs(SCEN, exist_ok=True)
        os.makedirs(GOLD, exist_ok=True)
        for name, ops in scenarios().items():
            with open(os.path.join(SCEN, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
                f.write(dump({"scenario": name, "ops": ops}))
        with open(os.path.join(SCEN, "extras.json"), "w", encoding="utf-8", newline="\n") as f:
            f.write(dump({"onex": onex_cases(), "mcs": mcs_cases()}))
    for fn in sorted(os.listdir(SCEN)):
        name = fn[:-5]
        with open(os.path.join(SCEN, fn), encoding="utf-8") as f:
            src = json.load(f)
        for lang in LANGS:
            docs["%s.%s" % (name, lang)] = extras(lang) if name == "extras" else run(src["ops"], lang)
    i18n.set_lang(prev)
    problems = 0
    for key, doc in docs.items():
        path = os.path.join(GOLD, key + ".json")
        if mode == "update":
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(dump(doc))
            continue
        with open(path, encoding="utf-8") as f:
            want = json.load(f)
        d = differences(want, json.loads(json.dumps(doc)))
        problems += len(d)
        for x in d[:20]:
            print("%s: %s" % (key, x))
    print("журнал: %s, файлов %d, отличий %d" % ("записано" if mode == "update" else "сверено", len(docs), problems))
    return 1 if problems else 0


if __name__ == "__main__":
    random.seed(0)
    sys.exit(main(sys.argv))
