"""Состояние GUI-приложения: последний снапшот, находки, история, фоновый скан."""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections import deque
from dataclasses import asdict
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..backends import Backend
from ..conn import ConnTracker
from ..diff import diff_snapshots
from ..ie import describe_ies
from ..model import Bss, Snapshot
from ..oui import OuiDb
from ..rules import Thresholds, analyze, channel_advice, channel_utilization
from ..survey import Survey

HISTORY_POINTS = 240   # сколько последних замеров хранить на BSS
ADVICE_BANDS = ("2.4", "5")


PREF_THEMES = {"auto", "light", "dark", "nord", "solar", "paper", "contrast"}
PREF_TABS = {"channels", "overview", "util", "signal", "conn", "survey", "findings", "beacon", "compare"}
_COL_RE = re.compile(r"^[a-z_]{1,24}$")


def default_prefs_path() -> str:
    """Где хранить настройки вида: %APPDATA%\\WifiDiag\\prefs.json, на других ОС ~/.config/wifi_diag."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "WifiDiag", "prefs.json")
    return os.path.join(os.path.expanduser("~"), ".config", "wifi_diag", "prefs.json")


def sanitize_prefs(d: Any) -> Dict[str, Any]:
    """Оставляет только известные ключи с допустимыми значениями: файл может править кто угодно,
    а тема потом подставляется в HTML."""
    out: Dict[str, Any] = {}
    if not isinstance(d, dict):
        return out
    if d.get("theme") in PREF_THEMES:
        out["theme"] = d["theme"]
    if d.get("density") in ("normal", "compact"):
        out["density"] = d["density"]
    if d.get("tab") in PREF_TABS:
        out["tab"] = d["tab"]
    if d.get("expScope") in ("table", "focus", "all"):
        out["expScope"] = d["expScope"]
    if d.get("connWin") in (300, 900, 1800):
        out["connWin"] = d["connWin"]
    so = d.get("svOpacity")
    if isinstance(so, (int, float)) and not isinstance(so, bool) and 0.1 <= so <= 0.9:
        out["svOpacity"] = round(float(so), 2)
    if d.get("sigMode") in ("lines", "heat"):
        out["sigMode"] = d["sigMode"]
    for k in ("group", "heatAll"):
        if isinstance(d.get(k), bool):
            out[k] = d[k]
    if isinstance(d.get("panelH"), (int, float)) and not isinstance(d.get("panelH"), bool) and 100 <= d["panelH"] <= 4000:
        out["panelH"] = int(d["panelH"])
    if isinstance(d.get("v"), int) and not isinstance(d.get("v"), bool) and 0 <= d["v"] <= 100:
        out["v"] = d["v"]
    cols = d.get("cols")
    if isinstance(cols, list):
        out["cols"] = [c for c in cols if isinstance(c, str) and _COL_RE.match(c)][:40]
    focus = d.get("focus")
    if isinstance(focus, list):
        out["focus"] = [f.strip()[:64] for f in focus if isinstance(f, str) and f.strip()][:20]
    return out


def printable_ascii(data: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in data)


def bss_to_dict(b: Bss) -> Dict[str, Any]:
    i = b.info
    pmf = ""
    if i.rsn is not None:
        pmf = "required" if i.rsn.mfp_required else "capable" if i.rsn.mfp_capable else "no"
    return {
        "bssid": b.bssid,
        "ssid": b.ssid_display,
        "hidden": b.hidden,
        "vendor": b.vendor or "",
        "random_mac": b.locally_administered,
        "band": b.band,
        "channel": b.channel,
        "center": b.center_channel,
        "width": i.width_mhz,
        "rssi": b.rssi,
        "quality": b.link_quality,
        "security": b.security,
        "ciphers": b.ciphers,
        "akm": list(i.rsn.akm) if i.rsn else [],
        "pmf": pmf,
        "wps": i.wps,
        "gen": b.generation_label,
        "gen_n": i.generation,
        "streams": i.max_streams,
        "k": i.dot11k,
        "nr": i.neighbor_report,
        "r": i.dot11r,
        "v": i.dot11v,
        "mdid": i.mdid,
        "util": i.qbss_util_pct,
        "stations": i.qbss_stations,
        "country": i.country or "",
        "beacon": b.beacon_interval,
        "dtim": i.dtim_period,
        "cap": "0x%04X" % b.capability,
        "ht_prot": i.ht_protection,
        "ie_len": len(b.ie_raw),
        "ie_tree": describe_ies(b.ie_raw),
    }


class AppState:
    def __init__(self, backend: Backend, oui: Optional[OuiDb], focus: Optional[List[str]] = None,
                 prefs_path: Optional[str] = None) -> None:
        self.prefs_path = prefs_path
        self.prefs: Dict[str, Any] = self._load_prefs()
        if not focus:
            focus = self.prefs.get("focus")     # «Мои SSID» с прошлого запуска
        self.backend = backend
        self.oui = oui
        self.lock = threading.Lock()
        self.snapshot: Optional[Snapshot] = None
        self.findings: List[Any] = []
        self.history: Dict[str, Deque[Tuple[float, int, Optional[float]]]] = {}
        self.focus: List[str] = list(focus or [])
        self.thresholds = Thresholds()
        self.scanning = False
        self.error: Optional[str] = None
        self.scan_count = 0
        self.interfaces: List[str] = []
        self.interfaces_error: Optional[str] = None
        self.baseline: Optional[Snapshot] = None
        self.conn = ConnTracker()          # журнал подключения ноутбука
        self.survey = Survey()             # обход с планом этажа
        self.monitor: Any = None
        self._scan_args = (0, 4.0)

    # ---- настройки вида на диске ----
    def _load_prefs(self) -> Dict[str, Any]:
        if not self.prefs_path:
            return {}
        try:
            with open(self.prefs_path, "r", encoding="utf-8") as f:
                return sanitize_prefs(json.load(f))
        except (OSError, ValueError):
            return {}

    def _save_prefs(self) -> None:
        if not self.prefs_path:
            return
        try:
            os.makedirs(os.path.dirname(self.prefs_path), exist_ok=True)
            tmp = self.prefs_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.prefs, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.prefs_path)
        except OSError:
            pass    # настройки вида не стоят того, чтобы ронять приложение

    def set_prefs(self, d: Any) -> Dict[str, Any]:
        with self.lock:
            clean = sanitize_prefs(d)
            clean.pop("focus", None)                       # focus меняется только через /api/config
            if "focus" in self.prefs:
                clean["focus"] = self.prefs["focus"]
            self.prefs = clean
            self._save_prefs()
            return dict(self.prefs)

    # ---- интерфейсы ----
    def refresh_interfaces(self) -> None:
        try:
            self.interfaces = self.backend.interfaces()
            self.interfaces_error = None
        except Exception as e:  # noqa: BLE001 - показываем причину в UI
            self.interfaces = []
            self.interfaces_error = str(e)

    # ---- данные ----
    def _apply(self, snap: Snapshot, record_history: bool, ts: Optional[float] = None) -> None:
        if self.oui is not None:
            for b in snap.bss:
                b.vendor = self.oui.lookup(b.bssid)
        self.snapshot = snap
        self.findings = analyze(snap.bss, self.thresholds, self.focus)
        if record_history:
            t = ts if ts is not None else time.time()
            for b in snap.bss:
                self.history.setdefault(b.bssid, deque(maxlen=HISTORY_POINTS)).append(
                    (t, b.rssi, b.info.qbss_util_pct))
            self.scan_count += 1

    def load_snapshot(self, snap: Snapshot) -> None:
        with self.lock:
            self.history.clear()
            self.scan_count = 0
            self._apply(snap, record_history=True)
            self.error = None

    def set_config(self, focus: Optional[List[str]], weak_rssi: Optional[int]) -> None:
        with self.lock:
            if focus is not None:
                self.focus = [s.strip() for s in focus if s.strip()]
                self.prefs["focus"] = sanitize_prefs({"focus": self.focus}).get("focus", [])
                self._save_prefs()
            if weak_rssi is not None:
                self.thresholds.weak_rssi = int(weak_rssi)
            if self.snapshot is not None:
                self.findings = analyze(self.snapshot.bss, self.thresholds, self.focus)

    # ---- базовый снапшот для сравнения «до/после» ----
    def set_baseline(self, snap: Optional[Snapshot]) -> None:
        with self.lock:
            self.baseline = snap

    def set_baseline_current(self) -> bool:
        with self.lock:
            if self.snapshot is None:
                return False
            self.baseline = self.snapshot
            return True

    # ---- фоновые мониторы ----
    def start_monitors(self, interface_index: int = 0) -> None:
        try:
            self.monitor = self.backend.start_conn_monitor(self.conn, self.lock, interface_index)
            if self.monitor is None:
                self.conn.status = "журнал подключения недоступен для этого источника данных"
        except Exception as e:  # noqa: BLE001 - журнал не должен мешать сканеру
            self.conn.status = "журнал подключения не запустился: %s" % e

    def stop_monitors(self) -> None:
        if self.monitor is not None:
            self.monitor.stop()

    def clear_journal(self) -> None:
        with self.lock:
            self.conn.clear()

    def _conn_point(self) -> Optional[Dict[str, Any]]:
        cur = self.conn.current()
        if cur is None or not cur.up:
            return None
        return {"ssid": cur.ssid, "bssid": cur.bssid, "rssi": cur.rssi}

    # ---- обход ----
    def survey_point(self, x: Any, y: Any) -> Dict[str, Any]:
        with self.lock:
            p = dict(self.survey.add_point(x, y))
        if hasattr(self.backend, "set_position"):      # только демо: сканирует «из этой точки»
            self.backend.set_position(p["x"], p["y"])
        self.start_scan(*self._scan_args)       # если скан уже идёт, после него запустится ещё один
        return p

    # ---- скан в фоне ----
    def start_scan(self, interface_index: int, wait_s: float) -> bool:
        self._scan_args = (interface_index, wait_s)
        with self.lock:
            if self.scanning:
                return False
            self.scanning = True
            self.error = None
        threading.Thread(target=self._scan_worker, args=(interface_index, wait_s), daemon=True).start()
        return True

    def _scan_worker(self, idx: int, wait_s: float) -> None:
        started = time.time()
        try:
            snap = self.backend.scan(idx, wait_s)
            with self.lock:
                self._apply(snap, record_history=True)
                self.conn.check_scan(time.time(), snap.bss)
                self.survey.fill(started, snap.bss, self._conn_point())
        except Exception as e:  # noqa: BLE001
            with self.lock:
                self.error = str(e)
                self.survey.fail_pending(started, str(e))
        finally:
            with self.lock:
                self.scanning = False
                again = self.survey.pending_after(started)
        if again:                       # точку поставили во время скана: нужен скан уже из новой позиции
            self.start_scan(idx, wait_s)

    # ---- экспорт: какие сети включать ----
    def export_view(self, scope: str, bssids: Optional[List[str]] = None):
        """Возвращает (снапшот, находки, фокус, история, пояснение) для выбранного набора сетей.

        scope: "all" - всё; "focus" - только «Мои SSID»; "list" - переданный список BSSID
        (так интерфейс передаёт строки, видимые в таблице с её фильтрами).
        Находки считаются по всему эфиру (соседи влияют на каналы), а в отчёт попадают только
        те, что касаются выбранных сетей. Ошибки выбора - ValueError с понятным текстом.
        """
        with self.lock:
            snap, findings, focus = self.snapshot, list(self.findings), list(self.focus)
            hist = {k: list(v) for k, v in self.history.items()}
        if snap is None:
            return None
        if scope == "all":
            return snap, findings, focus, hist, "все сети (%d BSS)" % len(snap.bss)
        if scope == "focus":
            if not focus:
                raise ValueError("не заданы «Мои SSID»: впиши их в поле вверху или выбери «Все сети»")
            keep = [b for b in snap.bss if b.ssid in focus]
            note = "только мои SSID: %s" % ", ".join(focus)
        elif scope == "list":
            if not isinstance(bssids, list) or not all(isinstance(x, str) for x in bssids) or len(bssids) > 20000:
                raise ValueError("bssids должен быть списком строк")
            wanted = set(x.lower() for x in bssids)
            keep = [b for b in snap.bss if b.bssid in wanted]
            note = "сети, видимые в таблице с текущими фильтрами"
        else:
            raise ValueError("неизвестный scope: %r" % (scope,))
        if not keep:
            raise ValueError("в выбранном наборе нет ни одной сети")
        ids = {b.bssid for b in keep}
        ssids = {b.ssid_display for b in keep}
        sub = Snapshot(snap.taken_at, snap.interface, keep)
        fsub = [f for f in findings if ids.intersection(f.bssids) or (f.ssid and f.ssid in ssids)]
        hsub = {k: v for k, v in hist.items() if k in ids}
        return sub, fsub, focus, hsub, "%s (%d BSS)" % (note, len(keep))

    def _conn_dict(self) -> Dict[str, Any]:
        d = self.conn.to_dict(max_samples=1800, max_events=500)
        cur = d["current"]
        if cur and cur.get("bssid") and self.oui is not None:
            cur["vendor"] = self.oui.lookup(cur["bssid"]) or ""
        return d

    # ---- сериализация ----
    def to_dict(self) -> Dict[str, Any]:
        with self.lock:
            snap = self.snapshot
            advice = {}
            if snap is not None:
                for band in ADVICE_BANDS:
                    advice[band] = channel_advice(snap.bss, band)
            rows = []
            denom = max(1, min(self.scan_count, HISTORY_POINTS))
            for b in (snap.bss if snap else []):
                d = bss_to_dict(b)
                h = self.history.get(b.bssid)
                if h:
                    vals = [p[1] for p in h]
                    d.update(seen=len(h), seen_pct=min(100, round(100 * len(h) / denom)),
                             rssi_min=min(vals), rssi_max=max(vals), rssi_avg=round(sum(vals) / len(vals), 1),
                             first_seen=round(h[0][0], 1))
                else:
                    d.update(seen=0, seen_pct=0, rssi_min=b.rssi, rssi_max=b.rssi, rssi_avg=float(b.rssi),
                             first_seen=None)
                rows.append(d)
            base = self.baseline
            diff = None
            if base is not None and snap is not None and base is not snap:
                diff = diff_snapshots(base.bss, snap.bss)
            return {
                "scanning": self.scanning,
                "error": self.error,
                "scan_count": self.scan_count,
                "backend": self.backend.name,
                "interfaces": self.interfaces,
                "interfaces_error": self.interfaces_error,
                "focus": list(self.focus),
                "weak_rssi": self.thresholds.weak_rssi,
                "taken_at": snap.taken_at if snap else None,
                "adapter": snap.interface if snap else "",
                "bss": rows,
                "baseline": {"taken_at": base.taken_at, "count": len(base.bss), "is_current": base is snap} if base else None,
                "diff": diff,
                "findings": [asdict(f) for f in self.findings],
                "advice": advice,
                "util": channel_utilization(snap.bss, self.history) if snap else {"channels": [], "no_data": []},
                "conn": self._conn_dict(),
                "survey": self.survey.summary(),
                "history": {k: [[round(t, 1), r, u] for t, r, u in v] for k, v in self.history.items()},
                "now": round(time.time(), 1),
            }
