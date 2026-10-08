"""Журнал собственного подключения ноутбука: из замеров раз в секунду получаем события.

Источник замеров - опрос текущего подключения (WlanQueryInterface, current_connection) и,
если Windows разрешает, уведомления WLAN API с кодами причин. Этот модуль от Windows не зависит:
он получает готовые ConnSample и уведомления и строит события, поэтому полностью покрыт тестами.

События:
  connected      - подключились (после старта или после обрыва; для обрыва указана длительность)
  disconnected   - связь пропала; причина подтягивается из уведомления, если оно пришло рядом
  roam           - сменилась BSS в том же SSID (сколько провели на прошлой, RSSI до и после)
  ssid_change    - переключились на другую сеть
  pingpong       - роуминг A->B, затем быстро B->A: признак пограничной зоны или порогов роуминга
  sticky         - «залипание»: клиент держится за слабую BSS, хотя та же сеть рядом слышна заметно сильнее
  attempt_fail   - неудачная попытка подключения (из уведомления), с причиной
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence

CONNECTED = "connected"

STATE_RU = {
    "connected": "подключён", "disconnected": "отключён", "disconnecting": "отключается",
    "associating": "ассоциация", "authenticating": "аутентификация", "discovering": "поиск сети",
    "not_ready": "адаптер не готов", "ad_hoc": "ad hoc", "unknown": "неизвестно",
}


@dataclass
class ConnSample:
    t: float
    state: str                      # см. STATE_RU
    ssid: str = ""
    bssid: str = ""
    rssi: Optional[int] = None      # дБм (opcode rssi)
    quality: Optional[int] = None   # 0..100 по драйверу
    channel: Optional[int] = None
    rx_mbps: Optional[float] = None
    tx_mbps: Optional[float] = None
    auth: str = ""
    cipher: str = ""
    onex: bool = False
    profile: str = ""

    @property
    def up(self) -> bool:
        return self.state == CONNECTED and bool(self.bssid)


@dataclass
class ConnEvent:
    t: float
    kind: str
    severity: str                   # info | warning | critical
    text: str
    ssid: str = ""
    bssid_from: str = ""
    bssid_to: str = ""
    rssi_from: Optional[int] = None
    rssi_to: Optional[int] = None
    duration_s: Optional[float] = None   # время на прошлой BSS / длительность обрыва
    reason_code: Optional[int] = None
    reason: str = ""


class ConnTracker:
    def __init__(self, sticky_rssi: int = -75, sticky_delta: int = 8, sticky_hold_s: float = 10.0,
                 pingpong_window_s: float = 30.0, max_samples: int = 7200, max_events: int = 2000,
                 reason_attach_s: float = 10.0) -> None:
        self.sticky_rssi = sticky_rssi
        self.sticky_delta = sticky_delta
        self.sticky_hold_s = sticky_hold_s
        self.pingpong_window_s = pingpong_window_s
        self.reason_attach_s = reason_attach_s
        self.samples: Deque[ConnSample] = deque(maxlen=max_samples)
        self.events: Deque[ConnEvent] = deque(maxlen=max_events)
        self.raw: Deque[Dict[str, Any]] = deque(maxlen=300)     # сырые уведомления для отладки
        self.status: str = "не запущен"
        self._last: Optional[ConnSample] = None
        self._bss_since: Optional[float] = None
        self._down_since: Optional[float] = None
        self._last_roam: Optional[ConnEvent] = None
        self._sticky_since: Optional[float] = None
        self._sticky_reported_for: str = ""
        self._dwell: Dict[str, float] = {}                      # bssid -> секунд на ней

    # ---------- замеры ----------
    def add_sample(self, s: ConnSample) -> List[ConnEvent]:
        out: List[ConnEvent] = []
        prev = self._last
        if prev is not None and prev.up:
            self._dwell[prev.bssid] = self._dwell.get(prev.bssid, 0.0) + max(0.0, s.t - prev.t)
        if prev is None:
            if s.up:
                self._bss_since = s.t
                out.append(ConnEvent(s.t, "connected", "info", "Подключён к %s" % (s.ssid or "?"),
                                     ssid=s.ssid, bssid_to=s.bssid, rssi_to=s.rssi))
            else:
                self._down_since = s.t
        elif prev.up and s.up:
            if s.ssid != prev.ssid:
                out.append(ConnEvent(s.t, "ssid_change", "warning", "Переключился на другую сеть: %s → %s" % (prev.ssid, s.ssid),
                                     ssid=s.ssid, bssid_from=prev.bssid, bssid_to=s.bssid,
                                     rssi_from=prev.rssi, rssi_to=s.rssi, duration_s=self._since(self._bss_since, s.t)))
                self._bss_since = s.t
                self._last_roam = None
            elif s.bssid != prev.bssid:
                ev = ConnEvent(s.t, "roam", "info", "Роуминг", ssid=s.ssid, bssid_from=prev.bssid, bssid_to=s.bssid,
                               rssi_from=prev.rssi, rssi_to=s.rssi, duration_s=self._since(self._bss_since, s.t))
                out.append(ev)
                lr = self._last_roam
                if (lr is not None and lr.bssid_from == s.bssid and lr.bssid_to == prev.bssid
                        and s.t - lr.t <= self.pingpong_window_s):
                    out.append(ConnEvent(s.t, "pingpong", "warning",
                                         "Пинг-понг: вернулся на прежнюю BSS через %.0f с" % (s.t - lr.t),
                                         ssid=s.ssid, bssid_from=prev.bssid, bssid_to=s.bssid,
                                         rssi_from=prev.rssi, rssi_to=s.rssi, duration_s=s.t - lr.t))
                self._last_roam = ev
                self._bss_since = s.t
                self._sticky_since = None
        elif prev.up and not s.up:
            out.append(ConnEvent(s.t, "disconnected", "critical", "Связь пропала (%s)" % STATE_RU.get(s.state, s.state),
                                 ssid=prev.ssid, bssid_from=prev.bssid, rssi_from=prev.rssi,
                                 duration_s=self._since(self._bss_since, s.t)))
            self._down_since = s.t
            self._sticky_since = None
            self._attach_recent_reason(out[-1])
        elif not prev.up and s.up:
            gap = self._since(self._down_since, s.t)
            out.append(ConnEvent(s.t, "connected", "info",
                                 "Подключён к %s" % (s.ssid or "?") + (" после %.0f с без связи" % gap if gap else ""),
                                 ssid=s.ssid, bssid_to=s.bssid, rssi_to=s.rssi, duration_s=gap))
            self._bss_since = s.t
            self._down_since = None
        self.samples.append(s)
        self._last = s
        self.events.extend(out)
        return out

    @staticmethod
    def _since(t0: Optional[float], t: float) -> Optional[float]:
        return None if t0 is None else round(max(0.0, t - t0), 1)

    # ---------- уведомления с причинами ----------
    def add_reason(self, t: float, kind: str, reason_code: Optional[int], reason: str, ssid: str = "",
                   bssid: str = "") -> Optional[ConnEvent]:
        """kind: 'disconnected' | 'attempt_fail'. Причину обрыва приклеиваем к ближайшему событию
        «Связь пропала», если оно рядом по времени; иначе это отдельное событие."""
        if kind == "disconnected":
            for ev in reversed(self.events):
                if t - ev.t > self.reason_attach_s:
                    break
                if ev.kind == "disconnected" and not ev.reason and abs(ev.t - t) <= self.reason_attach_s:
                    ev.reason_code, ev.reason = reason_code, reason
                    return None
            ev = ConnEvent(t, "disconnect_reason", "warning", "Windows сообщила об отключении", ssid=ssid,
                           bssid_from=bssid, reason_code=reason_code, reason=reason)
        else:
            ev = ConnEvent(t, "attempt_fail", "critical", "Не удалось подключиться к %s" % (ssid or "сети"),
                           ssid=ssid, bssid_to=bssid, reason_code=reason_code, reason=reason)
        self.events.append(ev)
        return ev

    def _attach_recent_reason(self, ev: ConnEvent) -> None:
        # уведомление могло прийти раньше, чем опрос заметил обрыв
        for other in reversed(self.events):
            if ev.t - other.t > self.reason_attach_s:
                break
            if other.kind == "disconnect_reason" and other.reason:
                ev.reason_code, ev.reason = other.reason_code, other.reason
                self.events.remove(other)
                return

    def add_raw(self, t: float, source: int, code: int, name: str) -> None:
        self.raw.append({"t": round(t, 1), "source": source, "code": code, "name": name})

    # ---------- «залипание» по данным скана ----------
    def check_scan(self, t: float, bss: Sequence[Any]) -> Optional[ConnEvent]:
        """bss - BSS из последнего скана (у них есть bssid, ssid, rssi). Если подключённая BSS слабее
        порога, а другая BSS той же сети слышна сильнее на sticky_delta дБ дольше sticky_hold_s - событие."""
        cur = self._last
        if cur is None or not cur.up:
            self._sticky_since = None
            return None
        # живой RSSI подключения точнее: результаты скана Windows может отдавать из кэша
        mine = next((b for b in bss if b.bssid == cur.bssid), None)
        my_rssi = cur.rssi if cur.rssi is not None else (mine.rssi if mine is not None else None)
        if my_rssi is None or my_rssi >= self.sticky_rssi:
            self._sticky_since = None
            return None
        better = [b for b in bss if b.ssid == cur.ssid and b.bssid != cur.bssid and b.rssi >= my_rssi + self.sticky_delta]
        if not better:
            self._sticky_since = None
            return None
        if self._sticky_since is None:
            self._sticky_since = t
        if t - self._sticky_since < self.sticky_hold_s or self._sticky_reported_for == cur.bssid:
            return None
        best = max(better, key=lambda b: b.rssi)
        self._sticky_reported_for = cur.bssid
        ev = ConnEvent(t, "sticky", "warning",
                       "Залипание: держится за слабую BSS, хотя рядом есть сильнее на %d дБ" % (best.rssi - my_rssi),
                       ssid=cur.ssid, bssid_from=cur.bssid, bssid_to=best.bssid, rssi_from=my_rssi, rssi_to=best.rssi,
                       duration_s=round(t - self._sticky_since, 1))
        self.events.append(ev)
        return ev

    # ---------- сводка ----------
    def stats(self) -> Dict[str, Any]:
        kinds: Dict[str, int] = {}
        for e in self.events:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
        down = sum((e.duration_s or 0) for e in self.events if e.kind == "connected" and e.duration_s)
        if self._down_since is not None and self._last is not None and not self._last.up:
            down += max(0.0, self._last.t - self._down_since)
        t0 = self.samples[0].t if self.samples else None
        t1 = self.samples[-1].t if self.samples else None
        return {
            "roams": kinds.get("roam", 0), "disconnects": kinds.get("disconnected", 0),
            "pingpong": kinds.get("pingpong", 0), "sticky": kinds.get("sticky", 0),
            "attempt_fail": kinds.get("attempt_fail", 0), "ssid_change": kinds.get("ssid_change", 0),
            "down_s": round(down, 1), "since": t0, "until": t1,
            "dwell": sorted(({"bssid": k, "s": round(v, 1)} for k, v in self._dwell.items()), key=lambda x: -x["s"]),
        }

    def current(self) -> Optional[ConnSample]:
        return self._last

    def clear(self) -> None:
        last = self._last
        self.__init__(self.sticky_rssi, self.sticky_delta, self.sticky_hold_s, self.pingpong_window_s,
                      self.samples.maxlen or 7200, self.events.maxlen or 2000, self.reason_attach_s)
        if last is not None:
            self.add_sample(last)

    def to_dict(self, max_samples: int = 3600, max_events: int = 500) -> Dict[str, Any]:
        cur = self._last
        samples = list(self.samples)[-max_samples:] if max_samples > 0 else []   # [-0:] вернул бы всё
        return {
            "status": self.status,
            "current": asdict(cur) if cur else None,
            "samples": [[round(s.t, 1), s.rssi if s.up else None, s.bssid if s.up else ""] for s in samples],
            "events": [asdict(e) for e in list(self.events)[-max_events:]],
            "stats": self.stats(),
            "raw": list(self.raw)[-60:],
        }
