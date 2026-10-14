"""Сессии подключения: машина состояний клиента по уведомлениям Windows.

Источники (все без прав администратора):
  * ACM: connection_start / connection_complete / connection_attempt_fail / disconnected;
  * MSM: associating → associated → authenticating → connected, roaming_start / roaming_end,
    disassociating / disconnected;
  * ONEX (802.1X): результат аутентификации EAP, причина отказа, тип EAP, чья учётка (машина/пользователь);
  * IP (GetAdaptersInfo): когда появился IPv4 и когда получена аренда DHCP.

Из этого собирается список сессий. Сессия - одна попытка подключения или один роуминг: стадии
с отметками времени и длительности. 4-way handshake отдельно Windows не сообщает: он входит
в стадию «аутентификация» (authenticating → connected). Для 802.1X туда же входит весь обмен EAP.
Модуль не зависит от Windows: на вход подаются уже разобранные события, поэтому он покрыт тестами.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional
from .i18n import N_, tr

STAGE_RU = {
    "start": N_("начало подключения"), "associating": N_("ассоциация"), "associated": N_("ассоциирован"),
    "authenticating": N_("аутентификация"), "connected": N_("подключён"), "complete": N_("подключение завершено"),
    "roam_start": N_("начало роуминга"), "roam_end": N_("роуминг завершён"), "disassociating": N_("разрыв ассоциации"),
    "disconnected": N_("отключён"), "fail": N_("не удалось подключиться"), "ip": N_("получен IPv4"),
    "dhcp": N_("аренда DHCP"), "onex": "802.1X", "onex_restart": N_("802.1X перезапущен"),
}
ONEX_STATUS_RU = {0: N_("не начата"), 1: N_("идёт"), 2: N_("нет ответа от аутентификатора (802.1X не включён на AP?)"),
                  3: N_("успех"), 4: N_("отказ"), 5: N_("неизвестно")}
ONEX_IDENTITY_RU = {0: N_("нет"), 1: N_("компьютер"), 2: N_("пользователь"), 3: N_("явно заданный пользователь"), 4: N_("гость")}
EAP_TYPES = {1: "Identity", 4: "MD5", 6: "GTC", 13: "EAP-TLS", 17: "LEAP", 18: "EAP-SIM", 21: "EAP-TTLS",
             23: "EAP-AKA", 25: "PEAP", 26: "MSCHAPv2", 43: "EAP-FAST", 50: "EAP-AKA'"}

SESSION_TIMEOUT_S = 120.0       # попытка без исхода дольше этого считается брошенной
IP_WAIT_S = 60.0                # сколько после подключения ждём IPv4 / новую аренду DHCP


@dataclass
class Stage:
    t: float
    stage: str
    detail: str = ""


@dataclass
class Session:
    id: int
    kind: str                       # connect | roam
    t_start: float
    ssid: str = ""
    bssid: str = ""
    bssid_from: str = ""
    result: str = "in_progress"     # in_progress | ok | fail | aborted
    reason: str = ""
    reason_code: Optional[int] = None
    stages: List[Stage] = field(default_factory=list)
    t_assoc_start: Optional[float] = None
    t_assoc_done: Optional[float] = None
    t_auth_start: Optional[float] = None
    t_connected: Optional[float] = None
    t_end: Optional[float] = None
    # 802.1X
    onex_status: Optional[int] = None
    onex_reason: str = ""
    onex_reason_code: Optional[int] = None
    onex_error: str = ""
    onex_error_code: Optional[int] = None
    eap_type: Optional[int] = None
    onex_identity: Optional[int] = None
    onex_restarts: int = 0
    # IP / DHCP
    t_ip: Optional[float] = None
    ip: str = ""
    dhcp_server: str = ""
    dhcp: Optional[bool] = None
    lease_obtained: Optional[float] = None
    ip_note: str = ""
    ip_kind: str = ""                   # lease / appeared / kept / static / apipa - для логики, не для показа
    ip_checked: bool = False
    ip_at_connect: str = ""
    lease_at_connect: Optional[float] = None

    def ms(self, a: Optional[float], b: Optional[float]) -> Optional[int]:
        return None if a is None or b is None else max(0, int(round((b - a) * 1000)))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        first = self.t_assoc_start if self.kind == "roam" and self.t_assoc_start is not None else self.t_start
        d.update(
            assoc_ms=self.ms(self.t_assoc_start, self.t_assoc_done),
            auth_ms=self.ms(self.t_auth_start, self.t_connected),
            total_ms=self.ms(first, self.t_connected),
            ip_ms=self.ms(self.t_connected, self.t_ip),
            eap_name=EAP_TYPES.get(self.eap_type, "EAP %d" % self.eap_type) if self.eap_type is not None else "",
            onex_status_ru=tr(ONEX_STATUS_RU.get(self.onex_status, "")) if self.onex_status is not None else "",
            onex_identity_ru=tr(ONEX_IDENTITY_RU.get(self.onex_identity, "")) if self.onex_identity is not None else "",
        )
        return d


class SessionTracker:
    def __init__(self, max_sessions: int = 300) -> None:
        self.sessions: Deque[Session] = deque(maxlen=max_sessions)
        self._next_id = 1
        self._open: Optional[Session] = None
        self._lease: Optional[float] = None          # последняя известная аренда DHCP
        self._ip: str = ""
        self._linked = False                         # ноутбук сейчас подключён (для роуминга без roaming_start)

    # ---------- служебное ----------
    def _new(self, t: float, kind: str, ssid: str = "", bssid: str = "", bssid_from: str = "") -> Session:
        if self._open is not None and self._open.result == "in_progress":
            self._finish(self._open, t, "aborted", tr("прервано новой попыткой"))
        s = Session(self._next_id, kind, t, ssid=ssid, bssid=bssid, bssid_from=bssid_from)
        self._next_id += 1
        self.sessions.append(s)
        self._open = s
        return s

    @staticmethod
    def _finish(s: Session, t: float, result: str, reason: str = "", code: Optional[int] = None) -> None:
        s.result, s.t_end = result, t
        if reason:
            s.reason = reason
        if code is not None:
            s.reason_code = code

    def _current(self, t: float) -> Optional[Session]:
        s = self._open
        if s is not None and s.result == "in_progress" and t - s.t_start > SESSION_TIMEOUT_S:
            if s.t_connected is not None:
                self._finish(s, t, "ok")            # подключились, а завершающее уведомление не пришло
            else:
                self._finish(s, t, "aborted", tr("нет исхода за %d с") % SESSION_TIMEOUT_S)
        return s

    def last_connected(self, t: float, within: float = IP_WAIT_S) -> Optional[Session]:
        for s in reversed(self.sessions):
            if s.t_connected is not None:
                return s if t - s.t_connected <= within else None
        return None

    # ---------- стадии из ACM / MSM ----------
    def stage(self, t: float, stage: str, ssid: str = "", bssid: str = "", reason_code: Optional[int] = None,
              reason: str = "") -> Optional[Session]:
        s = self._current(t)
        active = s is not None and s.result == "in_progress"
        if stage == "start":
            s = self._new(t, "connect", ssid)
        elif stage == "roam_start":
            prev = self.sessions[-1].bssid if self.sessions else ""
            s = self._new(t, "roam", ssid, bssid_from=bssid or prev)
        elif stage == "associating":
            if not active:
                # без connection_start: роуминг без roaming_start (если связь была) или переподключение
                prev = self.sessions[-1].bssid if self.sessions else ""
                s = self._new(t, "roam", ssid, bssid, bssid_from=prev) if self._linked else \
                    self._new(t, "connect", ssid, bssid)
            s.t_assoc_start = s.t_assoc_start or t
        elif not active:
            if s is not None and stage in ("roam_end", "complete") and s.t_end is not None and t - s.t_end < 5:
                s.stages.append(Stage(t, stage, reason))     # хвост только что закрытой сессии
                return s
            if stage in ("connected", "complete", "roam_end", "disconnected", "disassociating", "fail"):
                return None             # событие вне попытки подключения
            s = self._new(t, "connect", ssid, bssid)
        assert s is not None
        if ssid and not s.ssid:
            s.ssid = ssid
        if bssid and stage not in ("roam_start",):
            s.bssid = bssid
        s.stages.append(Stage(t, stage, reason))
        if stage in ("connected", "complete", "roam_end"):
            self._linked = s.result != "fail"
        elif stage in ("disconnected", "disassociating", "fail"):
            self._linked = False
        if stage == "associated":
            s.t_assoc_done = t
        elif stage == "authenticating":
            s.t_auth_start = s.t_auth_start or t
        elif stage == "connected":
            if s.t_connected is None:
                s.t_connected = t
                s.ip_at_connect, s.lease_at_connect = self._ip, self._lease
            if s.kind == "roam":
                self._finish(s, t, "ok")
        elif stage == "complete":
            if reason_code:
                self._finish(s, t, "fail", reason, reason_code)
            else:
                if s.t_connected is None:
                    s.t_connected = t
                    s.ip_at_connect, s.lease_at_connect = self._ip, self._lease
                self._finish(s, t, "ok")
        elif stage == "roam_end":
            if s.t_connected is None:
                s.t_connected = t
            self._finish(s, t, "ok" if s.result == "in_progress" else s.result)
        elif stage in ("fail", "disconnected", "disassociating"):
            if s.result == "in_progress":
                self._finish(s, t, "fail", reason or tr(STAGE_RU[stage]), reason_code)
        if s.result != "in_progress" and self._open is s:
            self._open = None if s.t_connected is None else s     # подключённую держим для IP
        return s

    # ---------- 802.1X ----------
    def onex(self, t: float, status: int, reason_code: int = 0, reason: str = "", error_code: int = 0,
             error: str = "", eap_type: Optional[int] = None, identity: Optional[int] = None,
             restarted: bool = False) -> Optional[Session]:
        s = self._open if self._open is not None and (self._open.result == "in_progress" or
                                                      t - (self._open.t_connected or t) < 30) else None
        if s is None:
            s = self._new(t, "connect")
        if restarted:
            s.onex_restarts += 1
            s.stages.append(Stage(t, "onex_restart", reason))
            return s
        s.onex_status = status
        if reason_code:
            s.onex_reason_code, s.onex_reason = reason_code, reason
        if error_code:
            s.onex_error_code, s.onex_error = error_code, error
        if eap_type is not None:
            s.eap_type = eap_type
        if identity is not None:
            s.onex_identity = identity
        detail = tr(ONEX_STATUS_RU.get(status, str(status)))
        if reason:
            detail += ": " + reason
        s.stages.append(Stage(t, "onex", detail))
        if status in (2, 4) and s.result == "in_progress":
            self._finish(s, t, "fail", "802.1X: " + (reason or error or tr(ONEX_STATUS_RU.get(status, ""))),
                         reason_code or error_code or None)
        return s

    # ---------- IP / DHCP ----------
    def ip_update(self, t: float, ip: str, dhcp: Optional[bool] = None, dhcp_server: str = "",
                  lease_obtained: Optional[float] = None) -> Optional[Session]:
        """Опрос адаптера раз в секунду. Новая аренда DHCP после подключения и есть завершённый DORA:
        время берём из самой аренды (LeaseObtained), оно точнее опроса."""
        valid = bool(ip) and ip != "0.0.0.0"
        self._ip = ip if valid else ""
        if lease_obtained is not None:
            self._lease = lease_obtained
        s = self.last_connected(t)
        if s is None or s.ip_checked or not valid:
            return None
        s.ip, s.dhcp, s.dhcp_server = ip, dhcp, dhcp_server
        if lease_obtained is not None and lease_obtained != s.lease_at_connect and lease_obtained >= s.t_connected - 2:
            s.t_ip = min(t, max(s.t_connected, float(lease_obtained)))
            s.lease_obtained = lease_obtained
            s.ip_note, s.ip_kind = tr("новая аренда DHCP"), "lease"
        elif ip != s.ip_at_connect:
            s.t_ip = t
            s.ip_note, s.ip_kind = tr("адрес появился") + (" (DHCP)" if dhcp else ""), "appeared"
        elif t - s.t_connected >= 10:
            s.ip_kind = "kept" if dhcp else "static"
            s.ip_note = (tr("адрес сохранился с прошлого подключения, новой аренды DHCP не было") if dhcp
                         else tr("статический адрес"))
        else:
            return None
        if ip.startswith("169.254."):
            s.ip_note, s.ip_kind = tr("APIPA 169.254.x.x: DHCP-сервер не ответил"), "apipa"
        s.ip_checked = True
        s.stages.append(Stage(s.t_ip if s.t_ip is not None else t, "dhcp" if s.ip_kind == "lease" else "ip",
                              "%s%s, %s" % (ip, (tr(", DHCP-сервер ") + dhcp_server) if dhcp_server else "", s.ip_note)))
        return s

    # ---------- сводка ----------
    def summary(self) -> Dict[str, Any]:
        ss = list(self.sessions)

        def med(vals):
            vals = sorted(v for v in vals if v is not None)
            return vals[len(vals) // 2] if vals else None
        conn = [s for s in ss if s.kind == "connect"]
        roam = [s for s in ss if s.kind == "roam"]
        d = [s.to_dict() for s in ss]
        return {
            "connects": len(conn), "connects_ok": sum(1 for s in conn if s.result == "ok"),
            "connects_fail": sum(1 for s in conn if s.result in ("fail", "aborted")),
            "roams": len(roam), "roams_fail": sum(1 for s in roam if s.result in ("fail", "aborted")),
            "connect_ms_med": med(x["total_ms"] for x in d if x["kind"] == "connect" and x["result"] == "ok"),
            "roam_ms_med": med(x["total_ms"] for x in d if x["kind"] == "roam" and x["result"] == "ok"),
            "auth_ms_med": med(x["auth_ms"] for x in d),
            "ip_ms_med": med(x["ip_ms"] for x in d if x.get("ip_kind") in ("lease", "appeared")),
            "onex_ok": sum(1 for s in ss if s.onex_status == 3),
            "onex_fail": sum(1 for s in ss if s.onex_status in (2, 4)),
        }

    def to_dict(self, max_sessions: int = 200) -> Dict[str, Any]:
        return {"sessions": [s.to_dict() for s in list(self.sessions)[-max_sessions:]], "summary": self.summary()}

    def clear(self) -> None:
        self.__init__(self.sessions.maxlen or 300)
