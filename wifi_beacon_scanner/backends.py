"""Источники данных для GUI. Всё, что умеет «дать снапшот», подходит под Backend."""
from __future__ import annotations

import random
import sys
import threading
import time
from typing import List, Optional

from .i18n import tr
from .conn import ConnSample, ConnTracker
from .mcs import phy_rate
from .demo import build_demo_snapshot
from .model import Bss, Snapshot, now_iso


class Backend:
    name = "base"

    def interfaces(self) -> List[str]:
        raise NotImplementedError

    def scan(self, interface_index: int, wait_s: float) -> Snapshot:
        raise NotImplementedError

    def start_conn_monitor(self, tracker: ConnTracker, lock: threading.Lock, interface_index: int = 0):
        """Запускает фоновый монитор подключения; None, если источник его не поддерживает."""
        return None

    def read_winlog(self, hours: float = 24) -> List[dict]:
        """События журнала WLAN-AutoConfig/Operational за последние hours часов (новые первыми)."""
        raise OSError(tr("журнал Windows недоступен для этого источника данных"))


class WindowsBackend(Backend):
    name = "windows"

    def interfaces(self) -> List[str]:
        from . import scanner_win
        return [d for d, _ in scanner_win.list_interfaces()]

    def scan(self, interface_index: int, wait_s: float) -> Snapshot:
        from . import scanner_win
        return scanner_win.scan(interface_index, wait_s)

    def read_winlog(self, hours: float = 24) -> List[dict]:
        from .winlog_win import read_events
        return read_events(hours)

    def start_conn_monitor(self, tracker, lock, interface_index=0):
        from .conn_win import WinConnMonitor
        m = WinConnMonitor(tracker, lock, interface_index)
        m.start()
        return m


class DemoBackend(Backend):
    """Крутит заранее заданный снапшот: каждый «скан» слегка меняет RSSI и иногда
    «теряет» слабый BSS, как в реальности."""
    name = "demo"

    def __init__(self, base: Optional[Snapshot] = None, seed: Optional[int] = None) -> None:
        self.base = base or build_demo_snapshot()
        self.rng = random.Random(seed)
        self.pos: Optional[tuple] = None        # позиция «ноутбука» на плане (только для демо-обхода)

    def set_position(self, x: float, y: float) -> None:
        self.pos = (x, y)

    @staticmethod
    def _virtual_place(bssid: str) -> tuple:
        """Условное место AP на плане: радио одной AP (общий префикс MAC) стоят в одной точке."""
        h = sum((i + 1) * ord(c) for i, c in enumerate(bssid[:14]))
        return (0.08 + (h % 97) / 97 * 0.84, 0.1 + (h // 97 % 89) / 89 * 0.8)

    def interfaces(self) -> List[str]:
        return ["Demo adapter"]

    def read_winlog(self, hours: float = 24) -> List[dict]:
        now = time.time()
        return [e for e in demo_winlog(now) if e["t"] >= now - hours * 3600]

    def start_conn_monitor(self, tracker, lock, interface_index=0):
        m = DemoConnMonitor(tracker, lock, self.base)
        m.start()
        return m

    def scan(self, interface_index: int, wait_s: float) -> Snapshot:
        time.sleep(min(wait_s, 0.6))
        out: List[Bss] = []
        for b in self.base.bss:
            rssi = b.rssi + self.rng.randint(-3, 3)
            if self.pos is not None:            # демо-обход: сигнал падает с расстоянием до условного места AP
                ax, ay = self._virtual_place(b.bssid)
                dist = max(0.02, ((ax - self.pos[0]) ** 2 + ((ay - self.pos[1]) * 0.55) ** 2) ** 0.5)
                rssi = int(-38 - 30 * (dist / 0.3) ** 0.8 - (4 if b.band != "2.4" else 0) + self.rng.randint(-2, 2))
                if rssi < -92:
                    continue
            elif b.rssi < -78 and self.rng.random() < 0.3:
                continue
            out.append(Bss(
                bssid=b.bssid, ssid_bytes=b.ssid_bytes,
                rssi=max(-100, min(-20, rssi)),
                link_quality=b.link_quality, freq_khz=b.freq_khz, beacon_interval=b.beacon_interval,
                capability=b.capability, phy_type=b.phy_type, ie_raw=b.ie_raw))
        return Snapshot(taken_at=now_iso(), interface=self.base.interface, bss=out)


def _demo_rate(rssi: float, back: int) -> float:
    """Скорость как у настоящего HE-подключения 2x2, 80 МГц: MCS падает с сигналом (примерно 3 дБ на ступень)."""
    mcs = max(0, min(11, int((rssi + 82) / 3)) - back)
    return round(phy_rate("HE", mcs, 2, 80), 1)


def demo_connect(ses, t: float, bssid: str, ip_after: float, eap_s: float = 0.6, fail: str = "",
                 lease: bool = True) -> None:
    """Синтетическое подключение: ассоциация, 802.1X EAP-TLS (учётка компьютера), 4-way, DHCP."""
    ses.stage(t, "start", "CORP")
    ses.stage(t + 0.05, "associating", "CORP", bssid)
    ses.stage(t + 0.08, "associated", "CORP", bssid)
    ses.stage(t + 0.08, "authenticating", "CORP", bssid)
    ses.onex(t + 0.10, 1, eap_type=13, identity=1)
    if fail:
        ses.onex(t + 0.10 + eap_s, 4, 0x50005, fail, 0x80092013,
                 tr("демо: функции отзыва не смогли проверить отзыв сертификата"), eap_type=13, identity=1)
        ses.stage(t + 0.2 + eap_s, "fail", "CORP", bssid, 0x50005, tr("демо: ") + fail)
        return
    ses.onex(t + 0.10 + eap_s, 3, eap_type=13, identity=1)
    ses.stage(t + 0.14 + eap_s, "connected", "CORP", bssid)
    ses.stage(t + 0.16 + eap_s, "complete", "CORP", bssid)
    tc = t + 0.14 + eap_s
    ses.ip_update(tc + ip_after + 0.3, "10.20.30.41", True, "10.20.0.10", (tc + ip_after) if lease else None)


def demo_roam(ses, t: float, frm: str, to: str, ms: float, full_auth: bool = False) -> None:
    """Синтетический роуминг: с FT (802.11r) или с полной 802.1X-аутентификацией."""
    ses.stage(t, "roam_start", "CORP", frm)
    ses.stage(t + 0.01, "associating", "CORP", to)
    a = ms * (0.45 if not full_auth else 0.1) / 1000.0
    ses.stage(t + 0.01 + a, "associated", "CORP", to)
    ses.stage(t + 0.01 + a, "authenticating", "CORP", to)
    if full_auth:
        ses.onex(t + 0.02 + a, 1, eap_type=13, identity=1)
        ses.onex(t + ms / 1000.0, 3, eap_type=13, identity=1)
    ses.stage(t + 0.01 + ms / 1000.0, "connected", "CORP", to)
    ses.stage(t + 0.02 + ms / 1000.0, "roam_end", "CORP", to)


def demo_winlog(now: float) -> List[dict]:
    """Синтетические события WLAN-AutoConfig для демо-режима (текст - пересказ, помечен «демо»)."""
    from .winlog import group_of, LEVEL_RU
    ok = {"ProfileName": "CORP", "SSID": "CORP", "BSSType": "Infrastructure", "PHYType": "802.11ax",
          "AuthenticationAlgorithm": "WPA2-Enterprise", "CipherAlgorithm": "AES-CCMP", "OnexEnabled": "1"}
    rows = [
        (-30500, 8001, 4, tr("демо: служба WLAN AutoConfig успешно подключилась к сети CORP"), ok),
        (-21900, 8003, 4, tr("демо: отключено от сети CORP. Причина: пользователь отключил беспроводное подключение"),
         {"SSID": "CORP", "Reason": tr("Пользователь отключил подключение"), "ReasonCode": "0x00028002"}),
        (-21850, 8002, 2, tr("демо: не удалось подключиться к сети Hotel-WiFi. Причина: сеть недоступна"),
         {"SSID": "Hotel-WiFi", "FailureReason": tr("Сеть недоступна"), "ReasonCode": "0x00028002"}),
        (-9000, 11006, 3, tr("демо: проверка безопасности беспроводной сети не выполнена: истекло время ожидания 4-way handshake"),
         {"SSID": "CORP", "PeerMac": "00:e0:fc:10:04:02", "FailureReason": tr("Тайм-аут 4-way handshake"), "ReasonCode": "0x00048001"}),
        (-8990, 8002, 2, tr("демо: не удалось подключиться к сети CORP. Причина: тайм-аут 4-way handshake"),
         {"SSID": "CORP", "FailureReason": tr("Тайм-аут 4-way handshake"), "ReasonCode": "0x00048001"}),
        (-8950, 8001, 4, tr("демо: служба WLAN AutoConfig успешно подключилась к сети CORP"), ok),
        (-290, 8000, 4, tr("демо: служба WLAN AutoConfig начала подключение к сети CORP"), {"SSID": "CORP", "ConnectionMode": "Auto"}),
        (-289.9, 11000, 4, tr("демо: начата ассоциация с беспроводной сетью"), {"SSID": "CORP", "PeerMac": "00:e0:fc:10:01:02"}),
        (-289.8, 11001, 4, tr("демо: ассоциация с беспроводной сетью выполнена"), {"SSID": "CORP", "PeerMac": "00:e0:fc:10:01:02"}),
        (-289.8, 11010, 4, tr("демо: начата проверка безопасности беспроводной сети"), {"SSID": "CORP"}),
        (-289.7, 12011, 4, tr("демо: начата проверка подлинности 802.1X"), {"SSID": "CORP", "EAPType": "13"}),
        (-289.1, 12012, 4, tr("демо: проверка подлинности 802.1X выполнена (EAP-TLS, учётные данные компьютера)"),
         {"SSID": "CORP", "EAPType": "13", "Identity": "host/LAPTOP-01"}),
        (-289.0, 11005, 4, tr("демо: проверка безопасности беспроводной сети выполнена"), {"SSID": "CORP"}),
        (-288.9, 8001, 4, tr("демо: служба WLAN AutoConfig успешно подключилась к сети CORP"), ok),
        (-158, 8003, 4, tr("демо: отключено от сети CORP. Причина: точка доступа разорвала ассоциацию"),
         {"SSID": "CORP", "Reason": tr("Точка доступа разорвала ассоциацию"), "ReasonCode": "0x00038004"}),
        (-157, 8000, 4, tr("демо: служба WLAN AutoConfig начала подключение к сети CORP"), {"SSID": "CORP", "ConnectionMode": "Auto"}),
        (-156.5, 12013, 2, tr("демо: ошибка проверки подлинности 802.1X: не удалось проверить отзыв сертификата"),
         {"SSID": "CORP", "EAPType": "13", "Reason": tr("Не удалось проверить отзыв сертификата"), "ErrorCode": "0x80092013"}),
        (-156.4, 8002, 2, tr("демо: не удалось подключиться к сети CORP. Причина: ошибка 802.1X"),
         {"SSID": "CORP", "FailureReason": tr("Ошибка проверки подлинности 802.1X"), "ReasonCode": "0x00050005"}),
        (-154, 8000, 4, tr("демо: служба WLAN AutoConfig начала подключение к сети CORP"), {"SSID": "CORP", "ConnectionMode": "Auto"}),
        (-152.6, 12012, 4, tr("демо: проверка подлинности 802.1X выполнена"), {"SSID": "CORP", "EAPType": "13"}),
        (-152.5, 8001, 4, tr("демо: служба WLAN AutoConfig успешно подключилась к сети CORP"), ok),
    ]
    out = []
    for dt, eid, level, msg, data in rows:
        out.append({"t": now + dt, "id": eid, "level": level, "level_ru": LEVEL_RU.get(level, ""), "group": group_of(eid),
                    "message": msg, "ssid": data.get("SSID", ""), "bssid": data.get("PeerMac", ""),
                    "reason": data.get("FailureReason", data.get("Reason", "")), "data": dict(data)})
    return sorted(out, key=lambda e: -e["t"])


class DemoConnMonitor(threading.Thread):
    """Демо-журнал: сначала мгновенно «проигрывает» 5 минут истории с роумингами, обрывом,
    пинг-понгом и залипанием, потом раз в секунду добавляет живые замеры. Причины помечены «демо»."""
    daemon = True

    def __init__(self, tracker: ConnTracker, lock: threading.Lock, base: Snapshot, seed: Optional[int] = 7) -> None:
        super().__init__(name="demo-conn")
        self.tracker, self.lock = tracker, lock
        self.rng = random.Random(seed)
        corp = sorted([b for b in base.bss if b.ssid == "CORP" and b.band == "5"], key=lambda b: -b.rssi)
        self.aps = [(b.bssid, b.rssi, b.channel) for b in corp] or [("02:00:00:00:00:01", -55, 36)]
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def _s(self, t: float, i: int, rssi: float) -> ConnSample:
        bssid, _, ch = self.aps[i % len(self.aps)]
        return ConnSample(t=t, state="connected", ssid="CORP", bssid=bssid, rssi=int(round(rssi)),
                          quality=max(0, min(100, int(2 * (rssi + 100)))), channel=ch,
                          rx_mbps=_demo_rate(rssi, 0), tx_mbps=_demo_rate(rssi, 1),
                          auth="WPA2 (RSNA)", cipher="CCMP", onex=True, profile="CORP")

    def _prefill_sessions(self, t0: float) -> None:
        ses, ap = self.tracker.sessions, [a[0] for a in self.aps] + [a[0] for a in self.aps]
        ses.ip_update(t0 - 5, "0.0.0.0", True, "", t0 - 7200)
        demo_connect(ses, t0 - 1.0, ap[0], ip_after=0.8)
        demo_roam(ses, t0 + 70 - 0.06, ap[0], ap[1], 42)                       # FT: десятки мс
        ses.stage(t0 + 141.5, "disconnected", "CORP", ap[1], 0x38003, tr("демо: точка доступа разорвала ассоциацию"))
        ses.ip_update(t0 + 142, "0.0.0.0", True, "", t0 - 1)
        demo_connect(ses, t0 + 143.0, ap[1], ip_after=0, eap_s=0.5, fail=tr("EAP-TLS: сервер отклонил аутентификацию"))
        demo_connect(ses, t0 + 144.4, ap[1], ip_after=1.9, eap_s=1.3)
        demo_roam(ses, t0 + 175 - 0.05, ap[1], ap[2], 38)
        demo_roam(ses, t0 + 190 - 0.2, ap[2], ap[1], 186)                     # медленный роуминг обратно
        demo_roam(ses, t0 + 240 - 0.4, ap[1], ap[3], 410, full_auth=True)     # без FT: полный 802.1X

    def _prefill(self, now: float) -> None:
        t0, trk, j = now - 300, self.tracker, lambda: self.rng.uniform(-1.5, 1.5)
        self._prefill_sessions(t0)
        for k in range(300):
            t = t0 + k
            if k < 70:
                s = self._s(t, 0, -50 - k * 0.3 + j())                      # уходим от AP0
            elif k < 140:
                s = self._s(t, 1, -54 - (k - 70) * 0.2 + j())                # роуминг на AP1
            elif k < 146:
                s = ConnSample(t=t, state="disconnected" if k > 141 else "authenticating")
                if k == 142:
                    trk.add_reason(t, "disconnected", 0x00038003, tr("демо: точка доступа разорвала ассоциацию (deauth)"))
            elif k < 175:
                s = self._s(t, 1, -60 + j())
            elif k < 190:
                s = self._s(t, 2, -63 + j())                                 # роуминг на AP2 ...
            elif k < 240:
                s = self._s(t, 1, -61 + j())                                 # ... и быстро обратно: пинг-понг
            else:
                s = self._s(t, 3, -79 + j())                                 # залипание на слабой AP3
            trk.add_sample(s)
            if k >= 240 and k % 5 == 0:
                trk.check_scan(t, [type("B", (), {"bssid": b, "ssid": "CORP", "rssi": r})() for b, r, _ in self.aps])

    def run(self) -> None:
        with self.lock:
            self.tracker.status = tr("демо-режим: синтетический журнал (5 минут истории + живые замеры)")
            self._prefill(time.time())
        rssi, i, k = -58.0, 0, 0
        while not self._halt.wait(1.0):
            k += 1
            rssi = max(-85.0, min(-40.0, rssi + self.rng.uniform(-2, 2)))
            if k % 90 == 0:
                with self.lock:
                    demo_roam(self.tracker.sessions, time.time() - 0.05, self.aps[i % len(self.aps)][0],
                              self.aps[(i + 1) % 2 % len(self.aps)][0], self.rng.choice([35, 48, 62, 140]))
                i, rssi = (i + 1) % 2, -55.0
            with self.lock:
                self.tracker.add_sample(self._s(time.time(), i, rssi))


def default_backend() -> Backend:
    if sys.platform == "win32":
        return WindowsBackend()
    raise RuntimeError(tr("Сканирование доступно только на Windows. Для просмотра интерфейса запусти с --demo."))
