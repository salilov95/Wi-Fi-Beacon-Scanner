"""Источники данных для GUI. Всё, что умеет «дать снапшот», подходит под Backend."""
from __future__ import annotations

import random
import sys
import threading
import time
from typing import List, Optional

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


class WindowsBackend(Backend):
    name = "windows"

    def interfaces(self) -> List[str]:
        from . import scanner_win
        return [d for d, _ in scanner_win.list_interfaces()]

    def scan(self, interface_index: int, wait_s: float) -> Snapshot:
        from . import scanner_win
        return scanner_win.scan(interface_index, wait_s)

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

    def _prefill(self, now: float) -> None:
        t0, tr, j = now - 300, self.tracker, lambda: self.rng.uniform(-1.5, 1.5)
        for k in range(300):
            t = t0 + k
            if k < 70:
                s = self._s(t, 0, -50 - k * 0.3 + j())                      # уходим от AP0
            elif k < 140:
                s = self._s(t, 1, -54 - (k - 70) * 0.2 + j())                # роуминг на AP1
            elif k < 146:
                s = ConnSample(t=t, state="disconnected" if k > 141 else "authenticating")
                if k == 142:
                    tr.add_reason(t, "disconnected", 0x00038003, "демо: точка доступа разорвала ассоциацию (deauth)")
            elif k < 175:
                s = self._s(t, 1, -60 + j())
            elif k < 190:
                s = self._s(t, 2, -63 + j())                                 # роуминг на AP2 ...
            elif k < 240:
                s = self._s(t, 1, -61 + j())                                 # ... и быстро обратно: пинг-понг
            else:
                s = self._s(t, 3, -79 + j())                                 # залипание на слабой AP3
            tr.add_sample(s)
            if k >= 240 and k % 5 == 0:
                tr.check_scan(t, [type("B", (), {"bssid": b, "ssid": "CORP", "rssi": r})() for b, r, _ in self.aps])

    def run(self) -> None:
        with self.lock:
            self.tracker.status = "демо-режим: синтетический журнал (5 минут истории + живые замеры)"
            self._prefill(time.time())
        rssi, i, k = -58.0, 0, 0
        while not self._halt.wait(1.0):
            k += 1
            rssi = max(-85.0, min(-40.0, rssi + self.rng.uniform(-2, 2)))
            if k % 90 == 0:
                i, rssi = (i + 1) % 2, -55.0
            with self.lock:
                self.tracker.add_sample(self._s(time.time(), i, rssi))


def default_backend() -> Backend:
    if sys.platform == "win32":
        return WindowsBackend()
    raise RuntimeError("Сканирование доступно только на Windows. Для просмотра интерфейса запусти с --demo.")
