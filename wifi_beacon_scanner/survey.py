"""Обход (site survey): план этажа, точки замеров и их результаты.

Сценарий: инженер загружает план, встаёт в точку и кликает по её месту на плане. Точка создаётся
«в ожидании», программа запускает скан, и результаты скана, начатого ПОСЛЕ клика, записываются
в точку: RSSI всех слышимых BSS плюс текущее подключение ноутбука. Координаты хранятся в долях
от размеров плана (0..1), поэтому не зависят от масштаба окна.

Проект сохраняется в один JSON-файл вместе с картинкой плана (base64).
"""
from __future__ import annotations

import base64
import math
import time
from typing import Any, Dict, List, Optional, Sequence

FORMAT = "wifi_beacon_scanner.survey"
VERSION = 1
MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_POINTS = 2000
MIMES = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}


def _check_plan(mime: str, data: bytes) -> None:
    if mime not in MIMES:
        raise ValueError("план должен быть PNG или JPEG")
    if not data.startswith(MIMES[mime]):
        raise ValueError("файл не похож на %s" % mime)
    if len(data) > MAX_PLAN_BYTES:
        raise ValueError("план больше %d МБ, уменьши картинку" % (MAX_PLAN_BYTES // (1024 * 1024)))


def _num01(v: Any, name: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= 1:
        raise ValueError("%s должен быть числом от 0 до 1" % name)
    return float(v)


class Survey:
    def __init__(self) -> None:
        self.name = "Обход"
        self.plan_mime = ""
        self.plan = b""
        self.points: List[Dict[str, Any]] = []
        self.rev = 0                 # меняется при любом изменении: клиент по нему понимает, что пора перечитать
        self.plan_rev = 0            # меняется только при смене картинки
        self._next_id = 1

    # ---------- план ----------
    def set_plan(self, mime: str, data_b64: str, name: Optional[str] = None) -> None:
        try:
            data = base64.b64decode(data_b64, validate=True)
        except (ValueError, TypeError):
            raise ValueError("картинка плана повреждена (base64)") from None
        _check_plan(mime, data)
        self.plan_mime, self.plan = mime, data
        self.points, self._next_id = [], 1
        if name:
            self.name = str(name)[:120]
        self.plan_rev += 1
        self.rev += 1

    @property
    def has_plan(self) -> bool:
        return bool(self.plan)

    # ---------- точки ----------
    def add_point(self, x: Any, y: Any, t: Optional[float] = None) -> Dict[str, Any]:
        if not self.has_plan:
            raise ValueError("сначала загрузи план этажа")
        if self.has_pending():
            # иначе несколько точек получат один и тот же скан, сделанный уже из новой позиции
            raise ValueError("дождись окончания замера предыдущей точки (около 5 секунд)")
        if len(self.points) >= MAX_POINTS:
            raise ValueError("в проекте уже %d точек" % MAX_POINTS)
        p = {"id": self._next_id, "x": _num01(x, "x"), "y": _num01(y, "y"), "t": t if t is not None else time.time(),
             "status": "pending", "results": {}, "conn": None}
        self._next_id += 1
        self.points.append(p)
        self.rev += 1
        return p

    def delete(self, pid: Any) -> bool:
        n = len(self.points)
        self.points = [p for p in self.points if p["id"] != pid]
        if len(self.points) != n:
            self.rev += 1
            return True
        return False

    def clear_points(self) -> None:
        self.points, self._next_id = [], 1
        self.rev += 1

    def pending_after(self, t: float) -> bool:
        return any(p["status"] == "pending" and p["t"] > t for p in self.points)

    def has_pending(self) -> bool:
        return any(p["status"] == "pending" for p in self.points)

    def fill(self, scan_started: float, bss: Sequence[Any], conn: Optional[Dict[str, Any]]) -> int:
        """Отдаёт результаты скана точкам, созданным до начала этого скана."""
        n = 0
        for p in self.points:
            if p["status"] == "pending" and p["t"] <= scan_started:
                p["results"] = {b.bssid: [b.ssid_display, b.band, b.channel, b.rssi] for b in bss}
                p["conn"] = conn
                p["status"] = "done"
                p["scan_t"] = scan_started
                n += 1
        if n:
            self.rev += 1
        return n

    def fail_pending(self, scan_started: float, error: str) -> None:
        changed = False
        for p in self.points:
            if p["status"] == "pending" and p["t"] <= scan_started:
                p["status"], p["error"] = "failed", error[:200]
                changed = True
        if changed:
            self.rev += 1

    # ---------- сериализация ----------
    def summary(self) -> Dict[str, Any]:
        return {"has_plan": self.has_plan, "name": self.name, "rev": self.rev, "plan_rev": self.plan_rev,
                "points": len(self.points), "pending": sum(1 for p in self.points if p["status"] == "pending")}

    def points_dict(self) -> Dict[str, Any]:
        return {"rev": self.rev, "name": self.name, "points": self.points}

    def to_project(self) -> Dict[str, Any]:
        return {"format": FORMAT, "version": VERSION, "name": self.name,
                "plan": {"mime": self.plan_mime, "data": base64.b64encode(self.plan).decode("ascii")} if self.plan else None,
                "points": self.points}

    def load_project(self, d: Any) -> None:
        if not isinstance(d, dict) or d.get("format") != FORMAT:
            raise ValueError("это не файл проекта обхода")
        if d.get("version") != VERSION:
            raise ValueError("неподдерживаемая версия проекта: %r" % d.get("version"))
        plan = d.get("plan")
        if not isinstance(plan, dict):
            raise ValueError("в проекте нет плана этажа")
        new = Survey()
        new.set_plan(str(plan.get("mime", "")), str(plan.get("data", "")), d.get("name"))
        pts = d.get("points") or []
        if not isinstance(pts, list) or len(pts) > MAX_POINTS:
            raise ValueError("список точек повреждён")
        for raw in pts:
            if not isinstance(raw, dict):
                raise ValueError("точка повреждена")
            p = new.add_point(raw.get("x"), raw.get("y"), float(raw.get("t") or 0))
            res = raw.get("results") or {}
            if not isinstance(res, dict):
                raise ValueError("результаты точки повреждены")
            clean = {}
            for k, v in list(res.items())[:2000]:
                if (isinstance(k, str) and len(k) <= 32 and isinstance(v, list) and len(v) == 4
                        and isinstance(v[3], (int, float)) and not isinstance(v[3], bool)):
                    clean[k] = [str(v[0])[:64], str(v[1])[:4], int(v[2]) if isinstance(v[2], (int, float)) else 0, int(v[3])]
            p["results"] = clean
            c = raw.get("conn")
            p["conn"] = ({"ssid": str(c.get("ssid", ""))[:64], "bssid": str(c.get("bssid", ""))[:32],
                          "rssi": int(c["rssi"]) if isinstance(c.get("rssi"), (int, float)) else None}
                         if isinstance(c, dict) else None)
            p["status"] = "done" if raw.get("status") == "done" else "failed"
        rev, plan_rev = self.rev, self.plan_rev
        self.__dict__.update(new.__dict__)
        self.rev, self.plan_rev = rev + 1, plan_rev + 1     # счётчики только растут: клиент сравнивает их с прошлыми
