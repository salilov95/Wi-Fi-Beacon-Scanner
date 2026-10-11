"""Проверка новой версии на GitHub Releases. Только по кнопке: программа сама в интернет не ходит."""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

REPO = "salilov95/Wi-Fi-Beacon-Scanner"
API = "https://api.github.com/repos/%s/releases/latest" % REPO
RELEASES = "https://github.com/%s/releases" % REPO


def parse_version(v: str) -> Optional[Tuple[int, ...]]:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def _fetch(url: str, timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "WiFiBeaconScanner"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # системный прокси Windows urllib берёт сам
        return json.loads(r.read().decode("utf-8"))


def check(current: str, fetch: Callable[[str, float], Dict[str, Any]] = _fetch, timeout: float = 6.0) -> Dict[str, Any]:
    """{"current", "latest", "newer", "url", "published", "error"}; ошибки сети - в "error", без исключений."""
    out: Dict[str, Any] = {"current": current, "latest": None, "newer": False, "url": RELEASES, "published": None,
                           "error": ""}
    try:
        d = fetch(API, timeout)
    except Exception as e:  # noqa: BLE001 - нет сети, прокси, лимит API: показать причину и не падать
        out["error"] = "не удалось связаться с GitHub: %s" % (getattr(e, "reason", None) or e)
        return out
    tag = str(d.get("tag_name") or "")
    out["latest"] = tag.lstrip("v") or None
    out["url"] = str(d.get("html_url") or RELEASES)
    out["published"] = d.get("published_at")
    a, b = parse_version(current), parse_version(tag)
    out["newer"] = bool(a and b and b > a)
    if b is None:
        out["error"] = "GitHub не вернул номер версии"
    return out
