"""Журнал работы программы в файл.

У установленной версии нет консоли, поэтому без файла сообщения терялись и понять, что случилось
на ноутбуке пользователя, было нечем. Файл: %LOCALAPPDATA%\\WiFiBeaconScanner\\logs\\app.log
(на других ОС ~/.cache/wifi_beacon_scanner/logs/app.log), до 1 МБ, плюс три предыдущих.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import platform
import sys
import threading
from typing import Optional

log = logging.getLogger("wifi_beacon_scanner")
FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_path: Optional[str] = None


def log_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "WiFiBeaconScanner", "logs")
    return os.path.join(os.path.expanduser("~"), ".cache", "wifi_beacon_scanner", "logs")


def log_path() -> Optional[str]:
    """Путь к текущему файлу журнала или None, если писать в файл не получилось."""
    return _path


def setup(level: int = logging.INFO, directory: Optional[str] = None) -> Optional[str]:
    """Включает журнал: файл (если можно создать) и консоль (если она есть). Повторный вызов ничего не меняет."""
    global _path
    root = logging.getLogger()
    if getattr(root, "_wbs_configured", False):
        return _path
    root.setLevel(level)
    fmt = logging.Formatter(FORMAT)
    if sys.stderr is not None:          # в exe без консоли sys.stderr = None
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(fmt)
        root.addHandler(h)
    d = directory or log_dir()
    try:
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "app.log")
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
        _path = path
    except OSError as e:
        log.warning("журнал в файл не пишется: %s", e)
    root._wbs_configured = True        # type: ignore[attr-defined]
    _hook_exceptions()
    from . import __version__
    log.info("запуск %s, Python %s, %s %s, %s", __version__, platform.python_version(), platform.system(),
             platform.version(), sys.executable)
    return _path


def _hook_exceptions() -> None:
    prev = sys.excepthook

    def hook(tp, val, tb):
        log.critical("необработанная ошибка", exc_info=(tp, val, tb))
        if prev is not None:
            prev(tp, val, tb)
    sys.excepthook = hook

    def thook(args):
        if args.exc_type is SystemExit:
            return
        log.error("ошибка в потоке %s", getattr(args.thread, "name", "?"),
                  exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
    threading.excepthook = thook
