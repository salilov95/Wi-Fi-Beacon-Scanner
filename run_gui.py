"""Точка входа для .exe (PyInstaller). Делает то же, что `python -m wifi_beacon_scanner gui`.

В установленной версии exe собран без консоли (--windowed): sys.stdout и sys.stderr тогда равны None.
Чтобы print и падения при старте не пропадали, они пишутся в %LOCALAPPDATA%\\WiFiBeaconScanner\\logs\\console.log
(файл больше 1 МБ начинается заново). Основной журнал программы - app.log рядом (applog.py).
"""
import os
import sys


def _log_to_file() -> None:
    if sys.stdout is not None and sys.stderr is not None:
        return
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    folder = os.path.join(base, "WiFiBeaconScanner", "logs")
    try:
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "console.log")
        mode = "w" if os.path.exists(path) and os.path.getsize(path) > 1024 * 1024 else "a"
        f = open(path, mode, encoding="utf-8", buffering=1)
    except OSError:
        return
    sys.stdout = sys.stdout or f
    sys.stderr = sys.stderr or f


if __name__ == "__main__":
    _log_to_file()
    from datetime import datetime

    from wifi_beacon_scanner import __version__
    from wifi_beacon_scanner.__main__ import main

    print("--- Wi-Fi Beacon Scanner %s, запуск %s" % (__version__, datetime.now().isoformat(timespec="seconds")))
    sys.exit(main(["gui"] + sys.argv[1:]))
