"""Проверка собранного exe в CI: запускается, отвечает, сканирует демо-эфир и выгружает PDF и Excel.

Запуск (Windows, из корня проекта):  python tools/smoke_exe.py dist\\WiFiBeaconScanner\\WiFiBeaconScanner.exe
Результат пишется аннотациями GitHub Actions (::notice / ::error), чтобы его было видно без логов.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request


def log_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "WiFiBeaconScanner", "wifi-beacon-scanner.log")


def call(base: str, token: str, path: str, body=None, timeout=90):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method="GET" if body is None else "POST",
                                 headers={"X-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def main(exe: str) -> int:
    lp = log_path()
    if os.path.exists(lp):
        os.remove(lp)
    proc = subprocess.Popen([exe, "--demo", "--no-browser", "--ssid", "CORP"])
    try:
        m = None
        for _ in range(60):
            time.sleep(0.5)
            if proc.poll() is not None:
                break
            if os.path.exists(lp):
                with open(lp, encoding="utf-8", errors="replace") as f:
                    m = re.search(r"(http://127\.0\.0\.1:\d+)/\?t=([\w-]+)", f.read())
                if m:
                    break
        if not m:
            print("::error title=exe::exe не запустил сервер (код %s)" % proc.poll())
            return 1
        base, token = m.group(1), m.group(2)
        call(base, token, "/api/scan", {"interface": 0, "wait": 1})
        for _ in range(40):
            st = json.loads(call(base, token, "/api/state")[1])
            if st.get("scan_count"):
                break
            time.sleep(0.5)
        else:
            print("::error title=exe::скан не завершился")
            return 1
        ok = True
        for fmt, magic in (("pdf", b"%PDF"), ("xlsx", b"PK")):
            t = time.monotonic()
            try:
                code, data = call(base, token, "/api/export/" + fmt, {"scope": "focus"})
            except urllib.error.HTTPError as e:
                code, data = e.code, e.read()
            good = code == 200 and data.startswith(magic)
            ok &= good
            print("::%s title=%s::%s: HTTP %s, %d байт за %.1f с%s" % (
                "notice" if good else "error", fmt.upper(), fmt, code, len(data), time.monotonic() - t,
                "" if good else ", ответ: " + data[:300].decode("utf-8", "replace")))
        print("::notice title=exe::%d BSS, версия окна отвечает" % len(st.get("bss", [])))
        return 0 if ok else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
