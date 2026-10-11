"""CI (Windows): программа открывает своё окно Edge, окно подключается, а когда окно закрывают,
программа завершается сама. Результат - аннотациями GitHub Actions.

    python tools/smoke_window.py
"""
import os
import queue
import shutil
import subprocess
import sys
import threading
import time

PROFILE_MARK = os.path.join("WiFiBeaconScanner", "edge-profile")


def edge_window_pids():
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
          "Where-Object { $_.CommandLine -like '*%s*' } | ForEach-Object { $_.ProcessId }" % PROFILE_MARK)
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout
    return [int(x) for x in out.split() if x.isdigit()]


def main() -> int:
    env = dict(os.environ, PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WiFiBeaconScanner")
    shutil.rmtree(os.path.join(base, "edge-profile"), ignore_errors=True)     # как самый первый запуск
    app = subprocess.Popen([sys.executable, "-m", "wifi_beacon_scanner", "gui", "--demo"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env)
    lines: "queue.Queue[str]" = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l.rstrip()) for l in app.stdout], daemon=True).start()

    def wait_for(text, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                if app.poll() is not None:
                    return None
                continue
            print(line)
            if text in line:
                return line
        return None

    try:
        if not wait_for("окно подключилось", 90):
            print("::error title=window::окно Edge не подключилось к программе за 90 с")
            return 1
        pids = edge_window_pids()
        print("::notice title=window::окно подключилось, процессов Edge с профилем программы: %d" % len(pids))
        # первые 30 с с новым профилем: Edge может перезапустить себя, программа при этом жить должна
        seen = []
        end = time.monotonic() + 30
        while time.monotonic() < end:
            try:
                line = lines.get(timeout=0.5)
                print(line)
                seen.append(line)
            except queue.Empty:
                pass
            if app.poll() is not None:
                print("::error title=window::программа завершилась при открытом окне: %s" % " | ".join(seen[-5:]))
                return 1
        if any("процесс окна Edge завершился" in x for x in seen):
            print("::notice title=window::Edge перезапустил окно при первом запуске, программа продолжила работу")
        log = os.path.join(base, "logs", "app.log")
        if not os.path.isfile(log):
            print("::error title=window::нет файла журнала %s" % log)
            return 1
        print("::notice title=window::журнал %s, %d байт" % (log, os.path.getsize(log)))
        pids = edge_window_pids()
        for pid in pids:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        if not wait_for("окно Edge закрыто", 30):
            print("::error title=window::окно закрыли, а программа не завершилась")
            return 1
        app.wait(15)
        print("::notice title=window::окно закрыто - программа завершилась сама (код %s)" % app.returncode)
        return 0
    finally:
        if app.poll() is None:
            app.kill()


if __name__ == "__main__":
    sys.exit(main())
