"""PDF из HTML-отчёта через Edge/Chromium в режиме headless (печать в PDF).

Отдельной PDF-библиотеки не нужно: Edge есть на любом Windows 10/11, а печатает он ту же вёрстку,
что и HTML-отчёт, с кириллицей и цветами. Используется отдельный временный профиль, чтобы не
мешать уже открытому окну приложения. Скриптов в отчёте нет, а его CSP (default-src 'none') запрещает
их выполнение, даже если что-то попадёт в разметку. Флаг выключения JS не используем: с ним Chromium
не печатает PDF.

Особенности Windows, из-за которых печать раньше срывалась:
  * после печати Edge может не завершиться сразу (фоновые процессы, crashpad), поэтому ждём не выхода
    процесса, а готового файла (заканчивается на %%EOF и перестал расти), потом закрываем дерево процессов;
  * эти процессы держат файлы временного профиля, удаление папки падало с PermissionError и обрывало
    ответ сервера. Теперь папка удаляется без ошибок, а что не удалилось, удаляется позже;
  * Edge бывает установлен не в Program Files: ищем ещё в профиле пользователя и по App Paths в реестре.
"""
from __future__ import annotations

import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import List, Optional

log = logging.getLogger(__name__)

ENV_BROWSER = "WIFI_BEACON_SCANNER_PDF_BROWSER"


class PdfError(RuntimeError):
    """Печать не удалась; текст понятен человеку."""


def _app_path(exe: str) -> Optional[str]:
    """Путь из HKLM/HKCU\\...\\App Paths\\<exe> (так Windows сама находит msedge.exe и chrome.exe)."""
    try:
        import winreg  # type: ignore
    except ImportError:
        return None
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s" % exe
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, key) as k:
                p = winreg.QueryValue(k, None)
        except OSError:
            continue
        p = (p or "").strip().strip('"')
        if p and os.path.isfile(p):
            return p
    return None


def candidates() -> List[str]:
    out: List[str] = []
    env = os.environ.get(ENV_BROWSER)
    if env:
        out.append(env)
    if sys.platform == "win32":
        bases = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")]
        for base in filter(None, bases):
            out.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
        out += list(filter(None, [_app_path("msedge.exe")]))
        for base in filter(None, bases):
            out.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
        out += list(filter(None, [_app_path("chrome.exe")]))
    for name in ("msedge", "chromium", "chromium-browser", "google-chrome", "chrome"):
        p = shutil.which(name)
        if p:
            out.append(p)
    return out


def find_browser() -> Optional[str]:
    for p in candidates():
        if p and os.path.isfile(p):
            return p
    return None


def _pdf_ready(path: str) -> bool:
    try:
        size = os.path.getsize(path)
        if size < 100:
            return False
        with open(path, "rb") as f:
            f.seek(max(0, size - 64))
            return b"%%EOF" in f.read()
    except OSError:
        return False


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, creationflags=0x08000000, check=False)
    else:
        proc.kill()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        pass


def _rmtree_later(path: str) -> None:
    """Удалить временную папку. Если Edge ещё держит файлы, повторить через несколько секунд в фоне."""
    shutil.rmtree(path, ignore_errors=True)
    if not os.path.exists(path):
        return

    def retry() -> None:
        for _ in range(6):
            time.sleep(5)
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.exists(path):
                return
    threading.Thread(target=retry, name="pdf-cleanup", daemon=True).start()


def html_to_pdf(html: str, timeout: float = 60.0) -> bytes:
    exe = find_browser()
    if not exe:
        raise PdfError("не найден Microsoft Edge (или Chrome) для печати в PDF")
    d = tempfile.mkdtemp(prefix="wbs_pdf_")
    try:
        src = os.path.join(d, "report.html")
        out = os.path.join(d, "report.pdf")
        with open(src, "w", encoding="utf-8") as f:
            f.write(html)
        cmd = [exe, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
               "--disable-extensions", "--disable-background-mode", "--disable-sync",
               "--user-data-dir=" + os.path.join(d, "profile"),
               "--no-pdf-header-footer", "--print-to-pdf-no-header",
               "--print-to-pdf=" + out, pathlib.Path(src).as_uri()]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(1, "--no-sandbox")    # только Linux под root (контейнер с тестами); на Windows песочница остаётся
        kw = {"creationflags": 0x08000000} if sys.platform == "win32" else {}     # CREATE_NO_WINDOW
        err_path = os.path.join(d, "browser.log")
        with open(err_path, "wb") as err:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err, stdin=subprocess.DEVNULL, **kw)
            t0, last_size, stable_since = time.monotonic(), -1, None
            try:
                while time.monotonic() - t0 < timeout:
                    exited = proc.poll() is not None
                    if _pdf_ready(out):
                        size = os.path.getsize(out)
                        if size == last_size:
                            if stable_since is None:
                                stable_since = time.monotonic()
                            if exited or time.monotonic() - stable_since >= 0.5:
                                break
                        else:
                            last_size, stable_since = size, None
                    elif exited:
                        break
                    time.sleep(0.2)
            finally:
                _kill_tree(proc)
        if not _pdf_ready(out):
            tail = ""
            try:
                with open(err_path, "rb") as f:
                    tail = f.read()[-1500:].decode("utf-8", "replace")
            except OSError:
                pass
            log.warning("PDF не создан: %s, код выхода %s, вывод браузера: %s", exe, proc.returncode, tail)
            if time.monotonic() - t0 >= timeout:
                raise PdfError("браузер не успел напечатать PDF за %d с" % timeout)
            raise PdfError("браузер не создал PDF (код выхода %s). Возможно, печать без окна запрещена политикой; "
                           "открой отчёт для печати и сохрани в PDF через Ctrl+P" % proc.returncode)
        with open(out, "rb") as f:
            return f.read()
    finally:
        _rmtree_later(d)
