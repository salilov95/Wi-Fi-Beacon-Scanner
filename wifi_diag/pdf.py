"""PDF из HTML-отчёта через Edge/Chromium в режиме headless (печать в PDF).

Отдельной PDF-библиотеки не нужно: Edge есть на любом Windows 10/11, а печатает он ту же вёрстку,
что и HTML-отчёт, с кириллицей и цветами. Используется отдельный временный профиль, чтобы не
мешать уже открытому окну приложения. Скриптов в отчёте нет, а его CSP (default-src 'none') запрещает
их выполнение, даже если что-то попадёт в разметку. Флаг выключения JS не используем: с ним Chromium
не печатает PDF.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


def find_browser() -> Optional[str]:
    env = os.environ.get("WIFI_DIAG_PDF_BROWSER")
    if env and os.path.isfile(env):
        return env
    if sys.platform == "win32":
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
            if base:
                p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
                if os.path.isfile(p):
                    return p
    for name in ("msedge", "chromium", "chromium-browser", "google-chrome", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    return None


def html_to_pdf(html: str, timeout: float = 90.0) -> bytes:
    exe = find_browser()
    if not exe:
        raise RuntimeError("не найден Microsoft Edge для печати в PDF; выгрузи HTML и распечатай его в PDF вручную")
    with tempfile.TemporaryDirectory(prefix="wifi_diag_pdf_") as d:
        src = os.path.join(d, "report.html")
        out = os.path.join(d, "report.pdf")
        with open(src, "w", encoding="utf-8") as f:
            f.write(html)
        cmd = [exe, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
               "--disable-extensions",
               "--user-data-dir=" + os.path.join(d, "profile"),
               "--no-pdf-header-footer", "--print-to-pdf-no-header",
               "--print-to-pdf=" + out, pathlib.Path(src).as_uri()]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(1, "--no-sandbox")    # только Linux под root (контейнер с тестами); на Windows песочница остаётся
        kw = {"creationflags": 0x08000000} if sys.platform == "win32" else {}     # CREATE_NO_WINDOW
        try:
            subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, **kw)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Edge не успел напечатать PDF за %d с" % timeout) from None
        if not os.path.isfile(out) or os.path.getsize(out) == 0:
            raise RuntimeError("Edge не создал PDF; выгрузи HTML и распечатай его в PDF вручную")
        with open(out, "rb") as f:
            return f.read()
