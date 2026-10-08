"""HTTP-сервер локального GUI на stdlib.

Безопасность (важно: приложение управляет Wi-Fi адаптером, а в SSID соседей может быть что угодно):
  * слушаем только 127.0.0.1;
  * каждый API-запрос требует одноразовый токен (заголовок X-Token); токен выдаётся
    только в URL, который мы сами открываем, сразу убирается из адресной строки и хранится
    во вкладке (sessionStorage). Сама страница без токена данных не показывает;
  * проверяем заголовок Host (защита от DNS rebinding) и отклоняем чужой Origin;
  * CSP запрещает inline-скрипты, поэтому даже если SSID попадёт в разметку без экранирования,
    скрипт из него не выполнится.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Optional, Tuple
from urllib.parse import urlparse

from .. import report
from ..pdf import html_to_pdf
from ..rules import channel_utilization
from ..model import Snapshot
from .state import PREF_THEMES, AppState

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
MAX_BODY = 12 * 1024 * 1024     # план этажа до 8 МБ в base64
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class WifiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr: Tuple[str, int], state: AppState, token: str) -> None:
        super().__init__(addr, Handler)
        self.state = state
        self.token = token

    @property
    def port(self) -> int:
        return self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    server: WifiServer  # type: ignore[assignment]
    server_version = "wifi_diag"

    def log_message(self, fmt: str, *args: Any) -> None:  # тише в консоли
        pass

    # ---------- вспомогательное ----------
    def _send(self, code: int, body: bytes, ctype: str, extra: Optional[dict] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.port
        if host not in ("127.0.0.1:%d" % port, "localhost:%d" % port):
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port)

    def _token_ok(self, query_token: Optional[str] = None) -> bool:
        t = self.headers.get("X-Token") or query_token or ""
        return secrets.compare_digest(t, self.server.token)

    def _body_json(self) -> Any:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("слишком большое тело запроса")
        raw = self.rfile.read(n) if n else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    # ---------- маршруты ----------
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._json(403, {"error": "bad host"})
        u = urlparse(self.path)
        if u.path in STATIC_FILES:
            # Оболочка страницы секретов не содержит и отдаётся без токена: иначе перезагрузка
            # (Ctrl+R) ломала бы приложение, ведь токен из адресной строки уже убран.
            # Все данные и действия идут через /api/* и требуют токен.
            name, ctype = STATIC_FILES[u.path]
            with open(os.path.join(STATIC_DIR, name), "rb") as f:
                data = f.read()
            if u.path == "/":
                # Тему подставляем сразу в разметку, чтобы окно не мигало светлым при запуске.
                # Значения берутся из белого списка (sanitize_prefs), произвольный текст сюда не попадёт.
                pr = self.server.state.prefs
                attrs = ""
                if pr.get("theme") in PREF_THEMES - {"auto"}:
                    attrs += ' data-theme="%s"' % pr["theme"]
                if pr.get("density") in ("normal", "compact"):
                    attrs += ' data-density="%s"' % pr["density"]
                data = data.replace(b'<html lang="ru">', ('<html lang="ru"%s>' % attrs).encode("ascii"), 1)
            return self._send(200, data, ctype)
        if not self._token_ok():
            return self._json(403, {"error": "bad token"})
        st = self.server.state
        if u.path == "/api/state":
            return self._json(200, st.to_dict())
        if u.path == "/api/prefs":
            return self._json(200, st.prefs)
        if u.path == "/api/survey/plan":
            with st.lock:
                mime, data = st.survey.plan_mime, st.survey.plan
            if not data:
                return self._json(404, {"error": "план не загружен"})
            return self._send(200, data, mime)
        if u.path == "/api/survey/points":
            with st.lock:
                return self._json(200, st.survey.points_dict())
        if u.path == "/api/survey/project":
            with st.lock:
                if not st.survey.has_plan:
                    return self._json(409, {"error": "нечего сохранять: план не загружен"})
                data = json.dumps(st.survey.to_project(), ensure_ascii=False).encode("utf-8")
            return self._send(200, data, "application/json",
                              {"Content-Disposition": 'attachment; filename="wifi-survey.json"'})
        if u.path.startswith("/api/export/"):
            return self._export(u.path.rsplit("/", 1)[1])
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._json(403, {"error": "bad host"})
        if not self._token_ok():
            return self._json(403, {"error": "bad token"})
        st = self.server.state
        path = urlparse(self.path).path
        try:
            body = self._body_json()
            if path == "/api/scan":
                idx = int(body.get("interface", 0))
                wait = max(1.0, min(30.0, float(body.get("wait", 5.0))))
                ok = st.start_scan(idx, wait)
                return self._json(202 if ok else 409, {"started": ok})
            if path == "/api/config":
                focus = body.get("focus")
                if focus is not None and not (isinstance(focus, list) and all(isinstance(x, str) for x in focus)):
                    return self._json(400, {"error": "focus должен быть списком строк"})
                st.set_config(focus, body.get("weak_rssi"))
                return self._json(200, {"ok": True})
            if path == "/api/load":
                st.load_snapshot(Snapshot.from_json(json.dumps(body)))
                return self._json(200, {"ok": True})
            if path.startswith("/api/export/"):
                return self._export(path.rsplit("/", 1)[1], str(body.get("scope", "all")), body.get("bssids"))
            if path == "/api/prefs":
                return self._json(200, st.set_prefs(body))
            if path == "/api/survey/plan":
                with st.lock:
                    st.survey.set_plan(str(body.get("mime", "")), str(body.get("data", "")), body.get("name"))
                return self._json(200, st.survey.summary())
            if path == "/api/survey/point":
                return self._json(200, st.survey_point(body.get("x"), body.get("y")))
            if path == "/api/survey/delete":
                with st.lock:
                    ok = st.survey.delete(body.get("id"))
                return self._json(200 if ok else 404, {"ok": ok})
            if path == "/api/survey/clear":
                with st.lock:
                    st.survey.clear_points()
                return self._json(200, {"ok": True})
            if path == "/api/survey/project":
                with st.lock:
                    st.survey.load_project(body)
                return self._json(200, st.survey.summary())
            if path == "/api/conn/clear":
                st.clear_journal()
                return self._json(200, {"ok": True})
            if path == "/api/baseline":
                if body.get("clear"):
                    st.set_baseline(None)
                elif body.get("current"):
                    if not st.set_baseline_current():
                        return self._json(409, {"error": "ещё нет данных: сначала выполни скан"})
                else:
                    st.set_baseline(Snapshot.from_json(json.dumps(body)))
                return self._json(200, {"ok": True})
            if path == "/api/quit":
                self._json(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return None
        except ValueError as e:              # наши проверки: текст уже понятен человеку
            return self._json(400, {"error": str(e)})
        except (KeyError, TypeError, AttributeError) as e:
            return self._json(400, {"error": "неверный запрос (%s: %s)" % (type(e).__name__, e)})
        return self._json(404, {"error": "not found"})

    def _export(self, fmt: str, scope: str = "all", bssids: Optional[List[str]] = None) -> None:
        st = self.server.state
        if fmt == "journal":            # журнал подключения от выбора сетей не зависит
            with st.lock:
                events = st.conn.to_dict(max_samples=0, max_events=100000)["events"]
            return self._send(200, report.render_journal_csv(events).encode("utf-8-sig"), "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="wifi-journal.csv"'})
        if fmt not in ("html", "csv", "json", "history", "xlsx", "pdf"):
            return self._json(404, {"error": "неизвестный формат"})
        try:
            view = st.export_view(scope, bssids)
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        if view is None:
            return self._json(409, {"error": "ещё нет данных: сначала выполни скан"})
        snap, findings, focus, hist, note = view
        suffix = {"all": "", "focus": "-my", "list": "-filtered"}.get(scope, "")
        extra = {}
        if fmt in ("html", "pdf", "xlsx"):
            # загрузка каналов - по выбранным сетям; журнал и обход - целиком (они про ноутбук и маршрут)
            with st.lock:
                extra = {"util": channel_utilization(snap.bss),
                         "journal": st.conn.to_dict(max_samples=0, max_events=100000),
                         "survey": [dict(p) for p in st.survey.points]}
        if fmt == "html":
            data, ctype, fname = (report.render_html(snap, findings, focus, note, **extra).encode("utf-8"),
                                  "text/html; charset=utf-8", "wifi-report%s.html" % suffix)
        elif fmt == "pdf":
            try:
                data = html_to_pdf(report.render_html(snap, findings, focus, note, **extra))
            except RuntimeError as e:
                return self._json(500, {"error": str(e)})
            ctype, fname = "application/pdf", "wifi-report%s.pdf" % suffix
        elif fmt == "xlsx":
            data = report.build_xlsx_report(snap, findings, focus, note, history=hist, **extra)
            ctype, fname = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "wifi-report%s.xlsx" % suffix)
        elif fmt == "csv":
            data, ctype, fname = report.render_csv(snap.bss).encode("utf-8-sig"), "text/csv; charset=utf-8", "wifi-bss%s.csv" % suffix
        elif fmt == "json":
            data, ctype, fname = snap.to_json().encode("utf-8"), "application/json", "wifi-snapshot%s.json" % suffix
        else:
            if not hist:
                return self._json(409, {"error": "истории ещё нет: сделай хотя бы два скана"})
            names = {x.bssid: (x.ssid_display, x.band, x.channel) for x in snap.bss}
            data, ctype, fname = (report.render_history_csv(hist, names).encode("utf-8-sig"),
                                  "text/csv; charset=utf-8", "wifi-history%s.csv" % suffix)
        self._send(200, data, ctype, {"Content-Disposition": 'attachment; filename="%s"' % fname})


# ---------- запуск ----------
def make_server(state: AppState, port: int = 0) -> WifiServer:
    return WifiServer(("127.0.0.1", port), state, secrets.token_urlsafe(24))


def app_url(server: WifiServer) -> str:
    return "http://127.0.0.1:%d/?t=%s" % (server.port, server.token)


def _find_edge() -> Optional[str]:
    p = shutil.which("msedge")
    if p:
        return p
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if base:
            cand = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.isfile(cand):
                return cand
    return None


def open_window(url: str) -> None:
    """Edge в режиме --app даёт окно без адресной строки; иначе обычный браузер по умолчанию."""
    if sys.platform == "win32":
        edge = _find_edge()
        if edge:
            subprocess.Popen([edge, "--app=" + url])
            return
    webbrowser.open(url)


def serve(state: AppState, port: int = 0, open_browser: bool = True) -> None:
    server = make_server(state, port)
    state.refresh_interfaces()
    state.start_monitors()
    url = app_url(server)
    print("Интерфейс: %s" % url)
    print("Остановить: кнопка «Выход» в окне или Ctrl+C")
    if open_browser:
        open_window(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        state.stop_monitors()
        server.server_close()
