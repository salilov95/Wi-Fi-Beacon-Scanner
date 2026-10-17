"""Скриншоты для README: devserver 2.x в демо-режиме, тема и язык - аргументами.

    cd rust && cargo build --example devserver && cd ..
    python tools/screenshots.py rust/target/debug/examples/devserver <manuf> docs/images/en en dark
    python tools/screenshots.py rust/target/debug/examples/devserver <manuf> docs/images ru dark
    python tools/screenshots.py ... en dark main survey      - только названные снимки

<manuf> - база вендоров Wireshark (колонка «Вендор»). Нужны Playwright (Chromium) и Pillow - только для
этого скрипта, программе они не нужны. План этажа и замеры обхода синтетические (survey_project), всё
остальное - демо-режим 2.x, как `WiFiBeaconScanner2.exe --demo`. Снимки в README - в тёмной теме,
light.png - светлая тема для раздела «Отчёты и темы».
"""
import io
import json
import os
import subprocess
import sys
import time
import urllib.request

from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

EXE, MANUF, OUT, LANG, THEME = sys.argv[1:6]
ONLY = set(sys.argv[6:])
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8820 + (LANG == "en")
BASE = "http://127.0.0.1:%d" % PORT


def api(path, body=None):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
                                 method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    try:
        return json.loads(data)
    except ValueError:
        return data


def wait_idle():
    for _ in range(200):
        s = api("/api/state")
        if not s["scanning"] and not s["survey"]["pending"]:
            return
        time.sleep(0.1)


W, H = 1400, 800
ROOMS = {"en": ["Meeting room", "Open space A", "Open space B", "Kitchen", "Corridor", "Storage", "Open space C",
                "Server room"],
         "ru": ["Переговорная", "Опенспейс A", "Опенспейс B", "Кухня", "Коридор", "Склад", "Опенспейс C",
                "Серверная"]}


def floor_plan() -> bytes:
    """Условный план офиса: переговорная, опенспейсы, кухня, коридор, склад, серверная."""
    bg, wall = (250, 250, 247), (60, 64, 70)
    im = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(im)
    font = ImageFont.truetype("/usr/share/fonts/opentype/inter/Inter-Regular.otf", 30)
    d.rectangle([20, 20, W - 20, H - 20], outline=wall, width=8)
    top, bot = 300, 470                                   # коридор между y=300 и y=470
    for x0, x1 in ((20, 120), (200, 400), (480, 680), (760, 960), (1040, 1180), (1250, W - 20)):
        d.line([x0, top, x1, top], fill=wall, width=6)
    for x0, x1 in ((20, 190), (260, 590), (680, 1040), (1120, W - 20)):
        d.line([x0, bot, x1, bot], fill=wall, width=6)
    for x in (300, 610, 920):
        d.line([x, 20, x, top], fill=wall, width=6)
    for x in (190, 420, 870):
        d.line([x, bot, x, H - 20], fill=wall, width=6)
    names = ROOMS[LANG]
    cells = [(160, 150), (455, 150), (765, 150), (1160, 150), (700, 385), (105, 635), (645, 635), (1135, 635)]
    for (cx, cy), name in zip(cells, names):
        d.text((cx, cy), name, fill=(150, 156, 162), font=font, anchor="mm")
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


# Условные места AP (доли плана) для обхода: CORP 01..05; переговорная и склад - дальше всего
AP_AT = {"01": (0.45, 0.2), "02": (0.8, 0.22), "03": (0.55, 0.78), "04": (0.88, 0.78), "05": (0.62, 0.48)}
POINTS = [(0.08, 0.14), (0.2, 0.2), (0.4, 0.14), (0.62, 0.2), (0.86, 0.16), (0.58, 0.32), (0.2, 0.42),
          (0.4, 0.5), (0.65, 0.5), (0.85, 0.6), (0.1, 0.7), (0.07, 0.9), (0.3, 0.7), (0.4, 0.93), (0.52, 0.7),
          (0.72, 0.7), (0.74, 0.93), (0.92, 0.88)]


def survey_project(bss) -> dict:
    """Проект обхода с правдоподобными замерами: затухание по расстоянию + стены 5 ГГц."""
    import base64
    import math
    pts = []
    for i, (x, y) in enumerate(POINTS):
        res = {}
        for b in bss:
            if b["ssid"] != "CORP":
                continue
            ap = AP_AT.get(b["bssid"][12:14])
            if not ap:
                continue
            dist = max(0.03, math.hypot(ap[0] - x, (ap[1] - y) * 0.57))
            rssi = -40 - 26 * math.log10(dist / 0.03) - (5 if b["band"] != "2.4" else 0) - (12 if x < 0.15 else 0)
            res[b["bssid"]] = ["CORP", b["band"], b["channel"], int(round(rssi + ((i * 7) % 5 - 2)))]
        best = max(res.items(), key=lambda kv: kv[1][3])
        pts.append({"id": i + 1, "x": x, "y": y, "t": 1792000000 + i * 40, "status": "done", "results": res,
                    "conn": {"ssid": "CORP", "bssid": best[0], "rssi": best[1][3]}})
    return {"format": "wifi_beacon_scanner.survey", "version": 1, "name": "Floor 3" if LANG == "en" else "Этаж 3",
            "plan": {"mime": "image/png", "data": base64.b64encode(floor_plan()).decode()}, "points": pts}


env = dict(os.environ, WBS_BACKEND="demo", WBS_LANG=LANG, WBS_MANUF=MANUF)
srv = subprocess.Popen([EXE, os.path.join(REPO, "contract/fixtures/demo-base.json"), str(PORT)],
                       env=env, stderr=subprocess.DEVNULL)
try:
    for _ in range(100):
        try:
            api("/api/prefs", {"lang": LANG, "theme": THEME, "auto": False, "connWin": 300})
            break
        except OSError:
            time.sleep(0.1)
    api("/api/config", {"focus": ["CORP"]})
    for _ in range(14):                       # история для «Тренда» и «Сигнала во времени»
        api("/api/scan", {"wait": 1})
        time.sleep(3.5)                       # шаг около 5 с, как у автоскана
        wait_idle()

    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as pw:
        br = pw.chromium.launch()

        def page(w, h):
            pg = br.new_page(viewport={"width": w, "height": h}, bypass_csp=True)
            pg.goto(BASE + "/")
            pg.wait_for_selector("#tbody tr")
            time.sleep(1.2)
            return pg

        def tab(pg, name):
            pg.click('[data-tab="%s"]' % name)
            time.sleep(0.8)

        def expand(pg):
            pg.click("#maxBtn")
            time.sleep(0.8)

        def panel(pg, name, max_h=None):
            """Развёрнутая панель: от вкладок до низа содержимого (не до низа окна)."""
            box = pg.locator("#panel").bounding_box()
            bottom = pg.evaluate("""() => { let m = 0;
                for (const el of document.querySelectorAll('#panelBody *')) {
                  const r = el.getBoundingClientRect();
                  if (r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden') m = Math.max(m, r.bottom);
                } return m; }""")
            hgt = min(bottom - box["y"] + 16, max_h or 10_000, box["height"])
            pg.screenshot(path=os.path.join(OUT, name + ".png"),
                          clip={"x": box["x"], "y": box["y"], "width": box["width"], "height": hgt})

        def select_connected(pg):
            pg.locator("#tbody tr:has(.tag.me)").first.click()
            time.sleep(0.6)

        def want(name):
            return not ONLY or name in ONLY

        if want("main"):
            pg = page(1760, 1000)
            pg.screenshot(path=os.path.join(OUT, "main.png"))
            pg.close()

        if want("standards"):
            pg = page(1760, 960)
            select_connected(pg)
            tab(pg, "beacon")
            pg.click("#stdBtn")
            time.sleep(0.4)
            pg.locator("#stdList label").nth(5).click()        # 802.11r
            time.sleep(0.8)
            pg.screenshot(path=os.path.join(OUT, "standards.png"))
            pg.close()

        if want("beacon"):
            pg = page(1760, 960)
            select_connected(pg)
            tab(pg, "beacon")                                   # RSN, HT Cap, HT Op раскрыты по умолчанию
            expand(pg)
            pg.screenshot(path=os.path.join(OUT, "beacon.png"))
            pg.close()

        for name, t, h in (("overview", "overview", None), ("utilization", "util", None),
                           ("signal", "signal", 800), ("heatmap", "signal", None), ("connection", "conn", 1018),
                           ("findings", "findings", 1018)):
            if not want(name):
                continue
            pg = page(1600, 1000)
            tab(pg, t)
            expand(pg)
            if name == "heatmap":
                pg.click('[data-sig="heat"]')
                time.sleep(0.8)
            elif name == "signal":
                pg.click('[data-sig="lines"]')
                time.sleep(0.8)
            panel(pg, name, h)
            pg.close()

        if want("sessions") or want("winlog"):
            for name, t in (("sessions", "sessions"), ("winlog", "winlog")):
                if not want(name):
                    continue
                pg = page(1760, 1000)
                tab(pg, t)
                expand(pg)
                time.sleep(1.5)
                rows = pg.locator("#panelBody tbody tr")
                if t == "sessions":
                    rows.nth(3).click()
                else:
                    pg.locator("#panelBody tbody tr", has_text="12013").first.click()
                time.sleep(0.8)
                pg.screenshot(path=os.path.join(OUT, name + ".png"))
                pg.close()

        if want("light"):
            api("/api/prefs", {"lang": LANG, "theme": "light", "auto": False, "connWin": 300})
            pg = page(1600, 1000)
            pg.screenshot(path=os.path.join(OUT, "light.png"))
            pg.close()
            api("/api/prefs", {"lang": LANG, "theme": THEME, "auto": False, "connWin": 300})

        if want("survey"):
            rows = api("/api/state")["bss"]
            r = api("/api/survey/project", survey_project(rows))
            assert "error" not in r, r
            pg = page(1600, 1000)
            tab(pg, "survey")
            expand(pg)
            pg.click('[data-svmode="view"]')
            time.sleep(1.5)
            panel(pg, "survey", 900)
            pg.close()
        br.close()
finally:
    srv.terminate()
