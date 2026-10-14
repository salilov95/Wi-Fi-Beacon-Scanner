"""Поиск строк для перевода (разработка).

    python tools/i18n_scan.py report     - кириллица вне tr()/N_(): где ещё не переведено
    python tools/i18n_scan.py msgids     - все строки в tr()/N_() (то, что должно быть в каталоге)
    python tools/i18n_scan.py missing    - строки без перевода в i18n_en.py
    python tools/i18n_scan.py js         - строки интерфейса (T() в app.js, текст index.html) без перевода в i18n.js

Пропускаются докстроки, сообщения журнала (log.*, print), строки с комментарием «no-i18n»
и модули, где текст не виден пользователю.
"""
import ast
import html.parser
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "wifi_beacon_scanner")
CYR = re.compile("[а-яА-ЯёЁ]")
# модули, где кириллица - только для разработчика (CLI, журнал, сборка)
SKIP_FILES = {"__main__.py", "applog.py", "i18n.py", "i18n_en.py", "winstructs.py"}
LOG_FUNCS = {"debug", "info", "warning", "error", "exception", "critical", "print", "log"}
MARKERS = {"tr", "N_"}


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def py_files():
    for root, _, files in os.walk(PKG):
        for f in sorted(files):
            if f.endswith(".py") and f not in SKIP_FILES:
                yield os.path.join(root, f)


def _call_name(node):
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def analyze(path):
    src = _read(path)
    lines = src.splitlines()
    tree = ast.parse(src)
    parent = {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node):
            parent[ch] = node
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docs.add(first.value)
    found = []          # (lineno, kind, text)
    msgids = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in MARKERS and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            msgids.append((node.lineno, node.args[0].value))
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str) and CYR.search(node.value)):
            continue
        if node in docs or "no-i18n" in lines[node.lineno - 1]:
            continue
        p, kind = parent.get(node), "plain"
        chain = []
        cur = node
        while cur in parent:
            cur = parent[cur]
            chain.append(cur)
        if isinstance(p, ast.Call) and _call_name(p) in MARKERS:
            continue
        if any(isinstance(c, ast.Call) and _call_name(c) in LOG_FUNCS for c in chain):
            continue
        if isinstance(p, ast.JoinedStr):
            kind = "fstring"
        elif not any(isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) for c in chain):
            kind = "module"
        found.append((node.lineno, kind, node.value))
    return found, msgids


STATIC = os.path.join(PKG, "web", "static")
_JS_STR = r"'((?:[^'\\\n]|\\.)*)'"


def _js_unescape(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), s)


def js_keys():
    """Строки-ключи T('...') из app.js (вызовы T() с литералом)."""
    src = _read(os.path.join(STATIC, "app.js"))
    return {_js_unescape(m) for m in re.findall(r"\bT\(\s*" + _JS_STR, src)}


class _HtmlText(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.out, self.skip = set(), 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        for k, v in attrs:
            if k in ("placeholder", "title", "aria-label", "alt") and v and CYR.search(v):
                self.out.add(v.strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1

    def handle_data(self, data):
        t = " ".join(data.split())
        if not self.skip and t and CYR.search(t):
            self.out.add(t)


def html_keys():
    """Видимый текст и подписи index.html (их переводит translateDom)."""
    p = _HtmlText()
    p.feed(_read(os.path.join(STATIC, "index.html")))
    return p.out


def js_catalog():
    """Ключи словаря I18N_EN из i18n.js."""
    src = _read(os.path.join(STATIC, "i18n.js"))
    block = src[src.index("const I18N_EN = {"):src.index("\n};", src.index("const I18N_EN = {"))]
    return {_js_unescape(m) for m in re.findall(_JS_STR + r"\s*:", block)}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    if cmd == "report":
        total = 0
        for p in py_files():
            found, _ = analyze(p)
            for ln, kind, text in found:
                total += 1
                print("%s:%d [%s] %s" % (os.path.relpath(p, ROOT), ln, kind, text[:90].replace("\n", "\\n")))
        print("всего:", total)
    elif cmd in ("msgids", "missing"):
        sys.path.insert(0, ROOT)
        from wifi_beacon_scanner.i18n_en import EN
        ids = {}
        for p in py_files():
            for ln, m in analyze(p)[1]:
                ids.setdefault(m, "%s:%d" % (os.path.relpath(p, ROOT), ln))
        for m, where in sorted(ids.items(), key=lambda x: x[1]):
            if cmd == "msgids" or m not in EN:
                print("%s\t%r" % (where, m))
    elif cmd == "js":
        cat = js_catalog()
        for k in sorted((js_keys() | html_keys()) - cat):
            print(repr(k))


if __name__ == "__main__":
    main()
