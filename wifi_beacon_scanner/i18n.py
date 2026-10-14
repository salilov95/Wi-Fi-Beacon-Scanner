"""Язык интерфейса и отчётов: русский (исходный) и английский.

Ключ перевода - сама русская строка: в коде пишется `tr("Открытая сеть")`, в `i18n_en.py` лежит её перевод.
Если перевода нет, показывается русский текст. Строки с подстановкой переводятся до форматирования:
`tr("слабый сигнал %d дБм") % rssi` - в переводе те же `%d`/`%s` в том же порядке.

Строки в таблицах уровня модуля помечаются `N_()` (ничего не делает, нужна только для сборщика строк)
и переводятся там, где используются, - иначе перевод застыл бы на языке момента импорта.

Язык один на программу (у неё один пользователь): `set_lang()` при запуске из настроек или языка Windows
и при переключении в «Вид» → «Язык».
"""
from __future__ import annotations

import locale
import sys
from typing import Dict, Optional

LANGS = ("ru", "en")
_lang = "ru"
_en: Optional[Dict[str, str]] = None


def N_(s: str) -> str:
    """Пометка «строка для перевода» без перевода (таблицы уровня модуля)."""
    return s


def set_lang(lang: str) -> str:
    global _lang
    _lang = lang if lang in LANGS else "ru"
    return _lang


def get_lang() -> str:
    return _lang


def _catalog() -> Dict[str, str]:
    global _en
    if _en is None:
        from .i18n_en import EN
        _en = EN
    return _en


def tr(s: str) -> str:
    if _lang == "ru" or not s:
        return s
    return _catalog().get(s, s)


def system_lang() -> str:
    """Язык по умолчанию: русский, если интерфейс Windows (или локаль) русский, иначе английский."""
    try:
        if sys.platform == "win32":
            import ctypes
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return "ru" if (langid & 0x3FF) == 0x19 else "en"        # 0x19 - LANG_RUSSIAN
        code = (locale.getlocale()[0] or "") if hasattr(locale, "getlocale") else ""
        return "ru" if code.lower().startswith("ru") else "en"
    except Exception:  # noqa: BLE001 - язык не главное, чтобы из-за него не упасть
        return "ru"
