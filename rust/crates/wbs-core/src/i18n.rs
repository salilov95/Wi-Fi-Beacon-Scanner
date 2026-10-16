//! Язык интерфейса и отчётов: русский (исходный) и английский. Перенос `wifi_beacon_scanner/i18n.py`.
//!
//! Ключ перевода - сама русская строка, как в Python: `tr("Открытая сеть")`. Каталог общий с Python-версией:
//! `contract/i18n/en.json` (его выгружает `tools/export_i18n.py`), он вшивается в программу при сборке.
//! Если перевода нет, показывается русский текст.
//!
//! Подстановки - в стиле Python `%`: сначала перевод шаблона, потом `pyfmt(шаблон, аргументы)`.
//! Язык - на поток (`thread_local`): так тесты на разных языках не мешают друг другу.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::json::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }
    /// Как `set_lang` в Python: всё, кроме "en", - русский.
    pub fn parse(s: &str) -> Lang {
        if s == "en" {
            Lang::En
        } else {
            Lang::Ru
        }
    }
}

thread_local! {
    static LANG: Cell<Lang> = const { Cell::new(Lang::Ru) };
}

pub fn set_lang(lang: Lang) {
    LANG.with(|l| l.set(lang));
}

pub fn get_lang() -> Lang {
    LANG.with(|l| l.get())
}

/// Выполнить `f` на языке `lang` и вернуть прежний язык потока.
pub fn with_lang<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let prev = get_lang();
    set_lang(lang);
    let out = f();
    set_lang(prev);
    out
}

const EN_JSON: &str = include_str!("../../../../contract/i18n/en.json");

fn catalog() -> &'static HashMap<String, String> {
    static CAT: OnceLock<HashMap<String, String>> = OnceLock::new();
    CAT.get_or_init(|| match json::parse(EN_JSON) {
        Ok(Value::Obj(kv)) => kv
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect(),
        _ => HashMap::new(),
    })
}

/// Перевод строки на текущий язык потока (русский - как есть).
pub fn tr(s: &str) -> String {
    if get_lang() == Lang::Ru || s.is_empty() {
        return s.to_string();
    }
    catalog().get(s).cloned().unwrap_or_else(|| s.to_string())
}

/// Аргумент подстановки `%`.
#[derive(Debug, Clone)]
pub enum Arg {
    S(String),
    I(i64),
    F(f64),
}

impl From<&str> for Arg {
    fn from(s: &str) -> Self {
        Arg::S(s.to_string())
    }
}
impl From<String> for Arg {
    fn from(s: String) -> Self {
        Arg::S(s)
    }
}
impl From<&String> for Arg {
    fn from(s: &String) -> Self {
        Arg::S(s.clone())
    }
}
impl From<f64> for Arg {
    fn from(x: f64) -> Self {
        Arg::F(x)
    }
}
macro_rules! arg_int {
    ($($t:ty),*) => {$(impl From<$t> for Arg { fn from(n: $t) -> Self { Arg::I(n as i64) } })*};
}
arg_int!(i8, i32, i64, u8, u16, u32, usize);

/// `str(x)` для float в Python: кратчайшая запись, целое значение - с ".0".
pub fn py_float(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e16 {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

/// `%g` в Python: 6 значащих цифр, без лишних нулей; экспонента при порядке < -4 или >= 6.
pub fn py_g(x: f64) -> String {
    if x == 0.0 || !x.is_finite() {
        return if x == 0.0 { "0".into() } else { format!("{x}") };
    }
    // порядок после округления до 6 значащих цифр
    let e = format!("{x:.5e}");
    let exp: i32 = e.split_once('e').and_then(|(_, p)| p.parse().ok()).unwrap_or(0);
    let trim = |s: String| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s
        }
    };
    if !(-4..6).contains(&exp) {
        let (m, _) = e.split_once('e').unwrap_or((&e, ""));
        let sign = if exp < 0 { '-' } else { '+' };
        return format!("{}e{sign}{:02}", trim(m.to_string()), exp.abs());
    }
    trim(format!("{x:.*}", (5 - exp) as usize))
}

/// Подстановка в стиле `шаблон % (аргументы)` Python: %s, %d, %g, %r, %.Nf, %X/%x с шириной и нулями, %%.
pub fn pyfmt(template: &str, args: &[Arg]) -> String {
    let mut out = String::new();
    let mut it = args.iter();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // флаги, ширина, точность
        let mut spec = String::new();
        while let Some(&n) = chars.peek() {
            if n.is_ascii_digit() || n == '.' || n == '-' || n == '0' {
                spec.push(n);
                chars.next();
            } else {
                break;
            }
        }
        let conv = chars.next().unwrap_or('%');
        if conv == '%' {
            out.push('%');
            continue;
        }
        let arg = it.next().cloned().unwrap_or(Arg::S(String::new()));
        let zero = spec.starts_with('0');
        let (width, prec) = match spec.split_once('.') {
            Some((w, p)) => (w.trim_start_matches('0').parse::<usize>().ok(), p.parse::<usize>().ok()),
            None => (spec.trim_start_matches('0').parse::<usize>().ok(), None),
        };
        let text = match (conv, &arg) {
            ('s' | 'r', Arg::S(s)) if conv == 'r' => format!("'{s}'"),
            ('s' | 'r', Arg::S(s)) => s.clone(),
            ('s' | 'r' | 'd', Arg::I(n)) => n.to_string(),
            ('s' | 'r', Arg::F(x)) => py_float(*x),
            ('d', Arg::F(x)) => (x.trunc() as i64).to_string(),
            ('f', a) => {
                let x = match a {
                    Arg::F(x) => *x,
                    Arg::I(n) => *n as f64,
                    Arg::S(_) => 0.0,
                };
                format!("{x:.*}", prec.unwrap_or(6))
            }
            ('g', Arg::F(x)) => py_g(*x),
            ('g', Arg::I(n)) => n.to_string(),
            ('X', Arg::I(n)) => format!("{n:X}"),
            ('x', Arg::I(n)) => format!("{n:x}"),
            (_, Arg::S(s)) => s.clone(),
            (_, Arg::I(n)) => n.to_string(),
            (_, Arg::F(x)) => py_float(*x),
        };
        match width {
            Some(w) if text.chars().count() < w => {
                let pad = w - text.chars().count();
                if zero {
                    out.push_str(&"0".repeat(pad));
                } else {
                    out.push_str(&" ".repeat(pad));
                }
                out.push_str(&text);
            }
            _ => out.push_str(&text),
        }
    }
    out
}

/// `tr(шаблон) % (аргументы)`.
pub fn trf(template: &str, args: &[Arg]) -> String {
    pyfmt(&tr(template), args)
}

/// Список в виде Python: `[100, 102]`.
pub fn py_list<T: std::fmt::Display>(items: &[T]) -> String {
    format!(
        "[{}]",
        items.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_like_python() {
        assert_eq!(pyfmt("занято %.0f%% эфира", &[74.5.into()]), "занято 74% эфира");
        assert_eq!(pyfmt("занято %.0f%% эфира", &[75.5.into()]), "занято 76% эфира");
        assert_eq!(pyfmt("%s ГГц, канал %d", &["5".into(), 36.into()]), "5 ГГц, канал 36");
        assert_eq!(pyfmt("%s%%", &[74.5.into()]), "74.5%");
        assert_eq!(pyfmt("%s%%", &[100.0.into()]), "100.0%");
        assert_eq!(pyfmt("0x%04X", &[0x1a.into()]), "0x001A");
        assert_eq!(pyfmt("%g", &[5.5.into()]), "5.5");
        assert_eq!(pyfmt("%g", &[54.0.into()]), "54");
        assert_eq!(py_list(&[100, 102]), "[100, 102]");
    }

    #[test]
    fn translation() {
        with_lang(Lang::En, || {
            assert_eq!(tr("обязательна"), "required");
            assert_eq!(tr("нет такой строки"), "нет такой строки");
        });
        assert_eq!(get_lang(), Lang::Ru);
        assert_eq!(tr("обязательна"), "обязательна");
        assert!(catalog().len() > 400);
    }
}

#[cfg(test)]
mod g_tests {
    use super::py_g;

    #[test]
    fn g_like_python() {
        for (x, want) in [
            (1201.0, "1201"),
            (2401.9, "2401.9"),
            (12345.67, "12345.7"),
            (0.8, "0.8"),
            (5.5, "5.5"),
            (1234567.0, "1.23457e+06"),
            (0.0001, "0.0001"),
            (0.00001234, "1.234e-05"),
            (-3.0, "-3"),
            (999999.5, "1e+06"),
            (60.0, "60"),
        ] {
            assert_eq!(py_g(x), want, "{x}");
        }
    }
}
