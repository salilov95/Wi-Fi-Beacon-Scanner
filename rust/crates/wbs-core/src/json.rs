//! Минимальный JSON без внешних крейтов: прочитать снапшот и эталон, записать результат.
//!
//! Зачем свой: ядро не тянет зависимостей и собирается без сети. В окне программы (крейт Tauri)
//! для обмена с интерфейсом будет serde - там он и так есть.
//!
//! Числа: если в записи есть `.`, `e` или `E` - это `Num(f64)`, иначе `Int(i64)`. Так же их различает
//! Python (`json.dumps` пишет float всегда с точкой), и сравнение с эталоном не путает 50 и 50.0.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    /// Порядок ключей сохраняется (как в Python dict).
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(n) => Some(*n as f64),
            Value::Num(x) => Some(*x),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Компактная запись JSON (без пробелов), не-ASCII - как есть.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        write_value(&mut s, self);
        s
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<f64> for Value {
    fn from(x: f64) -> Self {
        Value::Num(x)
    }
}
macro_rules! from_int {
    ($($t:ty),*) => {$(impl From<$t> for Value { fn from(n: $t) -> Self { Value::Int(n as i64) } })*};
}
from_int!(i8, i32, i64, u8, u16, u32, usize);
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        o.map(Into::into).unwrap_or(Value::Null)
    }
}
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Arr(v.into_iter().map(Into::into).collect())
    }
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Num(x) if x.is_finite() => {
            // как Python: целое значение float пишется с ".0"
            if x.fract() == 0.0 && x.abs() < 1e16 {
                let _ = write!(out, "{x:.1}");
            } else {
                let _ = write!(out, "{x}");
            }
        }
        Value::Num(_) => out.push_str("null"),
        Value::Str(s) => write_str(out, s),
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x);
            }
            out.push(']');
        }
        Value::Obj(kv) => {
            out.push('{');
            for (i, (k, x)) in kv.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, x);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------- разбор

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

/// Разбор JSON-текста. Ошибка - с позицией в байтах.
pub fn parse(text: &str) -> Result<Value, String> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(p.err("лишние данные после JSON"));
    }
    Ok(v)
}

impl Parser<'_> {
    fn err(&self, what: &str) -> String {
        format!("JSON, позиция {}: {what}", self.pos)
    }
    fn ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }
    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.s[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(self.err(&format!("ожидалось {lit}")))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        match self.s.get(self.pos) {
            None => Err(self.err("неожиданный конец")),
            Some(b'n') => self.eat("null").map(|_| Value::Null),
            Some(b't') => self.eat("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.eat("false").map(|_| Value::Bool(false)),
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => {
                self.pos += 1;
                let mut a = vec![];
                self.ws();
                if self.s.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Ok(Value::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value()?);
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::Arr(a));
                        }
                        _ => return Err(self.err("ожидалось , или ]")),
                    }
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut kv = vec![];
                self.ws();
                if self.s.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                    return Ok(Value::Obj(kv));
                }
                loop {
                    self.ws();
                    if self.s.get(self.pos) != Some(&b'"') {
                        return Err(self.err("ожидался ключ"));
                    }
                    let k = self.string()?;
                    self.ws();
                    self.eat(":")?;
                    self.ws();
                    let v = self.value()?;
                    kv.push((k, v));
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Value::Obj(kv));
                        }
                        _ => return Err(self.err("ожидалось , или }")),
                    }
                }
            }
            Some(_) => self.number(),
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        while self.pos < self.s.len() && matches!(self.s[self.pos], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
            self.pos += 1;
        }
        let t = std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| self.err("число"))?;
        if t.is_empty() {
            return Err(self.err("неожиданный символ"));
        }
        if t.contains(['.', 'e', 'E']) {
            t.parse().map(Value::Num).map_err(|_| self.err("число"))
        } else {
            t.parse().map(Value::Int).map_err(|_| self.err("целое"))
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.pos..self.pos + 4).ok_or_else(|| self.err("\\u"))?;
        let v = u32::from_str_radix(std::str::from_utf8(h).map_err(|_| self.err("\\u"))?, 16)
            .map_err(|_| self.err("\\u"))?;
        self.pos += 4;
        Ok(v)
    }
    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // открывающая кавычка
        let mut out = String::new();
        loop {
            let start = self.pos;
            while self.pos < self.s.len() && self.s[self.pos] != b'"' && self.s[self.pos] != b'\\' {
                self.pos += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| self.err("UTF-8"))?);
            match self.s.get(self.pos) {
                None => return Err(self.err("строка не закрыта")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(_) => {
                    self.pos += 1; // обратная косая
                    let c = *self.s.get(self.pos).ok_or_else(|| self.err("строка не закрыта"))?;
                    self.pos += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp) && self.s[self.pos..].starts_with(b"\\u") {
                                self.pos += 2; // суррогатная пара
                                let lo = self.hex4()?;
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff);
                            }
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(self.err("неизвестная escape-последовательность")),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let t = r#"{"a":1,"b":2.5,"c":50.0,"d":[true,false,null],"e":"кот \"\n","f":-3e2}"#;
        let v = parse(t).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Int(1)));
        assert_eq!(v.get("c"), Some(&Value::Num(50.0)));
        assert_eq!(v.get("e").and_then(Value::as_str), Some("кот \"\n"));
        assert_eq!(v.get("f").and_then(Value::as_f64), Some(-300.0));
        assert_eq!(parse(&v.to_json()).unwrap(), v);
    }

    #[test]
    fn unicode_escapes() {
        assert_eq!(parse(r#""К😀""#).unwrap(), Value::Str("К😀".into()));
    }

    #[test]
    fn errors() {
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("1 2").is_err());
    }
}
