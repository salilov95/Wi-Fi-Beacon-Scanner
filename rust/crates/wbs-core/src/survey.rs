//! Обход (site survey): план этажа, точки замеров и их результаты. Перенос `wifi_beacon_scanner/survey.py`.
//!
//! Инженер загружает план, встаёт в точку и кликает по её месту на плане. Точка создаётся «в ожидании»,
//! программа запускает скан, и результаты скана, начатого ПОСЛЕ клика, записываются в точку: RSSI всех
//! слышимых BSS плюс текущее подключение ноутбука. Координаты - доли размеров плана (0..1).
//! Проект сохраняется в один JSON вместе с картинкой плана (base64).

use crate::i18n::{py_float, tr, trf, Arg};
use crate::json::Value;
use crate::model::Bss;

pub const FORMAT: &str = "wifi_beacon_scanner.survey";
pub const VERSION: i64 = 1;
pub const MAX_PLAN_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_POINTS: usize = 2000;

// ---------------------------------------------------------------- base64 (строгий, как b64decode(validate=True))

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn b64decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (ci, chunk) in b.chunks(4).enumerate() {
        let last = ci == b.len() / 4 - 1;
        let mut n = 0u32;
        let mut valid = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if last && i >= 4 - pad => 0,
                _ => return None,
            };
            if c != b'=' {
                valid += 1;
            }
            n = n << 6 | v as u32;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..valid - 1]);
    }
    Some(out)
}

// ---------------------------------------------------------------- точки

/// Подключение ноутбука в момент замера.
#[derive(Debug, Clone, PartialEq)]
pub struct PointConn {
    pub ssid: String,
    pub bssid: String,
    pub rssi: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub id: i64,
    pub x: f64,
    pub y: f64,
    pub t: f64,
    /// pending | done | failed
    pub status: String,
    /// BSSID -> (SSID, диапазон, канал, RSSI), в порядке скана
    pub results: Vec<(String, (String, String, i64, i64))>,
    pub conn: Option<PointConn>,
    pub scan_t: Option<f64>,
    pub error: Option<String>,
}

impl Point {
    pub fn to_value(&self) -> Value {
        let mut kv: Vec<(String, Value)> = vec![
            ("id".into(), self.id.into()),
            ("x".into(), self.x.into()),
            ("y".into(), self.y.into()),
            ("t".into(), self.t.into()),
            ("status".into(), self.status.as_str().into()),
            (
                "results".into(),
                Value::Obj(
                    self.results
                        .iter()
                        .map(|(k, (s, b, c, r))| {
                            (
                                k.clone(),
                                Value::Arr(vec![s.as_str().into(), b.as_str().into(), (*c).into(), (*r).into()]),
                            )
                        })
                        .collect(),
                ),
            ),
            (
                "conn".into(),
                self.conn.as_ref().map_or(Value::Null, |c| {
                    Value::Obj(vec![
                        ("ssid".into(), c.ssid.as_str().into()),
                        ("bssid".into(), c.bssid.as_str().into()),
                        ("rssi".into(), c.rssi.into()),
                    ])
                }),
            ),
        ];
        // поля, которые 1.x добавляет к точке после скана
        if let Some(t) = self.scan_t {
            kv.push(("scan_t".into(), t.into()));
        }
        if let Some(e) = &self.error {
            kv.push(("error".into(), e.as_str().into()));
        }
        Value::Obj(kv)
    }
}

/// Число 0..1 (не bool), иначе понятная ошибка.
fn num01(v: Option<&Value>, name: &str) -> Result<f64, String> {
    let x = match v {
        Some(Value::Int(n)) => *n as f64,
        Some(Value::Num(x)) => *x,
        _ => f64::NAN,
    };
    if !x.is_finite() || !(0.0..=1.0).contains(&x) {
        return Err(trf("%s должен быть числом от 0 до 1", &[Arg::S(name.into())]));
    }
    Ok(x)
}

/// `str(v)` в Python для значений JSON.
fn py_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(n) => n.to_string(),
        Value::Num(x) => py_float(*x),
        Value::Null => "None".into(),
        Value::Bool(b) => (if *b { "True" } else { "False" }).into(),
        other => other.to_json(),
    }
}

fn cut(s: String, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Ложное значение в Python (`x or default`).
fn falsy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::Int(n)) => *n == 0,
        Some(Value::Num(x)) => *x == 0.0,
        Some(Value::Str(s)) => s.is_empty(),
        Some(Value::Arr(a)) => a.is_empty(),
        Some(Value::Obj(o)) => o.is_empty(),
        _ => false,
    }
}

/// Число из JSON как `int()` в Python (bool - это 0/1).
fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(n) => Some(*n),
        Value::Num(x) if x.is_finite() => Some(x.trunc() as i64),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Survey {
    pub name: String,
    pub plan_mime: String,
    pub plan: Vec<u8>,
    pub points: Vec<Point>,
    /// Меняется при любом изменении: окно по нему понимает, что пора перечитать.
    pub rev: i64,
    /// Меняется только при смене картинки.
    pub plan_rev: i64,
    next_id: i64,
}

impl Survey {
    /// Имя по умолчанию - на языке программы в момент создания (как в 1.x).
    pub fn new() -> Survey {
        Survey {
            name: tr("Обход"),
            plan_mime: String::new(),
            plan: vec![],
            points: vec![],
            rev: 0,
            plan_rev: 0,
            next_id: 1,
        }
    }

    pub fn has_plan(&self) -> bool {
        !self.plan.is_empty()
    }

    pub fn set_plan(&mut self, mime: &str, data_b64: &str, name: Option<&Value>) -> Result<(), String> {
        let data = b64decode(data_b64).ok_or_else(|| tr("картинка плана повреждена (base64)"))?;
        let magic: &[u8] = match mime {
            "image/png" => b"\x89PNG\r\n\x1a\n",
            "image/jpeg" => b"\xff\xd8\xff",
            _ => return Err(tr("план должен быть PNG или JPEG")),
        };
        if !data.starts_with(magic) {
            return Err(trf("файл не похож на %s", &[Arg::S(mime.into())]));
        }
        if data.len() > MAX_PLAN_BYTES {
            return Err(trf(
                "план больше %d МБ, уменьши картинку",
                &[Arg::I((MAX_PLAN_BYTES / (1024 * 1024)) as i64)],
            ));
        }
        self.plan_mime = mime.into();
        self.plan = data;
        self.points.clear();
        self.next_id = 1;
        // `if name:` - пустая строка, null, 0, false и пустые списки имя не меняют
        if let (false, Some(v)) = (falsy(name), name) {
            self.name = cut(py_str(v), 120);
        }
        self.plan_rev += 1;
        self.rev += 1;
        Ok(())
    }

    pub fn has_pending(&self) -> bool {
        self.points.iter().any(|p| p.status == "pending")
    }

    pub fn add_point(&mut self, x: Option<&Value>, y: Option<&Value>, t: f64) -> Result<&Point, String> {
        if !self.has_plan() {
            return Err(tr("сначала загрузи план этажа"));
        }
        if self.has_pending() {
            // иначе несколько точек получат один и тот же скан, сделанный уже из новой позиции
            return Err(tr("дождись окончания замера предыдущей точки (около 5 секунд)"));
        }
        if self.points.len() >= MAX_POINTS {
            return Err(trf("в проекте уже %d точек", &[Arg::I(MAX_POINTS as i64)]));
        }
        let p = Point {
            id: self.next_id,
            x: num01(x, "x")?,
            y: num01(y, "y")?,
            t,
            status: "pending".into(),
            results: vec![],
            conn: None,
            scan_t: None,
            error: None,
        };
        self.next_id += 1;
        self.points.push(p);
        self.rev += 1;
        Ok(self.points.last().expect("точка"))
    }

    pub fn delete(&mut self, id: Option<&Value>) -> bool {
        let n = self.points.len();
        // в 1.x сравнение p["id"] != pid: 2, 2.0 и True == 1 совпадают с числом, строка - нет
        let want = match id {
            Some(Value::Int(n)) => Some(*n as f64),
            Some(Value::Num(x)) => Some(*x),
            Some(Value::Bool(b)) => Some(*b as i64 as f64),
            _ => None,
        };
        self.points.retain(|p| Some(p.id as f64) != want);
        if self.points.len() != n {
            self.rev += 1;
            return true;
        }
        false
    }

    pub fn clear_points(&mut self) {
        self.points.clear();
        self.next_id = 1;
        self.rev += 1;
    }

    pub fn pending_after(&self, t: f64) -> bool {
        self.points.iter().any(|p| p.status == "pending" && p.t > t)
    }

    /// Результаты скана - точкам, созданным до его начала.
    pub fn fill(&mut self, scan_started: f64, bss: &[Bss], conn: Option<PointConn>) -> usize {
        let mut results: Vec<(String, (String, String, i64, i64))> = vec![];
        for b in bss {
            let v = (
                b.ssid_display(),
                b.band().to_string(),
                b.channel() as i64,
                b.rssi as i64,
            );
            match results.iter_mut().find(|(k, _)| *k == b.bssid) {
                Some(slot) => slot.1 = v,
                None => results.push((b.bssid.clone(), v)),
            }
        }
        let mut n = 0;
        for p in &mut self.points {
            if p.status == "pending" && p.t <= scan_started {
                p.results = results.clone();
                p.conn = conn.clone();
                p.status = "done".into();
                p.scan_t = Some(scan_started);
                n += 1;
            }
        }
        if n > 0 {
            self.rev += 1;
        }
        n
    }

    pub fn fail_pending(&mut self, scan_started: f64, error: &str) {
        let mut changed = false;
        for p in &mut self.points {
            if p.status == "pending" && p.t <= scan_started {
                p.status = "failed".into();
                p.error = Some(cut(error.to_string(), 200));
                changed = true;
            }
        }
        if changed {
            self.rev += 1;
        }
    }

    pub fn summary(&self) -> Value {
        Value::Obj(vec![
            ("has_plan".into(), self.has_plan().into()),
            ("name".into(), self.name.as_str().into()),
            ("rev".into(), self.rev.into()),
            ("plan_rev".into(), self.plan_rev.into()),
            ("points".into(), self.points.len().into()),
            (
                "pending".into(),
                self.points.iter().filter(|p| p.status == "pending").count().into(),
            ),
        ])
    }

    pub fn points_value(&self) -> Value {
        Value::Obj(vec![
            ("rev".into(), self.rev.into()),
            ("name".into(), self.name.as_str().into()),
            (
                "points".into(),
                Value::Arr(self.points.iter().map(Point::to_value).collect()),
            ),
        ])
    }

    pub fn to_project(&self) -> Value {
        Value::Obj(vec![
            ("format".into(), FORMAT.into()),
            ("version".into(), Value::Int(VERSION)),
            ("name".into(), self.name.as_str().into()),
            (
                "plan".into(),
                if self.plan.is_empty() {
                    Value::Null
                } else {
                    Value::Obj(vec![
                        ("mime".into(), self.plan_mime.as_str().into()),
                        ("data".into(), b64encode(&self.plan).into()),
                    ])
                },
            ),
            (
                "points".into(),
                Value::Arr(self.points.iter().map(Point::to_value).collect()),
            ),
        ])
    }

    pub fn load_project(&mut self, d: &Value) -> Result<(), String> {
        if !matches!(d, Value::Obj(_)) || d.get("format").and_then(Value::as_str) != Some(FORMAT) {
            return Err(tr("это не файл проекта обхода"));
        }
        if d.get("version") != Some(&Value::Int(VERSION)) {
            let v = d.get("version").cloned().unwrap_or(Value::Null);
            let shown = match &v {
                Value::Str(s) => format!("'{s}'"),
                other => py_str(other),
            };
            return Err(tr("неподдерживаемая версия проекта: %r").replacen("%r", &shown, 1));
        }
        let Some(plan @ Value::Obj(_)) = d.get("plan") else {
            return Err(tr("в проекте нет плана этажа"));
        };
        let mut new = Survey::new();
        let mime = plan.get("mime").map_or(String::new(), py_str);
        let data = plan.get("data").map_or(String::new(), py_str);
        new.set_plan(&mime, &data, d.get("name"))?;
        let pts = match d.get("points") {
            v if falsy(v) => vec![],
            Some(Value::Arr(a)) if a.len() <= MAX_POINTS => a.clone(),
            _ => return Err(tr("список точек повреждён")),
        };
        for raw in &pts {
            if !matches!(raw, Value::Obj(_)) {
                return Err(tr("точка повреждена"));
            }
            let t = raw.get("t").and_then(Value::as_f64).unwrap_or(0.0);
            new.add_point(raw.get("x"), raw.get("y"), t)?;
            let mut clean = vec![];
            match raw.get("results") {
                v if falsy(v) => {}
                Some(Value::Obj(res)) => {
                    for (k, v) in res.iter().take(2000) {
                        let Value::Arr(a) = v else { continue };
                        if k.chars().count() > 32 || a.len() != 4 || !matches!(a[3], Value::Int(_) | Value::Num(_)) {
                            continue;
                        }
                        clean.push((
                            k.clone(),
                            (
                                cut(py_str(&a[0]), 64),
                                cut(py_str(&a[1]), 4),
                                if matches!(a[2], Value::Int(_) | Value::Num(_) | Value::Bool(_)) {
                                    py_int(&a[2]).unwrap_or(0)
                                } else {
                                    0
                                },
                                py_int(&a[3]).unwrap_or(0),
                            ),
                        ));
                    }
                }
                _ => return Err(tr("результаты точки повреждены")),
            }
            let p = new.points.last_mut().expect("точка");
            p.results = clean;
            p.conn = match raw.get("conn") {
                Some(c @ Value::Obj(_)) => Some(PointConn {
                    ssid: cut(c.get("ssid").map_or(String::new(), py_str), 64),
                    bssid: cut(c.get("bssid").map_or(String::new(), py_str), 32),
                    rssi: c.get("rssi").and_then(|r| match r {
                        Value::Int(_) | Value::Num(_) | Value::Bool(_) => py_int(r),
                        _ => None,
                    }),
                }),
                _ => None,
            };
            p.status = if raw.get("status").and_then(Value::as_str) == Some("done") {
                "done".into()
            } else {
                "failed".into()
            };
        }
        let (rev, plan_rev) = (self.rev, self.plan_rev);
        *self = new;
        // счётчики только растут: окно сравнивает их с прошлыми
        self.rev = rev + 1;
        self.plan_rev = plan_rev + 1;
        Ok(())
    }
}

impl Default for Survey {
    fn default() -> Self {
        Survey::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x89PNG\r\n\x1a\n\x00\xff",
        ] {
            assert_eq!(b64decode(&b64encode(data)).unwrap(), data);
        }
        assert_eq!(b64encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64encode(b"fo"), "Zm8=");
        assert!(b64decode("Zm8").is_none());
        assert!(b64decode("Zm 8=").is_none());
        assert!(b64decode("Z=8=").is_none());
    }
}
