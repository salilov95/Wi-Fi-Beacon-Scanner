//! Журнал собственного подключения ноутбука: из замеров раз в секунду - события. Перенос `wifi_beacon_scanner/conn.py`.
//!
//! Источник замеров - опрос текущего подключения (WlanQueryInterface) и уведомления WLAN API с кодами причин
//! (модуль `win_conn`). Этот модуль от Windows не зависит: получает готовые замеры и уведомления и строит события.
//!
//! События: `connected`, `disconnected` (причина подтягивается из уведомления, если оно рядом), `roam`,
//! `ssid_change`, `pingpong` (A→B, затем быстро B→A), `sticky` (держится за слабую BSS, хотя та же сеть рядом
//! заметно сильнее), `attempt_fail`, `disconnect_reason` (Windows сообщила об отключении, а опрос его не видел).

use std::collections::{HashMap, VecDeque};

use crate::i18n::{tr, trf, Arg};
use crate::ie::round1;
use crate::json::Value;
use crate::session::SessionTracker;

pub fn state_ru(state: &str) -> Option<&'static str> {
    Some(match state {
        "connected" => "подключён",
        "disconnected" => "отключён",
        "disconnecting" => "отключается",
        "associating" => "ассоциация",
        "authenticating" => "аутентификация",
        "discovering" => "поиск сети",
        "not_ready" => "адаптер не готов",
        "ad_hoc" => "ad hoc",
        "unknown" => "неизвестно",
        _ => return None,
    })
}

/// Замер подключения (раз в секунду).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConnSample {
    pub t: f64,
    pub state: String,
    pub ssid: String,
    pub bssid: String,
    pub rssi: Option<i32>,
    pub quality: Option<i32>,
    pub channel: Option<i32>,
    pub rx_mbps: Option<f64>,
    pub tx_mbps: Option<f64>,
    pub auth: String,
    pub cipher: String,
    pub onex: bool,
    pub profile: String,
}

impl ConnSample {
    pub fn up(&self) -> bool {
        self.state == "connected" && !self.bssid.is_empty()
    }
    pub fn down(t: f64, state: &str) -> ConnSample {
        ConnSample {
            t,
            state: state.into(),
            ..ConnSample::default()
        }
    }
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("t".into(), self.t.into()),
            ("state".into(), self.state.as_str().into()),
            ("ssid".into(), self.ssid.as_str().into()),
            ("bssid".into(), self.bssid.as_str().into()),
            ("rssi".into(), self.rssi.into()),
            ("quality".into(), self.quality.into()),
            ("channel".into(), self.channel.into()),
            ("rx_mbps".into(), self.rx_mbps.into()),
            ("tx_mbps".into(), self.tx_mbps.into()),
            ("auth".into(), self.auth.as_str().into()),
            ("cipher".into(), self.cipher.as_str().into()),
            ("onex".into(), self.onex.into()),
            ("profile".into(), self.profile.as_str().into()),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConnEvent {
    pub t: f64,
    pub kind: String,
    /// info | warning | critical
    pub severity: String,
    pub text: String,
    pub ssid: String,
    pub bssid_from: String,
    pub bssid_to: String,
    pub rssi_from: Option<i32>,
    pub rssi_to: Option<i32>,
    /// Время на прошлой BSS / длительность обрыва, с.
    pub duration_s: Option<f64>,
    pub reason_code: Option<i64>,
    pub reason: String,
}

impl ConnEvent {
    fn new(t: f64, kind: &str, severity: &str, text: String) -> ConnEvent {
        ConnEvent {
            t,
            kind: kind.into(),
            severity: severity.into(),
            text,
            ..ConnEvent::default()
        }
    }
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("t".into(), self.t.into()),
            ("kind".into(), self.kind.as_str().into()),
            ("severity".into(), self.severity.as_str().into()),
            ("text".into(), self.text.as_str().into()),
            ("ssid".into(), self.ssid.as_str().into()),
            ("bssid_from".into(), self.bssid_from.as_str().into()),
            ("bssid_to".into(), self.bssid_to.as_str().into()),
            ("rssi_from".into(), self.rssi_from.into()),
            ("rssi_to".into(), self.rssi_to.into()),
            ("duration_s".into(), self.duration_s.into()),
            ("reason_code".into(), self.reason_code.into()),
            ("reason".into(), self.reason.as_str().into()),
        ])
    }
}

/// BSS из скана для проверки «залипания».
pub struct ScanSeen<'a> {
    pub bssid: &'a str,
    pub ssid: &'a str,
    pub rssi: i32,
}

#[derive(Debug, Clone)]
pub struct ConnTracker {
    pub sticky_rssi: i32,
    pub sticky_delta: i32,
    pub sticky_hold_s: f64,
    pub pingpong_window_s: f64,
    pub reason_attach_s: f64,
    max_samples: usize,
    max_events: usize,
    pub samples: VecDeque<ConnSample>,
    pub events: VecDeque<ConnEvent>,
    /// Сырые уведомления для отладки: (t, source, code, name).
    pub raw: VecDeque<(f64, u32, u32, String)>,
    pub status: String,
    last: Option<ConnSample>,
    bss_since: Option<f64>,
    down_since: Option<f64>,
    last_roam: Option<ConnEvent>,
    sticky_since: Option<f64>,
    sticky_reported_for: String,
    /// bssid -> секунд на ней (в порядке появления, как dict в Python)
    dwell: Vec<(String, f64)>,
    dwell_idx: HashMap<String, usize>,
    pub sessions: SessionTracker,
}

impl Default for ConnTracker {
    fn default() -> Self {
        ConnTracker {
            sticky_rssi: -75,
            sticky_delta: 8,
            sticky_hold_s: 10.0,
            pingpong_window_s: 30.0,
            reason_attach_s: 10.0,
            max_samples: 7200,
            max_events: 2000,
            samples: VecDeque::new(),
            events: VecDeque::new(),
            raw: VecDeque::new(),
            status: tr("не запущен"),
            last: None,
            bss_since: None,
            down_since: None,
            last_roam: None,
            sticky_since: None,
            sticky_reported_for: String::new(),
            dwell: vec![],
            dwell_idx: HashMap::new(),
            sessions: SessionTracker::new(),
        }
    }
}

fn since(t0: Option<f64>, t: f64) -> Option<f64> {
    t0.map(|t0| round1((t - t0).max(0.0)))
}

impl ConnTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn push_event(&mut self, ev: ConnEvent) {
        if self.events.len() == self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    // ---------- замеры ----------
    pub fn add_sample(&mut self, s: ConnSample) -> Vec<ConnEvent> {
        let mut out: Vec<ConnEvent> = vec![];
        let prev = self.last.take();
        if let Some(p) = prev.as_ref().filter(|p| p.up()) {
            let add = (s.t - p.t).max(0.0);
            match self.dwell_idx.get(&p.bssid) {
                Some(&i) => self.dwell[i].1 += add,
                None => {
                    self.dwell_idx.insert(p.bssid.clone(), self.dwell.len());
                    self.dwell.push((p.bssid.clone(), add));
                }
            }
        }
        let name = |s: &ConnSample| {
            if s.ssid.is_empty() {
                "?".to_string()
            } else {
                s.ssid.clone()
            }
        };
        match &prev {
            None => {
                if s.up() {
                    self.bss_since = Some(s.t);
                    let mut ev = ConnEvent::new(s.t, "connected", "info", trf("Подключён к %s", &[Arg::S(name(&s))]));
                    ev.ssid = s.ssid.clone();
                    ev.bssid_to = s.bssid.clone();
                    ev.rssi_to = s.rssi;
                    out.push(ev);
                } else {
                    self.down_since = Some(s.t);
                }
            }
            Some(p) if p.up() && s.up() => {
                if s.ssid != p.ssid {
                    let mut ev = ConnEvent::new(
                        s.t,
                        "ssid_change",
                        "warning",
                        trf(
                            "Переключился на другую сеть: %s → %s",
                            &[Arg::S(p.ssid.clone()), Arg::S(s.ssid.clone())],
                        ),
                    );
                    ev.ssid = s.ssid.clone();
                    ev.bssid_from = p.bssid.clone();
                    ev.bssid_to = s.bssid.clone();
                    ev.rssi_from = p.rssi;
                    ev.rssi_to = s.rssi;
                    ev.duration_s = since(self.bss_since, s.t);
                    out.push(ev);
                    self.bss_since = Some(s.t);
                    self.last_roam = None;
                } else if s.bssid != p.bssid {
                    let mut ev = ConnEvent::new(s.t, "roam", "info", tr("Роуминг"));
                    ev.ssid = s.ssid.clone();
                    ev.bssid_from = p.bssid.clone();
                    ev.bssid_to = s.bssid.clone();
                    ev.rssi_from = p.rssi;
                    ev.rssi_to = s.rssi;
                    ev.duration_s = since(self.bss_since, s.t);
                    out.push(ev.clone());
                    if let Some(lr) = &self.last_roam {
                        if lr.bssid_from == s.bssid && lr.bssid_to == p.bssid && s.t - lr.t <= self.pingpong_window_s {
                            let d = s.t - lr.t;
                            let mut pp = ConnEvent::new(
                                s.t,
                                "pingpong",
                                "warning",
                                trf("Пинг-понг: вернулся на прежнюю BSS через %.0f с", &[Arg::F(d)]),
                            );
                            pp.ssid = s.ssid.clone();
                            pp.bssid_from = p.bssid.clone();
                            pp.bssid_to = s.bssid.clone();
                            pp.rssi_from = p.rssi;
                            pp.rssi_to = s.rssi;
                            pp.duration_s = Some(d);
                            out.push(pp);
                        }
                    }
                    self.last_roam = Some(ev);
                    self.bss_since = Some(s.t);
                    self.sticky_since = None;
                }
            }
            Some(p) if p.up() => {
                let st = match state_ru(&s.state) {
                    Some(r) => tr(r),
                    None => tr(&s.state),
                };
                let mut ev = ConnEvent::new(
                    s.t,
                    "disconnected",
                    "critical",
                    trf("Связь пропала (%s)", &[Arg::S(st)]),
                );
                ev.ssid = p.ssid.clone();
                ev.bssid_from = p.bssid.clone();
                ev.rssi_from = p.rssi;
                ev.duration_s = since(self.bss_since, s.t);
                self.down_since = Some(s.t);
                self.sticky_since = None;
                self.attach_recent_reason(&mut ev);
                out.push(ev);
            }
            Some(_) if s.up() => {
                let gap = since(self.down_since, s.t);
                let mut text = trf("Подключён к %s", &[Arg::S(name(&s))]);
                if let Some(g) = gap.filter(|&g| g != 0.0) {
                    text += &trf(" после %.0f с без связи", &[Arg::F(g)]);
                }
                let mut ev = ConnEvent::new(s.t, "connected", "info", text);
                ev.ssid = s.ssid.clone();
                ev.bssid_to = s.bssid.clone();
                ev.rssi_to = s.rssi;
                ev.duration_s = gap;
                out.push(ev);
                self.bss_since = Some(s.t);
                self.down_since = None;
            }
            Some(_) => {}
        }
        if self.samples.len() == self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(s.clone());
        self.last = Some(s);
        for ev in &out {
            self.push_event(ev.clone());
        }
        out
    }

    // ---------- уведомления с причинами ----------

    /// `kind`: "disconnected" | "attempt_fail". Причину обрыва приклеиваем к ближайшему «Связь пропала»,
    /// если оно рядом по времени; иначе это отдельное событие.
    pub fn add_reason(&mut self, t: f64, kind: &str, reason_code: Option<i64>, reason: &str, ssid: &str, bssid: &str) {
        let ev = if kind == "disconnected" {
            for ev in self.events.iter_mut().rev() {
                if t - ev.t > self.reason_attach_s {
                    break;
                }
                if ev.kind == "disconnected" && ev.reason.is_empty() && (ev.t - t).abs() <= self.reason_attach_s {
                    ev.reason_code = reason_code;
                    ev.reason = reason.into();
                    return;
                }
            }
            let mut ev = ConnEvent::new(t, "disconnect_reason", "warning", tr("Windows сообщила об отключении"));
            ev.ssid = ssid.into();
            ev.bssid_from = bssid.into();
            ev.reason_code = reason_code;
            ev.reason = reason.into();
            ev
        } else {
            let who = if ssid.is_empty() {
                tr("сети")
            } else {
                ssid.to_string()
            };
            let mut ev = ConnEvent::new(
                t,
                "attempt_fail",
                "critical",
                trf("Не удалось подключиться к %s", &[Arg::S(who)]),
            );
            ev.ssid = ssid.into();
            ev.bssid_to = bssid.into();
            ev.reason_code = reason_code;
            ev.reason = reason.into();
            ev
        };
        self.push_event(ev);
    }

    /// Уведомление могло прийти раньше, чем опрос заметил обрыв.
    fn attach_recent_reason(&mut self, ev: &mut ConnEvent) {
        let mut hit = None;
        for (i, other) in self.events.iter().enumerate().rev() {
            if ev.t - other.t > self.reason_attach_s {
                break;
            }
            if other.kind == "disconnect_reason" && !other.reason.is_empty() {
                hit = Some(i);
                break;
            }
        }
        if let Some(i) = hit {
            let other = self.events.remove(i).expect("индекс события");
            ev.reason_code = other.reason_code;
            ev.reason = other.reason;
        }
    }

    pub fn add_raw(&mut self, t: f64, source: u32, code: u32, name: &str) {
        if self.raw.len() == 300 {
            self.raw.pop_front();
        }
        self.raw.push_back((round1(t), source, code, name.into()));
    }

    // ---------- «залипание» по данным скана ----------

    /// Подключённая BSS слабее порога, а другая BSS той же сети слышна сильнее на sticky_delta дБ
    /// дольше sticky_hold_s - событие.
    pub fn check_scan(&mut self, t: f64, bss: &[ScanSeen]) -> Option<ConnEvent> {
        let cur = match &self.last {
            Some(c) if c.up() => c.clone(),
            _ => {
                self.sticky_since = None;
                return None;
            }
        };
        // живой RSSI подключения точнее: результаты скана Windows может отдавать из кэша
        let mine = bss.iter().find(|b| b.bssid == cur.bssid);
        let my = match cur.rssi.or(mine.map(|b| b.rssi)) {
            Some(r) if r < self.sticky_rssi => r,
            _ => {
                self.sticky_since = None;
                return None;
            }
        };
        let better: Vec<&ScanSeen> = bss
            .iter()
            .filter(|b| b.ssid == cur.ssid && b.bssid != cur.bssid && b.rssi >= my + self.sticky_delta)
            .collect();
        if better.is_empty() {
            self.sticky_since = None;
            return None;
        }
        let since_t = *self.sticky_since.get_or_insert(t);
        if t - since_t < self.sticky_hold_s || self.sticky_reported_for == cur.bssid {
            return None;
        }
        // max() в Python берёт первый из равных
        let best = better
            .iter()
            .fold(better[0], |a, b| if b.rssi > a.rssi { b } else { a });
        self.sticky_reported_for = cur.bssid.clone();
        let mut ev = ConnEvent::new(
            t,
            "sticky",
            "warning",
            trf(
                "Залипание: держится за слабую BSS, хотя рядом есть сильнее на %d дБ",
                &[Arg::I((best.rssi - my) as i64)],
            ),
        );
        ev.ssid = cur.ssid.clone();
        ev.bssid_from = cur.bssid.clone();
        ev.bssid_to = best.bssid.to_string();
        ev.rssi_from = Some(my);
        ev.rssi_to = Some(best.rssi);
        ev.duration_s = Some(round1(t - since_t));
        self.push_event(ev.clone());
        Some(ev)
    }

    // ---------- сводка ----------
    pub fn stats(&self) -> Value {
        let count = |k: &str| self.events.iter().filter(|e| e.kind == k).count();
        // sum() в Python начинается с целого 0: без слагаемых в JSON уходит 0, а не 0.0
        let parts: Vec<f64> = self
            .events
            .iter()
            .filter(|e| e.kind == "connected")
            .filter_map(|e| e.duration_s)
            .filter(|&d| d != 0.0)
            .collect();
        let mut down: Option<f64> = parts.iter().fold(None, |acc, d| Some(acc.unwrap_or(0.0) + d));
        if let (Some(ds), Some(last)) = (self.down_since, &self.last) {
            if !last.up() {
                down = Some(down.unwrap_or(0.0) + (last.t - ds).max(0.0));
            }
        }
        let down_v: Value = match down {
            Some(d) => round1(d).into(),
            None => Value::Int(0),
        };
        let mut dwell: Vec<&(String, f64)> = self.dwell.iter().collect();
        dwell.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Value::Obj(vec![
            ("roams".into(), count("roam").into()),
            ("disconnects".into(), count("disconnected").into()),
            ("pingpong".into(), count("pingpong").into()),
            ("sticky".into(), count("sticky").into()),
            ("attempt_fail".into(), count("attempt_fail").into()),
            ("ssid_change".into(), count("ssid_change").into()),
            ("down_s".into(), down_v),
            ("since".into(), self.samples.front().map(|s| s.t).into()),
            ("until".into(), self.samples.back().map(|s| s.t).into()),
            (
                "dwell".into(),
                Value::Arr(
                    dwell
                        .iter()
                        .map(|(b, s)| {
                            Value::Obj(vec![
                                ("bssid".into(), b.as_str().into()),
                                ("s".into(), round1(*s).into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn current(&self) -> Option<&ConnSample> {
        self.last.as_ref()
    }

    /// «Очистить»: всё сначала, последний замер становится первым.
    pub fn clear(&mut self) {
        let last = self.last.take();
        let keep = (
            self.sticky_rssi,
            self.sticky_delta,
            self.sticky_hold_s,
            self.pingpong_window_s,
            self.max_samples,
            self.max_events,
            self.reason_attach_s,
        );
        *self = ConnTracker::default();
        (
            self.sticky_rssi,
            self.sticky_delta,
            self.sticky_hold_s,
            self.pingpong_window_s,
            self.max_samples,
            self.max_events,
            self.reason_attach_s,
        ) = keep;
        if let Some(l) = last {
            self.add_sample(l);
        }
    }

    /// Как `ConnTracker.to_dict()`: `max_samples = 0` - без замеров.
    pub fn to_value(&self, max_samples: usize, max_events: usize) -> Value {
        let skip_s = self.samples.len().saturating_sub(max_samples);
        let samples: Vec<Value> = if max_samples > 0 {
            self.samples
                .iter()
                .skip(skip_s)
                .map(|s| {
                    let up = s.up();
                    Value::Arr(vec![
                        round1(s.t).into(),
                        if up { s.rssi.into() } else { Value::Null },
                        if up { s.bssid.as_str().into() } else { "".into() },
                    ])
                })
                .collect()
        } else {
            vec![]
        };
        let skip_e = self.events.len().saturating_sub(max_events);
        let skip_r = self.raw.len().saturating_sub(60);
        Value::Obj(vec![
            ("status".into(), self.status.as_str().into()),
            (
                "current".into(),
                self.last.as_ref().map_or(Value::Null, ConnSample::to_value),
            ),
            ("samples".into(), Value::Arr(samples)),
            (
                "events".into(),
                Value::Arr(self.events.iter().skip(skip_e).map(ConnEvent::to_value).collect()),
            ),
            ("stats".into(), self.stats()),
            (
                "raw".into(),
                Value::Arr(
                    self.raw
                        .iter()
                        .skip(skip_r)
                        .map(|(t, s, c, n)| {
                            Value::Obj(vec![
                                ("t".into(), (*t).into()),
                                ("source".into(), (*s).into()),
                                ("code".into(), (*c).into()),
                                ("name".into(), n.as_str().into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

// ---------------------------------------------------------------- воспроизведение сценария

fn js(o: &Value, k: &str) -> String {
    o.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}
fn jf(o: &Value, k: &str) -> f64 {
    o.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}
fn jof(o: &Value, k: &str) -> Option<f64> {
    o.get(k).and_then(Value::as_f64)
}
fn joi(o: &Value, k: &str) -> Option<i64> {
    o.get(k).and_then(Value::as_i64)
}
fn jb(o: &Value, k: &str) -> bool {
    matches!(o.get(k), Some(Value::Bool(true)))
}

/// Одна операция сценария `contract/journal/scenarios` (замер, уведомление, стадия, IP, скан, очистка):
/// так сценарии 1.x прогоняются через журнал 2.x в тестах и в `examples/devserver` (`WBS_JOURNAL`).
pub fn replay_op(trk: &mut ConnTracker, o: &Value) -> Result<(), String> {
    match js(o, "op").as_str() {
        "sample" => {
            trk.add_sample(ConnSample {
                t: jf(o, "t"),
                state: js(o, "state"),
                ssid: js(o, "ssid"),
                bssid: js(o, "bssid"),
                rssi: joi(o, "rssi").map(|v| v as i32),
                quality: joi(o, "quality").map(|v| v as i32),
                channel: joi(o, "channel").map(|v| v as i32),
                rx_mbps: jof(o, "rx_mbps"),
                tx_mbps: jof(o, "tx_mbps"),
                auth: js(o, "auth"),
                cipher: js(o, "cipher"),
                onex: jb(o, "onex"),
                profile: js(o, "profile"),
            });
        }
        "reason" => trk.add_reason(
            jf(o, "t"),
            &js(o, "kind"),
            joi(o, "code"),
            &js(o, "reason"),
            &js(o, "ssid"),
            &js(o, "bssid"),
        ),
        "scan" => {
            let list = o.get("bss").and_then(Value::as_array).ok_or("нет поля")?;
            let seen: Vec<ScanSeen> = list
                .iter()
                .map(|x| {
                    let a = x
                        .as_array()
                        .filter(|a| a.len() == 3)
                        .ok_or("скан: [bssid, ssid, rssi]")?;
                    Ok(ScanSeen {
                        bssid: a[0].as_str().ok_or("скан: bssid")?,
                        ssid: a[1].as_str().ok_or("скан: ssid")?,
                        rssi: a[2].as_i64().ok_or("скан: rssi")? as i32,
                    })
                })
                .collect::<Result<_, &str>>()?;
            trk.check_scan(jf(o, "t"), &seen);
        }
        "raw" => trk.add_raw(
            jf(o, "t"),
            joi(o, "source").ok_or("нет поля")? as u32,
            joi(o, "code").ok_or("нет поля")? as u32,
            &js(o, "name"),
        ),
        "stage" => {
            trk.sessions.stage(
                jf(o, "t"),
                &js(o, "stage"),
                &js(o, "ssid"),
                &js(o, "bssid"),
                joi(o, "code"),
                &js(o, "reason"),
            );
        }
        "onex" => {
            trk.sessions.onex(
                jf(o, "t"),
                joi(o, "status").ok_or("нет поля")?,
                joi(o, "reason_code").unwrap_or(0),
                &js(o, "reason"),
                joi(o, "error_code").unwrap_or(0),
                &js(o, "error"),
                joi(o, "eap_type"),
                joi(o, "identity"),
                jb(o, "restarted"),
            );
        }
        "ip" => {
            let dhcp = match o.get("dhcp") {
                Some(Value::Bool(x)) => Some(*x),
                _ => None,
            };
            trk.sessions
                .ip_update(jf(o, "t"), &js(o, "ip"), dhcp, &js(o, "server"), jof(o, "lease"));
        }
        "clear" => trk.clear(),
        other => return Err(format!("неизвестная операция {other}")),
    }
    Ok(())
}
