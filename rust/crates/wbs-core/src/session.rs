//! Сессии подключения: машина состояний клиента по уведомлениям Windows. Перенос `wifi_beacon_scanner/session.py`.
//!
//! Источники (все без прав администратора): ACM (connection_start / complete / attempt_fail / disconnected),
//! MSM (associating → associated → authenticating → connected, roaming_start / roaming_end, disassociating),
//! ONEX (802.1X: результат EAP, причина, тип EAP, чья учётка) и опрос IP (когда появился IPv4, аренда DHCP).
//! Сессия - одна попытка подключения или один роуминг: стадии с отметками времени и длительности.
//! 4-way handshake отдельно Windows не сообщает: он входит в стадию «аутентификация» (authenticating → connected).
//!
//! Модуль не зависит от Windows; совпадение с 1.x проверяет `tests/journal.rs` по `contract/journal`.

use std::collections::VecDeque;

use crate::i18n::{tr, trf, Arg};
use crate::json::Value;

pub const SESSION_TIMEOUT_S: f64 = 120.0;
pub const IP_WAIT_S: f64 = 60.0;
const MAX_SESSIONS: usize = 300;

pub fn stage_ru(stage: &str) -> &'static str {
    match stage {
        "start" => "начало подключения",
        "associating" => "ассоциация",
        "associated" => "ассоциирован",
        "authenticating" => "аутентификация",
        "connected" => "подключён",
        "complete" => "подключение завершено",
        "roam_start" => "начало роуминга",
        "roam_end" => "роуминг завершён",
        "disassociating" => "разрыв ассоциации",
        "disconnected" => "отключён",
        "fail" => "не удалось подключиться",
        "ip" => "получен IPv4",
        "dhcp" => "аренда DHCP",
        "onex" => "802.1X",
        "onex_restart" => "802.1X перезапущен",
        _ => "",
    }
}

pub fn onex_status_ru(s: i64) -> Option<&'static str> {
    Some(match s {
        0 => "не начата",
        1 => "идёт",
        2 => "нет ответа от аутентификатора (802.1X не включён на AP?)",
        3 => "успех",
        4 => "отказ",
        5 => "неизвестно",
        _ => return None,
    })
}

pub fn onex_identity_ru(s: i64) -> Option<&'static str> {
    Some(match s {
        0 => "нет",
        1 => "компьютер",
        2 => "пользователь",
        3 => "явно заданный пользователь",
        4 => "гость",
        _ => return None,
    })
}

pub fn eap_name(t: i64) -> String {
    match t {
        1 => "Identity",
        4 => "MD5",
        6 => "GTC",
        13 => "EAP-TLS",
        17 => "LEAP",
        18 => "EAP-SIM",
        21 => "EAP-TTLS",
        23 => "EAP-AKA",
        25 => "PEAP",
        26 => "MSCHAPv2",
        43 => "EAP-FAST",
        50 => "EAP-AKA'",
        _ => return format!("EAP {t}"),
    }
    .to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stage {
    pub t: f64,
    pub stage: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Session {
    pub id: u64,
    /// connect | roam
    pub kind: String,
    pub t_start: f64,
    pub ssid: String,
    pub bssid: String,
    pub bssid_from: String,
    /// in_progress | ok | fail | aborted
    pub result: String,
    pub reason: String,
    pub reason_code: Option<i64>,
    pub stages: Vec<Stage>,
    pub t_assoc_start: Option<f64>,
    pub t_assoc_done: Option<f64>,
    pub t_auth_start: Option<f64>,
    pub t_connected: Option<f64>,
    pub t_end: Option<f64>,
    pub onex_status: Option<i64>,
    pub onex_reason: String,
    pub onex_reason_code: Option<i64>,
    pub onex_error: String,
    pub onex_error_code: Option<i64>,
    pub eap_type: Option<i64>,
    pub onex_identity: Option<i64>,
    pub onex_restarts: i64,
    pub t_ip: Option<f64>,
    pub ip: String,
    pub dhcp_server: String,
    pub dhcp: Option<bool>,
    pub lease_obtained: Option<f64>,
    pub ip_note: String,
    /// lease / appeared / kept / static / apipa - для логики, не для показа
    pub ip_kind: String,
    pub ip_checked: bool,
    pub ip_at_connect: String,
    pub lease_at_connect: Option<f64>,
}

/// Миллисекунды между отметками (`int(round(...))` в Python - банковское округление).
fn ms(a: Option<f64>, b: Option<f64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some((((b - a) * 1000.0).round_ties_even() as i64).max(0)),
        _ => None,
    }
}

impl Session {
    fn new(id: u64, kind: &str, t: f64, ssid: &str, bssid: &str, bssid_from: &str) -> Session {
        Session {
            id,
            kind: kind.into(),
            t_start: t,
            ssid: ssid.into(),
            bssid: bssid.into(),
            bssid_from: bssid_from.into(),
            result: "in_progress".into(),
            ..Session::default()
        }
    }

    pub fn assoc_ms(&self) -> Option<i64> {
        ms(self.t_assoc_start, self.t_assoc_done)
    }
    pub fn auth_ms(&self) -> Option<i64> {
        ms(self.t_auth_start, self.t_connected)
    }
    pub fn total_ms(&self) -> Option<i64> {
        let first = match self.t_assoc_start {
            Some(a) if self.kind == "roam" => a,
            _ => self.t_start,
        };
        ms(Some(first), self.t_connected)
    }
    pub fn ip_ms(&self) -> Option<i64> {
        ms(self.t_connected, self.t_ip)
    }
    pub fn eap_name(&self) -> String {
        self.eap_type.map(eap_name).unwrap_or_default()
    }
    pub fn onex_status_text(&self) -> String {
        self.onex_status
            .map(|s| tr(onex_status_ru(s).unwrap_or("")))
            .unwrap_or_default()
    }
    pub fn onex_identity_text(&self) -> String {
        self.onex_identity
            .map(|s| tr(onex_identity_ru(s).unwrap_or("")))
            .unwrap_or_default()
    }

    /// Как `Session.to_dict()`: поля dataclass по порядку и вычисленные длительности.
    pub fn to_value(&self) -> Value {
        let stages = Value::Arr(
            self.stages
                .iter()
                .map(|s| {
                    Value::Obj(vec![
                        ("t".into(), s.t.into()),
                        ("stage".into(), s.stage.as_str().into()),
                        ("detail".into(), s.detail.as_str().into()),
                    ])
                })
                .collect(),
        );
        let kv: Vec<(&str, Value)> = vec![
            ("id", Value::Int(self.id as i64)),
            ("kind", self.kind.as_str().into()),
            ("t_start", self.t_start.into()),
            ("ssid", self.ssid.as_str().into()),
            ("bssid", self.bssid.as_str().into()),
            ("bssid_from", self.bssid_from.as_str().into()),
            ("result", self.result.as_str().into()),
            ("reason", self.reason.as_str().into()),
            ("reason_code", self.reason_code.into()),
            ("stages", stages),
            ("t_assoc_start", self.t_assoc_start.into()),
            ("t_assoc_done", self.t_assoc_done.into()),
            ("t_auth_start", self.t_auth_start.into()),
            ("t_connected", self.t_connected.into()),
            ("t_end", self.t_end.into()),
            ("onex_status", self.onex_status.into()),
            ("onex_reason", self.onex_reason.as_str().into()),
            ("onex_reason_code", self.onex_reason_code.into()),
            ("onex_error", self.onex_error.as_str().into()),
            ("onex_error_code", self.onex_error_code.into()),
            ("eap_type", self.eap_type.into()),
            ("onex_identity", self.onex_identity.into()),
            ("onex_restarts", self.onex_restarts.into()),
            ("t_ip", self.t_ip.into()),
            ("ip", self.ip.as_str().into()),
            ("dhcp_server", self.dhcp_server.as_str().into()),
            ("dhcp", self.dhcp.into()),
            ("lease_obtained", self.lease_obtained.into()),
            ("ip_note", self.ip_note.as_str().into()),
            ("ip_kind", self.ip_kind.as_str().into()),
            ("ip_checked", self.ip_checked.into()),
            ("ip_at_connect", self.ip_at_connect.as_str().into()),
            ("lease_at_connect", self.lease_at_connect.into()),
            ("assoc_ms", self.assoc_ms().into()),
            ("auth_ms", self.auth_ms().into()),
            ("total_ms", self.total_ms().into()),
            ("ip_ms", self.ip_ms().into()),
            ("eap_name", self.eap_name().into()),
            ("onex_status_ru", self.onex_status_text().into()),
            ("onex_identity_ru", self.onex_identity_text().into()),
        ];
        Value::Obj(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

fn finish(s: &mut Session, t: f64, result: &str, reason: &str, code: Option<i64>) {
    s.result = result.into();
    s.t_end = Some(t);
    if !reason.is_empty() {
        s.reason = reason.into();
    }
    if code.is_some() {
        s.reason_code = code;
    }
}

/// Машина состояний (`SessionTracker`).
#[derive(Debug, Clone)]
pub struct SessionTracker {
    pub sessions: VecDeque<Session>,
    next_id: u64,
    /// id открытой сессии (в 1.x - ссылка на объект). Подключённую держим открытой, пока ждём IP.
    open: Option<u64>,
    lease: Option<f64>,
    ip: String,
    linked: bool,
}

impl Default for SessionTracker {
    fn default() -> Self {
        SessionTracker {
            sessions: VecDeque::new(),
            next_id: 1,
            open: None,
            lease: None,
            ip: String::new(),
            linked: false,
        }
    }
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn idx(&self, id: Option<u64>) -> Option<usize> {
        let id = id?;
        self.sessions.iter().rposition(|s| s.id == id)
    }

    fn new_session(&mut self, t: f64, kind: &str, ssid: &str, bssid: &str, bssid_from: &str) -> usize {
        if let Some(i) = self.idx(self.open) {
            if self.sessions[i].result == "in_progress" {
                finish(
                    &mut self.sessions[i],
                    t,
                    "aborted",
                    &tr("прервано новой попыткой"),
                    None,
                );
            }
        }
        let s = Session::new(self.next_id, kind, t, ssid, bssid, bssid_from);
        self.next_id += 1;
        if self.sessions.len() == MAX_SESSIONS {
            self.sessions.pop_front();
        }
        self.sessions.push_back(s);
        self.open = Some(self.next_id - 1);
        self.sessions.len() - 1
    }

    /// Открытая сессия; попытка без исхода дольше SESSION_TIMEOUT_S закрывается.
    fn current(&mut self, t: f64) -> Option<usize> {
        let i = self.idx(self.open)?;
        let s = &mut self.sessions[i];
        if s.result == "in_progress" && t - s.t_start > SESSION_TIMEOUT_S {
            if s.t_connected.is_some() {
                finish(s, t, "ok", "", None); // подключились, а завершающее уведомление не пришло
            } else {
                let why = trf("нет исхода за %d с", &[Arg::I(SESSION_TIMEOUT_S as i64)]);
                finish(s, t, "aborted", &why, None);
            }
        }
        Some(i)
    }

    /// Последняя сессия с подключением, если оно было не дольше `within` секунд назад.
    pub fn last_connected(&self, t: f64, within: f64) -> Option<usize> {
        for (i, s) in self.sessions.iter().enumerate().rev() {
            if let Some(tc) = s.t_connected {
                return (t - tc <= within).then_some(i);
            }
        }
        None
    }

    fn prev_bssid(&self) -> String {
        self.sessions.back().map(|s| s.bssid.clone()).unwrap_or_default()
    }

    /// Стадия из ACM / MSM.
    pub fn stage(
        &mut self,
        t: f64,
        stage: &str,
        ssid: &str,
        bssid: &str,
        reason_code: Option<i64>,
        reason: &str,
    ) -> Option<usize> {
        let cur = self.current(t);
        let active = cur.is_some_and(|i| self.sessions[i].result == "in_progress");
        let i = match stage {
            "start" => self.new_session(t, "connect", ssid, "", ""),
            "roam_start" => {
                let from = if bssid.is_empty() {
                    self.prev_bssid()
                } else {
                    bssid.to_string()
                };
                self.new_session(t, "roam", ssid, "", &from)
            }
            "associating" => {
                let i = match cur {
                    Some(i) if active => i,
                    _ => {
                        // без connection_start: роуминг без roaming_start (если связь была) или переподключение
                        let prev = self.prev_bssid();
                        if self.linked {
                            self.new_session(t, "roam", ssid, bssid, &prev)
                        } else {
                            self.new_session(t, "connect", ssid, bssid, "")
                        }
                    }
                };
                let s = &mut self.sessions[i];
                s.t_assoc_start = s.t_assoc_start.or(Some(t));
                i
            }
            _ if !active => {
                if let Some(c) = cur {
                    let s = &mut self.sessions[c];
                    if (stage == "roam_end" || stage == "complete") && s.t_end.is_some_and(|e| t - e < 5.0) {
                        s.stages.push(Stage {
                            t,
                            stage: stage.into(),
                            detail: reason.into(),
                        }); // хвост только что закрытой сессии
                        return Some(c);
                    }
                }
                if matches!(
                    stage,
                    "connected" | "complete" | "roam_end" | "disconnected" | "disassociating" | "fail"
                ) {
                    return None; // событие вне попытки подключения
                }
                self.new_session(t, "connect", ssid, bssid, "")
            }
            _ => cur.expect("активная сессия"),
        };
        let (ip_now, lease_now) = (self.ip.clone(), self.lease);
        let s = &mut self.sessions[i];
        if !ssid.is_empty() && s.ssid.is_empty() {
            s.ssid = ssid.into();
        }
        if !bssid.is_empty() && stage != "roam_start" {
            s.bssid = bssid.into();
        }
        s.stages.push(Stage {
            t,
            stage: stage.into(),
            detail: reason.into(),
        });
        let mut linked = None;
        match stage {
            "connected" | "complete" | "roam_end" => linked = Some(s.result != "fail"),
            "disconnected" | "disassociating" | "fail" => linked = Some(false),
            _ => {}
        }
        match stage {
            "associated" => s.t_assoc_done = Some(t),
            "authenticating" => s.t_auth_start = s.t_auth_start.or(Some(t)),
            "connected" => {
                if s.t_connected.is_none() {
                    s.t_connected = Some(t);
                    s.ip_at_connect = ip_now;
                    s.lease_at_connect = lease_now;
                }
                if s.kind == "roam" {
                    finish(s, t, "ok", "", None);
                }
            }
            "complete" => {
                if reason_code.is_some_and(|c| c != 0) {
                    finish(s, t, "fail", reason, reason_code);
                } else {
                    if s.t_connected.is_none() {
                        s.t_connected = Some(t);
                        s.ip_at_connect = ip_now;
                        s.lease_at_connect = lease_now;
                    }
                    finish(s, t, "ok", "", None);
                }
            }
            "roam_end" => {
                if s.t_connected.is_none() {
                    s.t_connected = Some(t);
                }
                let r = if s.result == "in_progress" {
                    "ok".to_string()
                } else {
                    s.result.clone()
                };
                finish(s, t, &r, "", None);
            }
            "fail" | "disconnected" | "disassociating" if s.result == "in_progress" => {
                let why = if reason.is_empty() {
                    tr(stage_ru(stage))
                } else {
                    reason.to_string()
                };
                finish(s, t, "fail", &why, reason_code);
            }
            _ => {}
        }
        let (done, connected, id) = (s.result != "in_progress", s.t_connected.is_some(), s.id);
        if let Some(l) = linked {
            self.linked = l;
        }
        if done && self.open == Some(id) {
            self.open = if connected { Some(id) } else { None }; // подключённую держим для IP
        }
        Some(i)
    }

    /// Уведомление 802.1X.
    #[allow(clippy::too_many_arguments)]
    pub fn onex(
        &mut self,
        t: f64,
        status: i64,
        reason_code: i64,
        reason: &str,
        error_code: i64,
        error: &str,
        eap_type: Option<i64>,
        identity: Option<i64>,
        restarted: bool,
    ) -> usize {
        let open = self.idx(self.open).filter(|&i| {
            let s = &self.sessions[i];
            s.result == "in_progress" || t - s.t_connected.unwrap_or(t) < 30.0
        });
        let i = match open {
            Some(i) => i,
            None => self.new_session(t, "connect", "", "", ""),
        };
        let s = &mut self.sessions[i];
        if restarted {
            s.onex_restarts += 1;
            s.stages.push(Stage {
                t,
                stage: "onex_restart".into(),
                detail: reason.into(),
            });
            return i;
        }
        s.onex_status = Some(status);
        if reason_code != 0 {
            s.onex_reason_code = Some(reason_code);
            s.onex_reason = reason.into();
        }
        if error_code != 0 {
            s.onex_error_code = Some(error_code);
            s.onex_error = error.into();
        }
        if eap_type.is_some() {
            s.eap_type = eap_type;
        }
        if identity.is_some() {
            s.onex_identity = identity;
        }
        let mut detail = match onex_status_ru(status) {
            Some(r) => tr(r),
            None => status.to_string(),
        };
        if !reason.is_empty() {
            detail.push_str(": ");
            detail.push_str(reason);
        }
        s.stages.push(Stage {
            t,
            stage: "onex".into(),
            detail,
        });
        if (status == 2 || status == 4) && s.result == "in_progress" {
            let why = if !reason.is_empty() {
                reason.to_string()
            } else if !error.is_empty() {
                error.to_string()
            } else {
                tr(onex_status_ru(status).unwrap_or(""))
            };
            let code = if reason_code != 0 {
                Some(reason_code)
            } else if error_code != 0 {
                Some(error_code)
            } else {
                None
            };
            finish(s, t, "fail", &format!("802.1X: {why}"), code);
        }
        i
    }

    /// Опрос адаптера раз в секунду: IPv4 и аренда DHCP. Новая аренда после подключения и есть завершённый DORA.
    pub fn ip_update(
        &mut self,
        t: f64,
        ip: &str,
        dhcp: Option<bool>,
        dhcp_server: &str,
        lease_obtained: Option<f64>,
    ) -> Option<usize> {
        let valid = !ip.is_empty() && ip != "0.0.0.0";
        self.ip = if valid { ip.to_string() } else { String::new() };
        if lease_obtained.is_some() {
            self.lease = lease_obtained;
        }
        let i = self.last_connected(t, IP_WAIT_S)?;
        let s = &mut self.sessions[i];
        if s.ip_checked || !valid {
            return None;
        }
        let tc = s.t_connected.unwrap_or(t);
        s.ip = ip.into();
        s.dhcp = dhcp;
        s.dhcp_server = dhcp_server.into();
        let dhcp_on = dhcp == Some(true);
        match lease_obtained {
            Some(lease) if Some(lease) != s.lease_at_connect && lease >= tc - 2.0 => {
                s.t_ip = Some(t.min(tc.max(lease)));
                s.lease_obtained = Some(lease);
                s.ip_note = tr("новая аренда DHCP");
                s.ip_kind = "lease".into();
            }
            _ if ip != s.ip_at_connect => {
                s.t_ip = Some(t);
                s.ip_note = tr("адрес появился") + if dhcp_on { " (DHCP)" } else { "" };
                s.ip_kind = "appeared".into();
            }
            _ if t - tc >= 10.0 => {
                s.ip_kind = if dhcp_on { "kept" } else { "static" }.into();
                s.ip_note = if dhcp_on {
                    tr("адрес сохранился с прошлого подключения, новой аренды DHCP не было")
                } else {
                    tr("статический адрес")
                };
            }
            _ => return None,
        }
        if ip.starts_with("169.254.") {
            s.ip_note = tr("APIPA 169.254.x.x: DHCP-сервер не ответил");
            s.ip_kind = "apipa".into();
        }
        s.ip_checked = true;
        let server = if dhcp_server.is_empty() {
            String::new()
        } else {
            tr(", DHCP-сервер ") + dhcp_server
        };
        s.stages.push(Stage {
            t: s.t_ip.unwrap_or(t),
            stage: if s.ip_kind == "lease" { "dhcp" } else { "ip" }.into(),
            detail: format!("{ip}{server}, {}", s.ip_note),
        });
        Some(i)
    }

    pub fn summary(&self) -> Value {
        fn med(mut v: Vec<i64>) -> Value {
            v.sort_unstable();
            v.get(v.len() / 2).copied().into()
        }
        let ss = &self.sessions;
        let conn: Vec<&Session> = ss.iter().filter(|s| s.kind == "connect").collect();
        let roam: Vec<&Session> = ss.iter().filter(|s| s.kind == "roam").collect();
        let failed = |s: &Session| s.result == "fail" || s.result == "aborted";
        let kv: Vec<(&str, Value)> = vec![
            ("connects", conn.len().into()),
            ("connects_ok", conn.iter().filter(|s| s.result == "ok").count().into()),
            ("connects_fail", conn.iter().filter(|s| failed(s)).count().into()),
            ("roams", roam.len().into()),
            ("roams_fail", roam.iter().filter(|s| failed(s)).count().into()),
            (
                "connect_ms_med",
                med(conn
                    .iter()
                    .filter(|s| s.result == "ok")
                    .filter_map(|s| s.total_ms())
                    .collect()),
            ),
            (
                "roam_ms_med",
                med(roam
                    .iter()
                    .filter(|s| s.result == "ok")
                    .filter_map(|s| s.total_ms())
                    .collect()),
            ),
            ("auth_ms_med", med(ss.iter().filter_map(|s| s.auth_ms()).collect())),
            (
                "ip_ms_med",
                med(ss
                    .iter()
                    .filter(|s| s.ip_kind == "lease" || s.ip_kind == "appeared")
                    .filter_map(|s| s.ip_ms())
                    .collect()),
            ),
            ("onex_ok", ss.iter().filter(|s| s.onex_status == Some(3)).count().into()),
            (
                "onex_fail",
                ss.iter()
                    .filter(|s| matches!(s.onex_status, Some(2) | Some(4)))
                    .count()
                    .into(),
            ),
        ];
        Value::Obj(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// `{"sessions": [последние max_sessions], "summary": {...}}`.
    pub fn to_value(&self, max_sessions: usize) -> Value {
        let skip = self.sessions.len().saturating_sub(max_sessions);
        Value::Obj(vec![
            (
                "sessions".into(),
                Value::Arr(self.sessions.iter().skip(skip).map(Session::to_value).collect()),
            ),
            ("summary".into(), self.summary()),
        ])
    }

    pub fn clear(&mut self) {
        *self = SessionTracker::new();
    }
}
