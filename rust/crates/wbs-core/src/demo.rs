//! Демо-режим: посмотреть программу без Wi-Fi. Перенос `DemoBackend`, `DemoConnMonitor`, `demo_winlog` из 1.x.
//!
//! «Офис с соседями» - тот же снапшот, что строит `demo.py` (`contract/fixtures/demo-office.json`). Каждый скан
//! слегка меняет RSSI и иногда «теряет» слабый BSS; на обходе сигнал падает с расстоянием до условного места AP.
//! Журнал подключения: сначала 5 минут истории (тот же сценарий, что у 1.x - `contract/journal/scenarios/demo.json`,
//! сдвинутый к «сейчас»), потом раз в секунду живые замеры и роуминг раз в 90 секунд. Причины помечены «демо».

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{Backend, ConnSink, MonitorHandle, ScanError};
use crate::clock::{iso_with_offset, now_unix};
use crate::conn::{replay_op, ConnSample, ConnTracker};
use crate::i18n::tr;
use crate::json::{self, Value};
use crate::mcs::{phy_rate, Phy};
use crate::model::{Bss, Snapshot};
use crate::winlog::{group_of, level_ru};

const DEMO_SNAPSHOT: &str = include_str!("../../../../contract/fixtures/demo-office.json");
const DEMO_JOURNAL: &str = include_str!("../../../../contract/journal/scenarios/demo.json");
/// Сценарий записан с «сейчас» = T0 + 300 (`tools/journal_contract.py`).
const DEMO_JOURNAL_NOW: f64 = 1_792_000_000.0 + 300.0;

/// Простой генератор случайных чисел (xorshift64*): для демо точность распределения не важна.
pub struct Rng(AtomicU64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(AtomicU64::new(seed | 1))
    }
    fn next(&self) -> u64 {
        let mut x = self.0.load(Ordering::Relaxed);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0.store(x, Ordering::Relaxed);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// [0, 1)
    pub fn random(&self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// a..=b
    pub fn randint(&self, a: i64, b: i64) -> i64 {
        a + (self.next() % (b - a + 1) as u64) as i64
    }
    pub fn uniform(&self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.random()
    }
}

fn time_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9)
}

pub fn demo_snapshot() -> Snapshot {
    Snapshot::from_json(DEMO_SNAPSHOT).expect("демо-снапшот")
}

/// Источник демо-режима (`DemoBackend`).
pub struct DemoBackend {
    pub base: Snapshot,
    rng: Rng,
    pos: Mutex<Option<(f64, f64)>>,
    tz_offset_min: i32,
}

impl DemoBackend {
    pub fn new(base: Option<Snapshot>, tz_offset_min: i32) -> DemoBackend {
        DemoBackend {
            base: base.unwrap_or_else(demo_snapshot),
            rng: Rng::new(time_seed()),
            pos: Mutex::new(None),
            tz_offset_min,
        }
    }

    /// Условное место AP на плане: радио одной AP (общий префикс MAC) стоят в одной точке.
    fn virtual_place(bssid: &str) -> (f64, f64) {
        let h: u64 = bssid
            .chars()
            .take(14)
            .enumerate()
            .map(|(i, c)| (i as u64 + 1) * c as u64)
            .sum();
        (
            0.08 + (h % 97) as f64 / 97.0 * 0.84,
            0.1 + (h / 97 % 89) as f64 / 89.0 * 0.8,
        )
    }
}

impl Backend for DemoBackend {
    fn name(&self) -> &str {
        "demo"
    }

    fn interfaces(&self) -> Result<Vec<String>, String> {
        Ok(vec!["Demo adapter".into()])
    }

    fn scan(&self, _: usize, wait_s: f64) -> Result<Snapshot, ScanError> {
        std::thread::sleep(Duration::from_secs_f64(wait_s.min(0.6)));
        let pos = *self.pos.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = vec![];
        for b in &self.base.bss {
            let mut rssi = b.rssi as i64 + self.rng.randint(-3, 3);
            if let Some((px, py)) = pos {
                // демо-обход: сигнал падает с расстоянием до условного места AP
                let (ax, ay) = Self::virtual_place(&b.bssid);
                let dist = ((ax - px).powi(2) + ((ay - py) * 0.55).powi(2)).sqrt().max(0.02);
                let band_loss = if b.band() != "2.4" { 4.0 } else { 0.0 };
                rssi = (-38.0 - 30.0 * (dist / 0.3).powf(0.8) - band_loss + self.rng.randint(-2, 2) as f64) as i64;
                if rssi < -92 {
                    continue;
                }
            } else if b.rssi < -78 && self.rng.random() < 0.3 {
                continue;
            }
            out.push(Bss::new(
                &b.bssid,
                b.ssid_bytes.clone(),
                rssi.clamp(-100, -20) as i32,
                b.link_quality,
                b.freq_khz,
                b.beacon_interval,
                b.capability,
                b.phy_type,
                b.ie_raw.clone(),
            ));
        }
        Ok(Snapshot {
            taken_at: iso_with_offset(now_unix(), self.tz_offset_min),
            interface: self.base.interface.clone(),
            bss: out,
        })
    }

    fn set_position(&self, x: f64, y: f64) {
        *self.pos.lock().unwrap_or_else(|e| e.into_inner()) = Some((x, y));
    }

    fn read_winlog(&self, hours: f64) -> Result<Vec<Value>, String> {
        let now = now_unix();
        Ok(demo_winlog(now)
            .into_iter()
            .filter(|e| e.get("t").and_then(Value::as_f64).unwrap_or(0.0) >= now - hours * 3600.0)
            .collect())
    }

    fn start_conn_monitor(
        &self,
        sink: Arc<dyn ConnSink>,
        _interface_index: usize,
    ) -> Result<Option<Box<dyn MonitorHandle>>, String> {
        start_monitor(sink, &self.base).map(Some)
    }
}

// ---------------------------------------------------------------- журнал Windows (демо)

/// (смещение от «сейчас», номер события, уровень, текст, EventData)
type WinlogRow<'a> = (f64, i64, i64, &'a str, Vec<(&'static str, String)>);

/// Синтетические события WLAN-AutoConfig (`demo_winlog`): текст - пересказ, помечен «демо».
pub fn demo_winlog(now: f64) -> Vec<Value> {
    let ok: Vec<(&'static str, String)> = vec![
        ("ProfileName", "CORP".into()),
        ("SSID", "CORP".into()),
        ("BSSType", "Infrastructure".into()),
        ("PHYType", "802.11ax".into()),
        ("AuthenticationAlgorithm", "WPA2-Enterprise".into()),
        ("CipherAlgorithm", "AES-CCMP".into()),
        ("OnexEnabled", "1".into()),
    ];
    let d = |kv: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
        kv.iter().map(|(k, v)| (*k, v.to_string())).collect()
    };
    let start = |dt: f64| {
        (
            dt,
            8000,
            4,
            "демо: служба WLAN AutoConfig начала подключение к сети CORP",
            d(&[("SSID", "CORP"), ("ConnectionMode", "Auto")]),
        )
    };
    let success = |dt: f64| {
        (
            dt,
            8001,
            4,
            "демо: служба WLAN AutoConfig успешно подключилась к сети CORP",
            ok.clone(),
        )
    };
    let rows: Vec<WinlogRow> = vec![
        success(-30500.0),
        (
            -21900.0,
            8003,
            4,
            "демо: отключено от сети CORP. Причина: пользователь отключил беспроводное подключение",
            vec![
                ("SSID", "CORP".into()),
                ("Reason", tr("Пользователь отключил подключение")),
                ("ReasonCode", "0x00028002".into()),
            ],
        ),
        (
            -21850.0,
            8002,
            2,
            "демо: не удалось подключиться к сети Hotel-WiFi. Причина: сеть недоступна",
            vec![
                ("SSID", "Hotel-WiFi".into()),
                ("FailureReason", tr("Сеть недоступна")),
                ("ReasonCode", "0x00028002".into()),
            ],
        ),
        (
            -9000.0,
            11006,
            3,
            "демо: проверка безопасности беспроводной сети не выполнена: истекло время ожидания 4-way handshake",
            vec![
                ("SSID", "CORP".into()),
                ("PeerMac", "00:e0:fc:10:04:02".into()),
                ("FailureReason", tr("Тайм-аут 4-way handshake")),
                ("ReasonCode", "0x00048001".into()),
            ],
        ),
        (
            -8990.0,
            8002,
            2,
            "демо: не удалось подключиться к сети CORP. Причина: тайм-аут 4-way handshake",
            vec![
                ("SSID", "CORP".into()),
                ("FailureReason", tr("Тайм-аут 4-way handshake")),
                ("ReasonCode", "0x00048001".into()),
            ],
        ),
        success(-8950.0),
        start(-290.0),
        (
            -289.9,
            11000,
            4,
            "демо: начата ассоциация с беспроводной сетью",
            d(&[("SSID", "CORP"), ("PeerMac", "00:e0:fc:10:01:02")]),
        ),
        (
            -289.8,
            11001,
            4,
            "демо: ассоциация с беспроводной сетью выполнена",
            d(&[("SSID", "CORP"), ("PeerMac", "00:e0:fc:10:01:02")]),
        ),
        (
            -289.8,
            11010,
            4,
            "демо: начата проверка безопасности беспроводной сети",
            d(&[("SSID", "CORP")]),
        ),
        (
            -289.7,
            12011,
            4,
            "демо: начата проверка подлинности 802.1X",
            d(&[("SSID", "CORP"), ("EAPType", "13")]),
        ),
        (
            -289.1,
            12012,
            4,
            "демо: проверка подлинности 802.1X выполнена (EAP-TLS, учётные данные компьютера)",
            d(&[("SSID", "CORP"), ("EAPType", "13"), ("Identity", "host/LAPTOP-01")]),
        ),
        (
            -289.0,
            11005,
            4,
            "демо: проверка безопасности беспроводной сети выполнена",
            d(&[("SSID", "CORP")]),
        ),
        success(-288.9),
        (
            -158.0,
            8003,
            4,
            "демо: отключено от сети CORP. Причина: точка доступа разорвала ассоциацию",
            vec![
                ("SSID", "CORP".into()),
                ("Reason", tr("Точка доступа разорвала ассоциацию")),
                ("ReasonCode", "0x00038004".into()),
            ],
        ),
        start(-157.0),
        (
            -156.5,
            12013,
            2,
            "демо: ошибка проверки подлинности 802.1X: не удалось проверить отзыв сертификата",
            vec![
                ("SSID", "CORP".into()),
                ("EAPType", "13".into()),
                ("Reason", tr("Не удалось проверить отзыв сертификата")),
                ("ErrorCode", "0x80092013".into()),
            ],
        ),
        (
            -156.4,
            8002,
            2,
            "демо: не удалось подключиться к сети CORP. Причина: ошибка 802.1X",
            vec![
                ("SSID", "CORP".into()),
                ("FailureReason", tr("Ошибка проверки подлинности 802.1X")),
                ("ReasonCode", "0x00050005".into()),
            ],
        ),
        start(-154.0),
        (
            -152.6,
            12012,
            4,
            "демо: проверка подлинности 802.1X выполнена",
            d(&[("SSID", "CORP"), ("EAPType", "13")]),
        ),
        success(-152.5),
    ];
    let mut out: Vec<(f64, Value)> = rows
        .into_iter()
        .map(|(dt, id, level, msg, data)| {
            let get = |k: &str| data.iter().find(|(x, _)| *x == k).map(|(_, v)| v.clone());
            let t = now + dt;
            (
                t,
                Value::Obj(vec![
                    ("t".into(), t.into()),
                    ("id".into(), id.into()),
                    ("level".into(), level.into()),
                    ("level_ru".into(), level_ru(level).into()),
                    ("group".into(), group_of(id).into()),
                    ("message".into(), tr(msg).into()),
                    ("ssid".into(), get("SSID").unwrap_or_default().into()),
                    ("bssid".into(), get("PeerMac").unwrap_or_default().into()),
                    (
                        "reason".into(),
                        get("FailureReason")
                            .or_else(|| get("Reason"))
                            .unwrap_or_default()
                            .into(),
                    ),
                    (
                        "data".into(),
                        Value::Obj(data.iter().map(|(k, v)| (k.to_string(), v.as_str().into())).collect()),
                    ),
                ]),
            )
        })
        .collect();
    out.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    out.into_iter().map(|(_, v)| v).collect()
}

// ---------------------------------------------------------------- журнал подключения (демо)

/// Текст сценария на языке программы: сценарий записан по-русски, «демо: ...» переводится по частям.
fn tr_demo(s: &str) -> String {
    let t = tr(s);
    if t != s || !s.starts_with("демо: ") {
        return t;
    }
    tr("демо: ") + &tr(&s["демо: ".len()..])
}

/// Скорость как у HE-подключения 2x2, 80 МГц: MCS падает с сигналом (примерно 3 дБ на ступень).
fn demo_rate(rssi: f64, back: i64) -> f64 {
    // max(0, min(11, int((rssi + 82) / 3)) - back) в 1.x
    let mcs = ((((rssi + 82.0) / 3.0).trunc() as i64).min(11) - back).max(0);
    crate::ie::round1(phy_rate(Phy::He, mcs as u32, 2, 80, None).unwrap_or(0.0))
}

/// 5 минут истории - сценарий 1.x, сдвинутый так, чтобы он кончался сейчас.
pub fn demo_prefill(c: &mut ConnTracker, now: f64) {
    let Ok(src) = json::parse(DEMO_JOURNAL) else { return };
    let shift = now - DEMO_JOURNAL_NOW;
    for o in src.get("ops").and_then(Value::as_array).into_iter().flatten() {
        let Value::Obj(kv) = o else { continue };
        let moved = Value::Obj(
            kv.iter()
                .map(|(k, v)| match (k.as_str(), v) {
                    ("t" | "lease", Value::Int(_) | Value::Num(_)) => {
                        (k.clone(), Value::Num(v.as_f64().unwrap_or(0.0) + shift))
                    }
                    ("reason" | "error", Value::Str(s)) => (k.clone(), Value::Str(tr_demo(s))),
                    _ => (k.clone(), v.clone()),
                })
                .collect(),
        );
        let _ = replay_op(c, &moved);
    }
}

struct DemoMonitor {
    sink: Arc<dyn ConnSink>,
    /// CORP 5 ГГц: (bssid, канал), сильнее - первыми
    aps: Vec<(String, i32)>,
    rng: Rng,
}

impl DemoMonitor {
    fn sample(&self, t: f64, i: usize, rssi: f64) -> ConnSample {
        let (bssid, ch) = &self.aps[i % self.aps.len()];
        ConnSample {
            t,
            state: "connected".into(),
            ssid: "CORP".into(),
            bssid: bssid.clone(),
            rssi: Some(rssi.round_ties_even() as i32),
            quality: Some((2.0 * (rssi + 100.0)).trunc().clamp(0.0, 100.0) as i32),
            channel: Some(*ch),
            rx_mbps: Some(demo_rate(rssi, 0)),
            tx_mbps: Some(demo_rate(rssi, 1)),
            auth: "WPA2 (RSNA)".into(),
            cipher: "CCMP".into(),
            onex: true,
            profile: "CORP".into(),
        }
    }

    fn roam(c: &mut ConnTracker, t: f64, from: &str, to: &str, ms: f64) {
        let ses = &mut c.sessions;
        ses.stage(t, "roam_start", "CORP", from, None, "");
        ses.stage(t + 0.01, "associating", "CORP", to, None, "");
        let a = ms * 0.45 / 1000.0;
        ses.stage(t + 0.01 + a, "associated", "CORP", to, None, "");
        ses.stage(t + 0.01 + a, "authenticating", "CORP", to, None, "");
        ses.stage(t + 0.01 + ms / 1000.0, "connected", "CORP", to, None, "");
        ses.stage(t + 0.02 + ms / 1000.0, "roam_end", "CORP", to, None, "");
    }

    fn run(self, stop: std::sync::mpsc::Receiver<()>) {
        self.sink.with_conn(&mut |c| {
            c.status = tr("демо-режим: синтетический журнал (5 минут истории + живые замеры)");
            demo_prefill(c, now_unix());
        });
        let (mut rssi, mut i, mut k) = (-58.0f64, 0usize, 0u64);
        loop {
            match stop.recv_timeout(Duration::from_secs(1)) {
                Err(RecvTimeoutError::Timeout) => {}
                _ => return,
            }
            k += 1;
            rssi = (rssi + self.rng.uniform(-2.0, 2.0)).clamp(-85.0, -40.0);
            if k.is_multiple_of(90) {
                let n = self.aps.len();
                let (from, to) = (self.aps[i % n].0.clone(), self.aps[(i + 1) % 2 % n].0.clone());
                let ms = [35.0, 48.0, 62.0, 140.0][self.rng.randint(0, 3) as usize];
                self.sink
                    .with_conn(&mut |c| Self::roam(c, now_unix() - 0.05, &from, &to, ms));
                i = (i + 1) % 2;
                rssi = -55.0;
            }
            let s = self.sample(now_unix(), i, rssi);
            self.sink.with_conn(&mut |c| {
                c.add_sample(s.clone());
            });
        }
    }
}

struct Handle(Mutex<Option<Sender<()>>>);

impl MonitorHandle for Handle {
    fn stop(&self) {
        if let Some(tx) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

fn start_monitor(sink: Arc<dyn ConnSink>, base: &Snapshot) -> Result<Box<dyn MonitorHandle>, String> {
    let mut corp: Vec<&Bss> = base
        .bss
        .iter()
        .filter(|b| b.ssid() == "CORP" && b.band() == "5")
        .collect();
    corp.sort_by_key(|b| -b.rssi);
    let mut aps: Vec<(String, i32)> = corp.iter().map(|b| (b.bssid.clone(), b.channel())).collect();
    if aps.is_empty() {
        aps.push(("02:00:00:00:00:01".into(), 36));
    }
    let m = DemoMonitor {
        sink,
        aps,
        rng: Rng::new(7),
    };
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("demo-conn".into())
        .spawn(move || m.run(rx))
        .map_err(|e| e.to_string())?;
    Ok(Box::new(Handle(Mutex::new(Some(tx)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_and_rng() {
        assert_eq!((demo_rate(-50.0, 0), demo_rate(-49.0, 0)), (1080.9, 1201.0));
        assert_eq!(demo_rate(-85.0, 1), demo_rate(-85.0, 0));
        let r = Rng::new(1);
        assert!((0..1000).all(|_| (-3..=3).contains(&r.randint(-3, 3))));
        assert!(demo_snapshot().bss.len() > 10);
        assert_eq!(tr_demo("x"), "x");
    }
}
