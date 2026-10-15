//! Правила диагностики (вкладка «Проблемы»), свободность и загрузка каналов.
//!
//! Перенос `wifi_beacon_scanner/rules.py`. Порядок групп, сортировки и тексты - как в Python, чтобы
//! результат совпадал с эталонами `contract/golden` строка в строку. Места, где Rust по умолчанию ведёт
//! себя иначе, помечены: `max()` в Python берёт ПЕРВЫЙ максимум (здесь `first_max`), списки в тексте
//! пишутся как в Python (`py_list`), `%.0f` округляет «ничьи» к чётному (так же делает `format!`).

use crate::i18n::{py_list, tr, trf};
use crate::json::Value;
use crate::model::Bss;

pub const CRITICAL: &str = "critical";
pub const WARNING: &str = "warning";
pub const INFO: &str = "info";

fn severity_order(s: &str) -> u8 {
    match s {
        CRITICAL => 0,
        WARNING => 1,
        _ => 2,
    }
}

/// Пороги (как `Thresholds` в Python).
#[derive(Debug, Clone, PartialEq)]
pub struct Thresholds {
    /// дБм: ниже - сигнал слабый для работы клиентов.
    pub weak_rssi: i32,
    /// дБм: «сильный» сосед для расчёта наложения каналов.
    pub strong_rssi: i32,
    /// дБм: соседей слабее этого на канале не считаем.
    pub cci_rssi: i32,
    /// Столько радио на одном канале = предупреждение.
    pub cci_warn_count: usize,
    /// % занятости канала по QBSS Load.
    pub util_warn: f64,
    pub util_crit: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            weak_rssi: -75,
            strong_rssi: -70,
            cci_rssi: -80,
            cci_warn_count: 4,
            util_warn: 50.0,
            util_crit: 70.0,
        }
    }
}

/// Проблема.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: &'static str,
    pub code: String,
    pub title: String,
    pub detail: String,
    pub ssid: String,
    pub bssids: Vec<String>,
    pub recommendation: String,
}

impl Finding {
    fn new(severity: &'static str, code: &str, title: String, detail: String) -> Finding {
        Finding {
            severity,
            code: code.into(),
            title,
            detail,
            ssid: String::new(),
            bssids: vec![],
            recommendation: String::new(),
        }
    }
    fn ssid(mut self, s: &str) -> Self {
        self.ssid = s.into();
        self
    }
    fn bssids(mut self, items: &[&Bss]) -> Self {
        self.bssids = macs(items);
        self
    }
    fn rec(mut self, r: &str) -> Self {
        self.recommendation = tr(r);
        self
    }
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("severity".into(), self.severity.into()),
            ("code".into(), self.code.as_str().into()),
            ("title".into(), self.title.as_str().into()),
            ("detail".into(), self.detail.as_str().into()),
            ("ssid".into(), self.ssid.as_str().into()),
            ("bssids".into(), self.bssids.clone().into()),
            ("recommendation".into(), self.recommendation.as_str().into()),
        ])
    }
}

fn macs(items: &[&Bss]) -> Vec<String> {
    items.iter().map(|b| b.bssid.clone()).collect()
}

fn is_focus(b: &Bss, focus: &[String]) -> bool {
    focus.is_empty() || focus.contains(&b.ssid())
}

/// Группировка с сохранением порядка первого появления ключа (как dict/defaultdict в Python).
fn group_by<'a, K: PartialEq>(
    items: impl IntoIterator<Item = &'a Bss>,
    key: impl Fn(&Bss) -> K,
) -> Vec<(K, Vec<&'a Bss>)> {
    let mut out: Vec<(K, Vec<&Bss>)> = vec![];
    for b in items {
        let k = key(b);
        match out.iter_mut().find(|(x, _)| *x == k) {
            Some((_, v)) => v.push(b),
            None => out.push((k, vec![b])),
        }
    }
    out
}

/// Первый элемент с максимальным ключом (как `max()` в Python; `Iterator::max_by` отдал бы последний).
fn first_max<'a, T: PartialOrd>(items: &[&'a Bss], key: impl Fn(&Bss) -> T) -> &'a Bss {
    let mut best = items[0];
    for &b in &items[1..] {
        if key(b) > key(best) {
            best = b;
        }
    }
    best
}

fn by_ssid<'a>(bss: &'a [Bss], focus: &[String]) -> Vec<(String, Vec<&'a Bss>)> {
    group_by(bss.iter().filter(|b| !b.hidden() && is_focus(b, focus)), |b| b.ssid())
}

/// Ключ радиомодуля AP: тот же диапазон, канал, ширина и центр полосы, а BSSID совпадает во всех битах,
/// кроме младших 4 бит последнего октета (см. `radio_key` в rules.py).
pub fn radio_key(b: &Bss) -> (&'static str, i32, u32, u64, String) {
    let mac = b.bssid.to_lowercase();
    (
        b.band(),
        b.channel(),
        b.info.width_mhz(),
        b.center_channel().to_bits(),
        mac.chars().take(16).collect(),
    )
}

/// BSS, разложенные по радиомодулям (порядок - по первому появлению).
pub fn group_radios<'a>(items: &[&'a Bss]) -> Vec<Vec<&'a Bss>> {
    group_by(items.iter().copied(), radio_key)
        .into_iter()
        .map(|(_, v)| v)
        .collect()
}

// ---------------------------------------------------------------- безопасность
fn rule_security(bss: &[Bss], _th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for ((ssid, sec), items) in group_by(bss.iter().filter(|b| is_focus(b, focus)), |b| {
        (b.ssid_display(), b.security())
    }) {
        let base = |f: Finding| f.ssid(&ssid).bssids(&items);
        if sec == "Open" {
            out.push(base(Finding::new(
                WARNING,
                "SEC_OPEN",
                tr("Открытая сеть без шифрования"),
                trf("Сеть «%s» не использует шифрование.", &[(&ssid).into()]),
            ))
            .rec("Если сеть гостевая - рассмотреть OWE (Enhanced Open) или captive portal; для корпоративной - WPA2/WPA3-Enterprise."));
        } else if sec == "WEP" {
            out.push(
                base(Finding::new(
                    CRITICAL,
                    "SEC_WEP",
                    "WEP".into(),
                    trf(
                        "Сеть «%s»: установлен бит Privacy, но нет RSN/WPA IE - это WEP.",
                        &[(&ssid).into()],
                    ),
                ))
                .rec("WEP взламывается за минуты; перевести на WPA2/WPA3."),
            );
        } else if sec.starts_with("WPA1") {
            out.push(
                base(Finding::new(
                    CRITICAL,
                    "SEC_WPA1_ONLY",
                    tr("Только WPA1"),
                    trf(
                        "Сеть «%s» вещает только WPA1 (vendor IE), RSN отсутствует.",
                        &[(&ssid).into()],
                    ),
                ))
                .rec("Включить WPA2 (CCMP) минимум."),
            );
        } else if sec.ends_with("+WPA1") {
            out.push(
                base(Finding::new(
                    WARNING,
                    "SEC_WPA1_MIXED",
                    tr("Включён режим совместимости с WPA1"),
                    trf(
                        "Сеть «%s» объявляет и RSN, и WPA1 IE (%s).",
                        &[(&ssid).into(), (&sec).into()],
                    ),
                ))
                .rec("Отключить WPA1/TKIP, если нет устройств, которым он нужен."),
            );
        }
        let mut ciphers: Vec<String> = items.iter().flat_map(|b| b.ciphers()).collect();
        ciphers.sort();
        ciphers.dedup();
        if ciphers.iter().any(|c| c == "TKIP") && !sec.starts_with("WPA1") {
            out.push(base(Finding::new(
                WARNING,
                "SEC_TKIP",
                tr("Разрешён шифр TKIP"),
                trf("Сеть «%s»: pairwise-шифры %s.", &[(&ssid).into(), ciphers.join(", ").into()]),
            ))
            .rec("TKIP отключает высокие скорости 802.11n+ у многих клиентов и считается устаревшим; оставить только CCMP/GCMP."));
        }
        if sec.contains("Enterprise") {
            let no_pmf: Vec<&Bss> = items
                .iter()
                .copied()
                .filter(|b| b.info.rsn.as_ref().is_some_and(|r| !r.mfp_capable))
                .collect();
            if !no_pmf.is_empty() {
                out.push(
                    Finding::new(
                        INFO,
                        "SEC_NO_PMF",
                        tr("Защита management-кадров (PMF/802.11w) не включена"),
                        trf(
                            "Сеть «%s»: у %d BSS не выставлен бит MFPC.",
                            &[(&ssid).into(), no_pmf.len().into()],
                        ),
                    )
                    .ssid(&ssid)
                    .bssids(&no_pmf)
                    .rec("Включить PMF в режиме optional (или required, если все клиенты поддерживают)."),
                );
            }
        }
        if sec.contains("WPA2/WPA3-Personal") {
            out.push(
                base(Finding::new(
                    INFO,
                    "SEC_TRANSITION",
                    "WPA2/WPA3 transition mode".into(),
                    trf("Сеть «%s» принимает и PSK, и SAE.", &[(&ssid).into()]),
                ))
                .rec("Это нормальный переходный режим; понижение до WPA2 возможно у клиентов, не поддерживающих SAE."),
            );
        }
        let wps: Vec<&Bss> = items.iter().copied().filter(|b| b.info.wps).collect();
        if !wps.is_empty() {
            out.push(
                Finding::new(
                    INFO,
                    "SEC_WPS",
                    tr("Включён WPS"),
                    trf(
                        "Сеть «%s»: WPS IE присутствует у %d BSS.",
                        &[(&ssid).into(), wps.len().into()],
                    ),
                )
                .ssid(&ssid)
                .bssids(&wps)
                .rec("Для корпоративной сети WPS не нужен - выключить."),
            );
        }
    }
    out
}

// ---------------------------------------------------- согласованность / роуминг
fn rule_roaming(bss: &[Bss], _th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for (ssid, items) in by_ssid(bss, focus) {
        if items.len() < 2 {
            continue;
        }
        let mut secs: Vec<String> = items.iter().map(|b| b.security()).collect();
        secs.sort();
        secs.dedup();
        if secs.len() > 1 {
            out.push(
                Finding::new(
                    WARNING,
                    "ROAM_SEC_MISMATCH",
                    tr("Разная безопасность у BSS одного SSID"),
                    format!("SSID «{ssid}»: {}.", secs.join("; ")),
                )
                .ssid(&ssid)
                .bssids(&items)
                .rec("Клиент, выбравший один BSS, может не подключиться к другому. Проверить профиль SSID на контроллере."),
            );
        }
        let mut countries: Vec<String> = items
            .iter()
            .filter_map(|b| b.info.country.clone())
            .filter(|c| !c.is_empty())
            .collect();
        countries.sort();
        countries.dedup();
        if countries.len() > 1 {
            out.push(
                Finding::new(
                    WARNING,
                    "ROAM_COUNTRY_MISMATCH",
                    tr("Разные country code у BSS одного SSID"),
                    format!("SSID «{ssid}»: {}.", countries.join(", ")),
                )
                .ssid(&ssid)
                .bssids(&items)
                .rec("Country code влияет на набор каналов и мощность; привести к одному значению."),
            );
        }
        type Has = fn(&Bss) -> bool;
        let checks: [(Has, &str, &str, bool); 3] = [
            (|b| b.info.dot11r(), "802.11r (FT)", "ROAM_11R", true),
            (|b| b.info.dot11k(), "802.11k", "ROAM_11K", false),
            (|b| b.info.dot11v(), "802.11v", "ROAM_11V", false),
        ];
        for (has, label, code, is_r) in checks {
            let have: Vec<&Bss> = items.iter().copied().filter(|b| has(b)).collect();
            let miss: Vec<&Bss> = items.iter().copied().filter(|b| !has(b)).collect();
            if !have.is_empty() && !miss.is_empty() {
                out.push(
                    Finding::new(
                        WARNING,
                        &format!("{code}_PARTIAL"),
                        trf("%s включён не на всех BSS", &[label.into()]),
                        trf(
                            "SSID «%s»: есть у %d, нет у %d BSS.",
                            &[(&ssid).into(), have.len().into(), miss.len().into()],
                        ),
                    )
                    .ssid(&ssid)
                    .bssids(&miss)
                    .rec("Проверить, что AP-группы/профили одинаковы."),
                );
            } else if have.is_empty() {
                let is_ent = items.iter().any(|b| b.security().contains("Enterprise"));
                if is_r && is_ent {
                    out.push(
                        Finding::new(
                            INFO,
                            &format!("{code}_OFF"),
                            tr("802.11r не объявлен"),
                            trf("SSID «%s» (Enterprise, %d BSS): Mobility Domain IE не найден.", &[(&ssid).into(), items.len().into()]),
                        )
                        .ssid(&ssid)
                        .bssids(&items)
                        .rec("Без FT каждый роуминг - это полная 802.1X-аутентификация, если не работают PMK caching/OKC. Включать FT стоит после проверки, что клиенты его поддерживают."),
                    );
                } else if !is_r {
                    out.push(
                        Finding::new(
                            INFO,
                            &format!("{code}_OFF"),
                            trf("%s не объявлен", &[label.into()]),
                            trf("SSID «%s»: нужный IE не найден ни у одного из %d BSS.", &[(&ssid).into(), items.len().into()]),
                        )
                        .ssid(&ssid)
                        .bssids(&items)
                        .rec("Помогает клиентам выбирать лучшую AP при роуминге; включать, если контроллер это поддерживает."),
                    );
                }
            }
        }
        let mut beacons: Vec<u32> = items.iter().map(|b| b.beacon_interval).collect();
        beacons.sort();
        beacons.dedup();
        let mut dtims: Vec<u8> = items.iter().filter_map(|b| b.info.dtim_period).collect();
        dtims.sort();
        dtims.dedup();
        if beacons.len() > 1 || dtims.len() > 1 {
            out.push(
                Finding::new(
                    INFO,
                    "ROAM_TIMERS",
                    tr("Разные beacon interval / DTIM у BSS одного SSID"),
                    format!("SSID «{ssid}»: beacon={}, DTIM={}.", py_list(&beacons), py_list(&dtims)),
                )
                .ssid(&ssid)
                .bssids(&items),
            );
        }
    }
    out
}

// --------------------------------------------------------------------- радио
fn rule_signal(bss: &[Bss], th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for (ssid, items) in by_ssid(bss, focus) {
        let best = first_max(&items, |b| b.rssi);
        if best.rssi < th.weak_rssi {
            out.push(
                Finding::new(
                    WARNING,
                    "RF_WEAK",
                    tr("Слабый сигнал"),
                    trf("SSID «%s»: лучший BSS %d дБм (порог %d).", &[(&ssid).into(), best.rssi.into(), th.weak_rssi.into()]),
                )
                .ssid(&ssid)
                .bssids(&[best])
                .rec("В этой точке покрытия клиенты будут работать на низких скоростях; проверить расположение AP или мощность."),
            );
        }
    }
    out
}

fn stations_str(b: &Bss) -> String {
    b.info
        .qbss_stations
        .map(|s| s.to_string())
        .unwrap_or_else(|| "None".into())
}

fn rule_utilization(bss: &[Bss], th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let rep: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.info.qbss_util_pct.is_some() && is_focus(b, focus))
        .collect();
    for radio in group_radios(&rep) {
        let b = first_max(&radio, |x| x.info.qbss_util_pct.unwrap_or(0.0));
        let u = b.info.qbss_util_pct.unwrap_or(0.0);
        let sev = if u >= th.util_crit {
            CRITICAL
        } else if u >= th.util_warn {
            WARNING
        } else {
            continue;
        };
        let (detail, ssid) = if radio.len() == 1 {
            (
                trf(
                    "%s (%s, канал %d, %s ГГц): занято %.0f%% эфира, станций: %s.",
                    &[
                        b.ssid_display().into(),
                        (&b.bssid).into(),
                        b.channel().into(),
                        b.band().into(),
                        u.into(),
                        stations_str(b).into(),
                    ],
                ),
                b.ssid_display(),
            )
        } else {
            let ssid = radio.iter().map(|x| x.ssid_display()).collect::<Vec<_>>().join(", ");
            let st = radio.iter().map(|x| stations_str(x)).collect::<Vec<_>>().join(", ");
            (
                trf(
                    "%s (одно радио, BSS: %d, канал %d, %s ГГц): занято %.0f%% эфира, станций по BSS: %s.",
                    &[
                        (&ssid).into(),
                        radio.len().into(),
                        b.channel().into(),
                        b.band().into(),
                        u.into(),
                        st.into(),
                    ],
                ),
                ssid,
            )
        };
        out.push(
            Finding::new(sev, "RF_UTIL", tr("Высокая загрузка канала"), detail)
                .ssid(&ssid)
                .bssids(&radio)
                .rec("Цифра берётся из QBSS Load самой AP. Проверить число клиентов, смену канала/ширины, перенос клиентов на 5 ГГц."),
        );
    }
    out
}

fn rule_cochannel(bss: &[Bss], th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let mut chans = group_by(bss.iter().filter(|b| b.rssi >= th.cci_rssi), |b| {
        (b.band(), b.channel())
    });
    chans.sort_by(|a, b| a.0.cmp(&b.0)); // sorted(chans.items()): по диапазону (строкой), затем по каналу
    for ((band, ch), items) in chans {
        let radios = group_radios(&items).len();
        if radios < th.cci_warn_count {
            continue;
        }
        if !focus.is_empty() && !items.iter().any(|b| focus.contains(&b.ssid())) {
            continue;
        }
        let heard = if radios == items.len() {
            format!("{} BSS", items.len())
        } else {
            trf("%d радио (BSS: %d)", &[radios.into(), items.len().into()])
        };
        let mut names: Vec<String> = items.iter().map(|b| b.ssid_display()).collect();
        names.sort();
        names.dedup();
        names.truncate(6);
        out.push(
            Finding::new(
                WARNING,
                "RF_COCHANNEL",
                tr("Много BSS на одном канале"),
                trf(
                    "%s ГГц, канал %d: слышно %s сильнее %d дБм (SSID: %s).",
                    &[
                        band.into(),
                        ch.into(),
                        heard.into(),
                        th.cci_rssi.into(),
                        names.join(", ").into(),
                    ],
                ),
            )
            .bssids(&items)
            .rec("Все они делят эфир (CSMA/CA). Рассмотреть другой канал, меньшую ширину или меньшую мощность."),
        );
    }
    out
}

fn sorted_channels(items: &[&Bss]) -> String {
    let mut ch: Vec<i32> = items.iter().map(|b| b.channel()).collect();
    ch.sort();
    ch.dedup();
    ch.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
}

fn rule_24ghz(bss: &[Bss], th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let nonstd: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.band() == "2.4" && ![1, 6, 11].contains(&b.channel()) && is_focus(b, focus))
        .collect();
    if !nonstd.is_empty() {
        out.push(
            Finding::new(
                WARNING,
                "RF_24_NONSTD",
                tr("2.4 ГГц: канал не 1/6/11"),
                trf("Каналы: %s.", &[sorted_channels(&nonstd).into()]),
            )
            .bssids(&nonstd)
            .rec("Каналы 2.4 ГГц перекрываются; вне 1/6/11 AP мешает сразу двум соседним."),
        );
    }
    let wide: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.band() == "2.4" && b.info.width_mhz() >= 40 && is_focus(b, focus))
        .collect();
    if !wide.is_empty() {
        out.push(
            Finding::new(
                WARNING,
                "RF_24_40MHZ",
                tr("2.4 ГГц: ширина канала 40 МГц"),
                trf("BSS с 40 МГц: %d.", &[wide.len().into()]),
            )
            .bssids(&wide)
            .rec("В 2.4 ГГц 40 МГц занимает почти полдиапазона; оставить 20 МГц."),
        );
    }
    let strong: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.band() == "2.4" && b.rssi >= th.strong_rssi)
        .collect();
    let mut pairs: Vec<(i32, i32)> = vec![];
    for (i, a) in strong.iter().enumerate() {
        for c in &strong[i + 1..] {
            let d = (a.channel() - c.channel()).abs();
            if (1..=4).contains(&d) {
                let p = (a.channel().min(c.channel()), a.channel().max(c.channel()));
                if !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }
    }
    pairs.sort();
    if !pairs.is_empty() {
        let txt = pairs
            .iter()
            .map(|(x, y)| format!("{x}/{y}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            Finding::new(WARNING, "RF_24_OVERLAP", tr("2.4 ГГц: сильные BSS на перекрывающихся каналах"), trf("Пары каналов: %s.", &[txt.into()]))
                .bssids(&strong)
                .rec("Перекрытие хуже, чем совпадение каналов: устройства не могут договориться через CSMA/CA и воспринимают друг друга как шум."),
        );
    }
    out
}

fn rule_dfs(bss: &[Bss], _th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let dfs: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.band() == "5" && (52..=144).contains(&b.channel()) && is_focus(b, focus))
        .collect();
    if dfs.is_empty() {
        return vec![];
    }
    vec![Finding::new(INFO, "RF_DFS", tr("5 ГГц: используются DFS-каналы"), trf("Каналы: %s.", &[sorted_channels(&dfs).into()]))
        .bssids(&dfs)
        .rec("При обнаружении радара AP обязана уйти с канала; если есть жалобы на кратковременные пропадания - сверить с логами радара на контроллере.")]
}

// ------------------------------------------------------------------- гигиена
fn rule_hygiene(bss: &[Bss], _th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    let legacy_basic: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.band() == "2.4" && is_focus(b, focus))
        .filter(|b| {
            b.info
                .rates
                .iter()
                .any(|&(mbps, basic)| basic && [1.0, 2.0, 5.5, 11.0].contains(&mbps))
        })
        .collect();
    if !legacy_basic.is_empty() {
        out.push(
            Finding::new(INFO, "HYG_BASIC_RATES", tr("2.4 ГГц: 802.11b-скорости в basic rate set"), format!("BSS: {}.", legacy_basic.len()))
                .bssids(&legacy_basic)
                .rec("Пока 1/2/5.5/11 Мбит/с обязательны, служебные кадры уходят на низкой скорости и занимают эфир. Отключить, если b-клиентов нет."),
        );
    }
    let prot: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.info.ht_protection != 0 && is_focus(b, focus))
        .collect();
    if !prot.is_empty() {
        let mut modes: Vec<u8> = prot.iter().map(|b| b.info.ht_protection).collect();
        modes.sort();
        modes.dedup();
        out.push(
            Finding::new(
                INFO,
                "HYG_HT_PROT",
                tr("HT protection включён"),
                format!("BSS: {} (mode {}).", prot.len(), py_list(&modes)),
            )
            .bssids(&prot)
            .rec("AP видит legacy-клиентов или соседние non-HT сети; это снижает пропускную способность."),
        );
    }
    let legacy: Vec<&Bss> = bss
        .iter()
        .filter(|b| b.info.generation() == 0 && is_focus(b, focus))
        .collect();
    if !legacy.is_empty() {
        out.push(
            Finding::new(
                WARNING,
                "HYG_LEGACY_PHY",
                tr("BSS без HT (только 802.11a/b/g)"),
                format!("BSS: {}.", legacy.len()),
            )
            .bssids(&legacy)
            .rec("Максимум 54 Мбит/с; проверить, что это не отключённый радиомодуль или старая AP."),
        );
    }
    for (ssid, items) in by_ssid(bss, focus) {
        if items.iter().all(|b| b.band() == "2.4") {
            out.push(
                Finding::new(
                    INFO,
                    "HYG_24_ONLY",
                    tr("SSID слышен только в 2.4 ГГц"),
                    format!("SSID «{ssid}»."),
                )
                .ssid(&ssid)
                .bssids(&items)
                .rec("Если сеть должна быть и в 5 ГГц - проверить радио 5 ГГц и привязку SSID."),
            );
        }
    }
    let hidden: Vec<&Bss> = bss.iter().filter(|b| b.hidden() && is_focus(b, focus)).collect();
    if !hidden.is_empty() {
        out.push(
            Finding::new(
                INFO,
                "HYG_HIDDEN",
                tr("Скрытые SSID"),
                trf("BSS со скрытым SSID: %d.", &[hidden.len().into()]),
            )
            .bssids(&hidden)
            .rec("Скрытие SSID не защита; клиенты при этом шлют probe с именем сети."),
        );
    }
    out
}

/// Все проблемы, отсортированные по важности, коду и SSID.
pub fn analyze(bss: &[Bss], th: &Thresholds, focus: &[String]) -> Vec<Finding> {
    type Rule = fn(&[Bss], &Thresholds, &[String]) -> Vec<Finding>;
    let rules: [Rule; 8] = [
        rule_security,
        rule_roaming,
        rule_signal,
        rule_utilization,
        rule_cochannel,
        rule_24ghz,
        rule_dfs,
        rule_hygiene,
    ];
    let mut all: Vec<Finding> = rules.iter().flat_map(|r| r(bss, th, focus)).collect();
    all.sort_by(|a, b| {
        (severity_order(a.severity), &a.code, &a.ssid).cmp(&(severity_order(b.severity), &b.code, &b.ssid))
    });
    all
}

// ---------------------------------------------------------------- каналы

/// Свободность одного канала (`channel_advice`).
#[derive(Debug, Clone, PartialEq)]
pub struct Advice {
    pub channel: i32,
    pub dbm: f64,
    pub count: usize,
    pub radios: usize,
    pub util: f64,
    pub dfs: bool,
    pub busy: bool,
    pub best: bool,
}

impl Advice {
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("channel".into(), self.channel.into()),
            ("dbm".into(), self.dbm.into()),
            ("count".into(), self.count.into()),
            ("radios".into(), self.radios.into()),
            ("util".into(), self.util.into()),
            ("dfs".into(), self.dfs.into()),
            ("busy".into(), self.busy.into()),
            ("best".into(), self.best.into()),
        ])
    }
}

/// Оценка свободности каналов: суммарная мощность соседей (по радиомодулям), чья полоса накрывает канал.
pub fn channel_advice(bss: &[Bss], band: &str, busy_util: f64) -> Vec<Advice> {
    let (cands, margin): (&[i32], f64) = match band {
        "2.4" => (&[1, 6, 11], 2.5),
        "5" => (&[36, 40, 44, 48, 149, 153, 157, 161], 2.0),
        _ => return vec![],
    };
    let near = |b: &Bss, c: i32| (b.center_channel() - c as f64).abs() < b.info.width_mhz() as f64 / 10.0 + margin;
    let mut rows: Vec<Advice> = cands
        .iter()
        .map(|&c| {
            let es: Vec<&Bss> = bss
                .iter()
                .filter(|b| b.band() == band && b.rssi >= -95 && near(b, c))
                .collect();
            let radios = group_radios(&es);
            let energy: f64 = radios
                .iter()
                .map(|r| 10f64.powf(r.iter().map(|b| b.rssi).max().unwrap_or(-120) as f64 / 10.0))
                .sum();
            let dbm = if energy > 0.0 {
                crate::ie::round1(10.0 * energy.log10())
            } else {
                -120.0
            };
            let util = es
                .iter()
                .map(|b| b.info.qbss_util_pct.unwrap_or(0.0))
                .fold(0.0, f64::max);
            Advice {
                channel: c,
                dbm,
                count: es.len(),
                radios: radios.len(),
                util: crate::ie::round1(util),
                dfs: band == "5" && (52..=144).contains(&c),
                busy: false,
                best: false,
            }
        })
        .collect();
    for r in &mut rows {
        r.busy = r.util >= busy_util;
    }
    rows.sort_by(|a, b| {
        (a.busy, a.dbm, a.radios)
            .partial_cmp(&(b.busy, b.dbm, b.radios))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (i, r) in rows.iter_mut().enumerate() {
        r.best = i == 0;
    }
    rows
}

/// Уровень загрузки: ключ и подпись (`util_level`).
pub fn util_level(u: f64) -> (&'static str, String) {
    for (lo, key, label) in [
        (70.0, "crit", "перегружен"),
        (50.0, "high", "высокая"),
        (30.0, "mid", "умеренная"),
        (0.0, "low", "свободен"),
    ] {
        if u >= lo {
            return (key, tr(label));
        }
    }
    ("low", tr("свободен"))
}

/// Загрузка каналов по QBSS Load (`channel_utilization` без истории): `{"channels": [...], "no_data": [...]}`.
pub fn channel_utilization(bss: &[Bss]) -> Value {
    let mut channels: Vec<(f64, &'static str, i32, Value)> = vec![];
    let mut no_data: Vec<(&'static str, i32, Value)> = vec![];
    for ((band, ch), items) in group_by(bss.iter(), |b| (b.band(), b.channel())) {
        let rep: Vec<&Bss> = items
            .iter()
            .copied()
            .filter(|b| b.info.qbss_util_pct.is_some())
            .collect();
        if rep.is_empty() {
            no_data.push((
                band,
                ch,
                Value::Obj(vec![
                    ("band".into(), band.into()),
                    ("channel".into(), ch.into()),
                    ("bss".into(), items.len().into()),
                ]),
            ));
            continue;
        }
        let vals: Vec<f64> = rep.iter().map(|b| b.info.qbss_util_pct.unwrap_or(0.0)).collect();
        let mx = vals.iter().copied().fold(f64::MIN, f64::max);
        let (key, label) = util_level(mx);
        let mut aps: Vec<&&Bss> = rep.iter().collect();
        // sorted(..., key=lambda a: -a["util"]) - стабильно, большие первыми
        aps.sort_by(|a, b| {
            b.info
                .qbss_util_pct
                .partial_cmp(&a.info.qbss_util_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let aps_v = Value::Arr(
            aps.iter()
                .map(|b| {
                    Value::Obj(vec![
                        ("bssid".into(), b.bssid.as_str().into()),
                        ("ssid".into(), b.ssid_display().into()),
                        ("util".into(), b.info.qbss_util_pct.into()),
                        ("stations".into(), b.info.qbss_stations.into()),
                    ])
                })
                .collect(),
        );
        let stations: u64 = rep.iter().map(|b| b.info.qbss_stations.unwrap_or(0) as u64).sum();
        let avg = crate::ie::round1(vals.iter().sum::<f64>() / vals.len() as f64);
        channels.push((
            mx,
            band,
            ch,
            Value::Obj(vec![
                ("band".into(), band.into()),
                ("channel".into(), ch.into()),
                ("max".into(), mx.into()),
                ("avg".into(), avg.into()),
                ("level".into(), key.into()),
                ("label".into(), label.into()),
                ("reporting".into(), rep.len().into()),
                ("bss".into(), items.len().into()),
                ("stations".into(), Value::Int(stations as i64)),
                ("aps".into(), aps_v),
                ("series".into(), Value::Arr(vec![])),
            ]),
        ));
    }
    channels.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(b.1))
            .then(a.2.cmp(&b.2))
    });
    no_data.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
    Value::Obj(vec![
        (
            "channels".into(),
            Value::Arr(channels.into_iter().map(|c| c.3).collect()),
        ),
        ("no_data".into(), Value::Arr(no_data.into_iter().map(|c| c.2).collect())),
    ])
}
