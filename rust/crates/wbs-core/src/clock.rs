//! Время без внешних крейтов: unix-время и ISO 8601 в местном поясе.
//!
//! Смещение пояса (в минутах) даёт платформа: на Windows - `local_offset_min()` из `scan_win`,
//! в тестах и на других ОС - 0, если не задано `WBS_TZ_OFFSET_MIN`.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Дни от 1970-01-01 -> (год, месяц, день). Алгоритм Howard Hinnant (`civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (год, месяц, день) -> дни от 1970-01-01 (Howard Hinnant, `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Время UTC из журнала Windows (`SystemTime="2026-10-15T08:01:02.1234567Z"`) -> unix-время.
/// Как `_time` в winlog.py: `Z` в конце отбрасывается, дробная часть - до 6 знаков; не разобрали - None.
pub fn parse_utc(s: &str) -> Option<f64> {
    let s = s.trim_end_matches('Z');
    if s.is_empty() {
        return None;
    }
    let (head, frac) = match s.split_once('.') {
        Some((h, f)) => (h, Some(&f[..f.char_indices().nth(6).map_or(f.len(), |(i, _)| i)])),
        None => (s, None),
    };
    let us: i64 = match frac {
        None => 0,
        Some(f) if !f.is_empty() && f.len() <= 6 && f.bytes().all(|c| c.is_ascii_digit()) => {
            format!("{f:0<6}").parse().ok()?
        }
        Some(_) => return None,
    };
    let (date, time) = head.split_once('T')?;
    let num = |p: &str, min: usize, max: usize| -> Option<i64> {
        (p.len() >= min && p.len() <= max && p.bytes().all(|c| c.is_ascii_digit())).then(|| p.parse().ok())?
    };
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let (y, mo, dd) = (num(d[0], 4, 4)?, num(d[1], 1, 2)? as u32, num(d[2], 1, 2)? as u32);
    let (hh, mi, ss) = (num(t[0], 1, 2)?, num(t[1], 1, 2)?, num(t[2], 1, 2)?);
    if !(1..=12).contains(&mo) || dd == 0 || dd > days_in_month(y, mo) || hh > 23 || mi > 59 || ss > 59 {
        return None;
    }
    let secs = days_from_civil(y, mo, dd) * 86_400 + hh * 3600 + mi * 60 + ss;
    // как timedelta / timedelta(seconds=1) в Python: целые микросекунды, одно деление
    Some((secs as i128 * 1_000_000 + us as i128) as f64 / 1e6)
}

/// `datetime.fromtimestamp(t).isoformat(timespec="seconds")`: местное время без пояса.
pub fn iso_naive(t: f64, offset_min: i32) -> String {
    let s = t.floor() as i64 + offset_min as i64 * 60;
    let (y, mo, d) = civil_from_days(s.div_euclid(86_400));
    let sod = s.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

/// `now_iso()` из 1.x: местное время с поясом, `2026-10-15T15:00:00+03:00`.
pub fn iso_with_offset(t: f64, offset_min: i32) -> String {
    let sign = if offset_min < 0 { '-' } else { '+' };
    let a = offset_min.unsigned_abs();
    format!("{}{sign}{:02}:{:02}", iso_naive(t, offset_min), a / 60, a % 60)
}

/// Смещение из переменной окружения (для разработки на Linux и тестов).
pub fn env_offset_min() -> i32 {
    std::env::var("WBS_TZ_OFFSET_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso() {
        assert_eq!(iso_naive(0.0, 0), "1970-01-01T00:00:00");
        // 2026-10-15 12:00:00 UTC
        assert_eq!(iso_naive(1_792_065_600.7, 180), "2026-10-15T15:00:00");
        assert_eq!(iso_with_offset(1_792_065_600.0, 180), "2026-10-15T15:00:00+03:00");
        assert_eq!(iso_with_offset(1_792_065_600.0, -330), "2026-10-15T06:30:00-05:30");
        assert_eq!(iso_naive(951_782_400.0, 0), "2000-02-29T00:00:00");
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(parse_utc("2026-10-15T12:00:00Z"), Some(1_792_065_600.0));
        assert_eq!(parse_utc("2026-10-15T12:00:00.1234567Z"), Some(1_792_065_600.123456));
        assert_eq!(parse_utc("2026-02-30T12:00:00"), None);
        assert_eq!(parse_utc("2026-10-15T12:00:00."), None);
        assert_eq!(parse_utc(""), None);
    }
}
