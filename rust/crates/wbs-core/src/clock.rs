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
    }
}
