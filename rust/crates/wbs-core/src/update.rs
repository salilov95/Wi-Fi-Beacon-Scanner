//! Проверка новой версии на GitHub Releases - только по кнопке. Перенос `wifi_beacon_scanner/update.py`.
//! Запрос делает оболочка (на Windows - WinHTTP, `win::https_get`); здесь - разбор ответа.

use crate::i18n::{tr, trf, Arg};
use crate::json::{self, Value};

pub const API_HOST: &str = "api.github.com";
pub const API_PATH: &str = "/repos/salilov95/Wi-Fi-Beacon-Scanner/releases/latest";
pub const RELEASES: &str = "https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases";

/// `v1.2.3-beta` -> (1, 2, 3); не версия - None.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let s = v.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut it = s.splitn(3, '.');
    let a = it.next()?;
    let b = it.next()?;
    let c = it.next()?;
    let digits = |x: &str| -> Option<u64> {
        let n = x.bytes().take_while(u8::is_ascii_digit).count();
        (n > 0).then(|| x[..n].parse().ok())?
    };
    // первые два числа - целиком цифры, третье - цифры в начале (дальше может быть -beta)
    if !a.bytes().all(|c| c.is_ascii_digit()) || !b.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((digits(a)?, digits(b)?, digits(c)?))
}

/// `{"current", "latest", "newer", "url", "published", "error"}`; `fetched` - тело ответа GitHub или ошибка сети.
pub fn check(current: &str, fetched: Result<String, String>) -> Value {
    let mut latest = Value::Null;
    let mut newer = false;
    let mut url = Value::Str(RELEASES.into());
    let mut published = Value::Null;
    let mut error = String::new();
    match fetched.and_then(|body| json::parse(&body)) {
        Err(e) => error = trf("не удалось связаться с GitHub: %s", &[Arg::S(e)]),
        Ok(d) => {
            let tag = match d.get("tag_name") {
                Some(Value::Str(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_json(),
            };
            let bare = tag.trim_start_matches('v');
            if !bare.is_empty() {
                latest = bare.into();
            }
            if let Some(Value::Str(u)) = d
                .get("html_url")
                .filter(|u| !matches!(u, Value::Str(s) if s.is_empty()))
            {
                url = u.as_str().into();
            }
            published = d.get("published_at").cloned().unwrap_or(Value::Null);
            let (a, b) = (parse_version(current), parse_version(&tag));
            newer = matches!((a, b), (Some(a), Some(b)) if b > a);
            if b.is_none() {
                error = tr("GitHub не вернул номер версии");
            }
        }
    }
    Value::Obj(vec![
        ("current".into(), current.into()),
        ("latest".into(), latest),
        ("newer".into(), newer.into()),
        ("url".into(), url),
        ("published".into(), published),
        ("error".into(), error.into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_1x() {
        // те же случаи, что tests/test_v100.py в 1.x
        let d = check(
            "0.9.0",
            Ok(r#"{"tag_name":"v1.0.0","html_url":"https://x/r/1.0.0","published_at":"2026-01-01T00:00:00Z"}"#.into()),
        );
        assert_eq!(
            d.to_json(),
            r#"{"current":"0.9.0","latest":"1.0.0","newer":true,"url":"https://x/r/1.0.0","published":"2026-01-01T00:00:00Z","error":""}"#
        );
        assert_eq!(
            check("1.0.0", Ok(r#"{"tag_name":"v1.0.0"}"#.into())).get("newer"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            check("1.2.0", Ok(r#"{"tag_name":"v1.10.0"}"#.into())).get("newer"),
            Some(&Value::Bool(true))
        );
        let e = check("1.0.0", Err("timed out".into()));
        assert!(e.get("error").and_then(Value::as_str).unwrap().contains("timed out"));
        assert_eq!(e.get("latest"), Some(&Value::Null));
        assert_eq!(parse_version("v1.2.3-beta"), Some((1, 2, 3)));
        assert_eq!(parse_version("2.0.0-alpha.2"), Some((2, 0, 0)));
        assert_eq!(parse_version("latest"), None);
        let x = check("2.0.0-alpha.2", Ok(r#"{"tag_name":"latest"}"#.into()));
        assert!(!x.get("error").and_then(Value::as_str).unwrap().is_empty());
    }
}
