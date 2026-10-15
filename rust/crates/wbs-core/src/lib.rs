//! Ядро Wi-Fi Beacon Scanner 2.x: разбор beacon, правила, состояние программы и её API - без внешних крейтов.
//!
//! Это перенос логики Python-версии 1.x (`wifi_beacon_scanner/`). Совпадение с ней проверяет
//! `tests/contract.rs` по общим эталонам `contract/golden` (см. `contract/README.ru.md`).
//!
//! | Модуль | Что | Откуда в 1.x |
//! |---|---|---|
//! | `ie` | разбор Information Elements | `ie.py` (`parse_ies`, `BssInfo`) |
//! | `model` | BSS: диапазон, канал, защита, шифры; снапшот | `model.py` |
//! | `mcs` | потолок PHY-скорости по beacon | `mcs.py` (`capability`) |
//! | `describe` | дерево IE для вкладки Beacon | `ie.py` (`describe_ies`) |
//! | `amend` | дополнения 802.11 (d e h i k r u v w ...) | `amend.py` |
//! | `rules` | проблемы, свободность и загрузка каналов | `rules.py` |
//! | `row` | строка таблицы сетей | `web/state.py` (`bss_to_dict`) |
//! | `i18n` | русский / английский, подстановки как `%` в Python | `i18n.py`, каталог `contract/i18n/en.json` |
//! | `json` | чтение и запись JSON без serde | - |
//! | `diff` | сравнение «до/после» | `diff.py` |
//! | `oui` | вендор по BSSID (файл manuf) | `oui.py` |
//! | `report` | CSV и снапшот JSON | `report.py` (без HTML/PDF/Excel) |
//! | `prefs` | настройки вида | `web/state.py` (`sanitize_prefs`) |
//! | `clock` | время и ISO 8601 без крейтов | - |
//! | `app` | состояние программы и `/api/*` для окна | `web/state.py`, `web/server.py` |
//! | `win` | скан через wlanapi.dll и мелочи ОС (только Windows) | `scanner_win.py` |

pub mod amend;
pub mod app;
pub mod clock;
pub mod describe;
pub mod diff;
pub mod i18n;
pub mod ie;
pub mod json;
pub mod mcs;
pub mod model;
pub mod oui;
pub mod prefs;
pub mod report;
pub mod row;
pub mod rules;
#[cfg(any(windows, wbs_check_win))]
pub mod win;
