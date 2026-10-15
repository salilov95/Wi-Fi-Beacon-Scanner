//! Ядро Wi-Fi Beacon Scanner 2.x: разбор beacon, модель BSS, MCS - без ОС и без внешних крейтов.
//!
//! Это перенос логики Python-версии 1.x (`wifi_beacon_scanner/`). Совпадение с ней проверяет
//! `tests/contract.rs` по общим эталонам `contract/golden` (см. `contract/README.ru.md`).
//!
//! | Модуль | Что | Откуда в 1.x |
//! |---|---|---|
//! | `ie` | разбор Information Elements | `ie.py` (`parse_ies`, `BssInfo`) |
//! | `model` | BSS: диапазон, канал, защита, шифры; снапшот | `model.py` |
//! | `mcs` | потолок PHY-скорости по beacon | `mcs.py` (`capability`) |
//! | `row` | строка таблицы сетей | `web/state.py` (`bss_to_dict`) |
//! | `json` | чтение и запись JSON без serde | - |

pub mod ie;
pub mod json;
pub mod mcs;
pub mod model;
pub mod row;
