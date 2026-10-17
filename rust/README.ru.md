# Wi-Fi Beacon Scanner 2.x (Rust + Tauri 2)

[English](README.md) · **Русский**

Текущая версия программы (с 2.0.0): своё окно вместо локального сервера и окна Edge, один небольшой exe; дальше
Linux и macOS. Версия 1.x на Python (`wifi_beacon_scanner/` в корне репозитория) - эталон, по которому строятся
эталонные файлы; её исправления выпускаются из ветки `1.x`. Сборка, тесты и выпуск -
[docs/ru/development.md](../docs/ru/development.md).

## Что здесь

| Крейт | Что | Состояние |
|---|---|---|
| `crates/wbs-core` | разбор beacon (IE), модель BSS, защита, MCS, дерево IE для вкладки Beacon, дополнения 802.11, проблемы, свободность и загрузка каналов, переводы; журнал подключения и сессии, журнал Windows, проверка обновлений; отчёты HTML, PDF, Excel; обход; демо-режим; состояние программы и её `/api/*` (история, сравнение «до/после», настройки, выгрузка CSV/JSON); скан через wlanapi.dll (Windows) | совпадает с 1.x на всех эталонах целиком (4 снапшота × 2 языка), `/api/state` и выгрузки - с Python-версией (`tools/compare_state.py`) |
| `app` | окно на Tauri 2: тот же интерфейс, что у 1.x, через свой протокол `wbs` (без порта и локального сервера); установщик NSIS | 2.0.0, собирается в CI на Windows (`.github/workflows/rust.yml`) |

Перенесено всё, что есть у exe 1.1: окно и все вкладки, отчёты, обход, демо-режим (`--demo`), параметры `--ssid`,
`--manuf`, `--lang`. Командная строка `python -m wifi_beacon_scanner interfaces|scan|analyze` остаётся только в 1.x.
2.x ставится рядом с 1.x: свои идентификатор, папка установки,
настройки (`%APPDATA%\WiFiBeaconScanner2`) и журнал; настройки 1.x читаются один раз, пока своих нет.

## Как проверяется

Ядро читает те же снапшоты, что и Python-версия (`contract/fixtures`), и сравнивает свой результат с её
эталонами (`contract/golden`) - тест `crates/wbs-core/tests/contract.rs`. Правила контракта - в
[`contract/README.ru.md`](../contract/README.ru.md).

    cd rust
    cargo test          # модульные тесты и сверка с эталонами
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

Нужен Rust (`rustup`, канал stable; в CI закреплена версия 1.97.0). У `wbs-core` нет внешних зависимостей:
он собирается без доступа к crates.io.

Интерфейс с API на Rust без Tauri, в любом браузере (данные - из снапшота):

    cargo run --example devserver -- ../contract/fixtures/demo-office.json 8765
    WBS_BACKEND=demo cargo run --example devserver -- ../contract/fixtures/demo-base.json 8765   # демо-режим
    python ../tools/compare_state.py target/debug/examples/devserver     # сверка с 1.x

Модуль `win` (wlanapi) собирается только на Windows; проверить его на Linux:
`RUSTFLAGS="--cfg wbs_check_win" cargo clippy`.

Окно (`app`) - отдельный workspace, ему нужен crates.io; собирается в CI (`.github/workflows/rust.yml`, job `app`):

    cd app
    npx @tauri-apps/cli@2 build        # exe и установщик NSIS в target/release
