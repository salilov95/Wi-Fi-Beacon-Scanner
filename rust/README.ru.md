# Wi-Fi Beacon Scanner 2.x (Rust + Tauri 2) - в разработке

[English](README.md) · **Русский**

Новая версия программы: своё окно вместо локального сервера и окна Edge, один небольшой exe, потом Linux
и macOS. Рабочая версия сейчас - **1.x на Python** (корень репозитория); этот каталог её не трогает, у него свой
workflow (`.github/workflows/rust.yml`), а версии 2.x выходят только как pre-release `v2.0.0-alpha.N`.

## Что уже есть

| Крейт | Что | Состояние |
|---|---|---|
| `crates/wbs-core` | разбор beacon (IE), модель BSS, защита, MCS, дерево IE для вкладки Beacon, дополнения 802.11, проблемы, свободность и загрузка каналов, переводы; состояние программы и её `/api/*` (история, сравнение «до/после», настройки, выгрузка CSV/JSON); скан через wlanapi.dll (Windows) | совпадает с 1.x на всех эталонах целиком (4 снапшота × 2 языка), `/api/state` и выгрузки - с Python-версией (`tools/compare_state.py`) |
| `app` | окно на Tauri 2: тот же интерфейс, что у 1.x, через свой протокол `wbs` (без порта и локального сервера); установщик NSIS | 2.0.0-alpha.1, собирается в CI на Windows |

Ещё не перенесено (в 2.0 alpha отвечает понятным сообщением): журнал подключения и сессии, журнал Windows, обход,
отчёты HTML/PDF/Excel, проверка обновлений. 2.x ставится рядом с 1.x: свои идентификатор, папка установки,
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
    python ../tools/compare_state.py target/debug/examples/devserver     # сверка с 1.x

Модуль `win` (wlanapi) собирается только на Windows; проверить его на Linux:
`RUSTFLAGS="--cfg wbs_check_win" cargo clippy`.

Окно (`app`) - отдельный workspace, ему нужен crates.io; собирается в CI (`.github/workflows/rust.yml`, job `app`):

    cd app
    npx @tauri-apps/cli@2 build        # exe и установщик NSIS в target/release
