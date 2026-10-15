# Wi-Fi Beacon Scanner 2.x (Rust + Tauri 2) - в разработке

[English](README.md) · **Русский**

Новая версия программы: своё окно вместо локального сервера и окна Edge, один небольшой exe, потом Linux
и macOS. Рабочая версия сейчас - **1.x на Python** (корень репозитория); этот каталог её не трогает, у него свой
workflow (`.github/workflows/rust.yml`), а версии 2.x выходят только как pre-release `v2.0.0-alpha.N`.

## Что уже есть

| Крейт | Что | Состояние |
|---|---|---|
| `crates/wbs-core` | разбор beacon (IE), модель BSS, защита, MCS и PHY-скорость, строка таблицы сетей | 37 полей строки совпадают с 1.x на всех эталонах |

Ещё не перенесено: пояснения к дополнениям 802.11 и дерево IE для вкладки Beacon (нужен каталог переводов),
проблемы, свободность и загрузка каналов, окно Tauri, скан через wlanapi, журнал подключения, отчёты.

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
