# Security policy / Политика безопасности

**English**

Supported versions: the latest release only.

Please do not report vulnerabilities in public issues. Use the repository's **Security** tab →
"Report a vulnerability" if it is available, or write to the maintainer via the email in the GitHub profile
[@salilov95](https://github.com/salilov95). Include the version, steps to reproduce and the impact.

What the app does that matters for security:
- version 2 opens no network port: the window talks to the app through its own `wbs` protocol inside the process,
  the page is limited by a strict Content Security Policy, external links open in the default browser
  (version 1.x: a local server on `127.0.0.1` only, with a one-time token and `Host`/`Origin` checks);
- no administrator rights are needed; the app only reads Wi-Fi data, the network adapter configuration and the
  WLAN-AutoConfig event log;
- the app goes online only when "Check for updates" is clicked (one request to `api.github.com`);
- snapshots and reports contain SSIDs and BSSIDs of nearby networks - review them before sharing.

**Русский**

Поддерживается только последний релиз.

Об уязвимостях не пишите в открытых issue. Используйте вкладку **Security** репозитория →
«Report a vulnerability», если она доступна, или напишите сопровождающему на почту из профиля GitHub
[@salilov95](https://github.com/salilov95): версия, шаги для повторения, последствия.

Что важно для безопасности:
- версия 2 не открывает сетевой порт: окно общается с программой через свой протокол `wbs` внутри процесса,
  странице строгий Content Security Policy, внешние ссылки открываются в браузере по умолчанию
  (версия 1.x: локальный сервер только на `127.0.0.1`, одноразовый токен, проверка `Host`/`Origin`);
- права администратора не нужны; программа только читает данные Wi-Fi, настройки сетевого адаптера и журнал
  WLAN-AutoConfig;
- в интернет программа выходит только по кнопке «Проверить обновления» (один запрос к `api.github.com`);
- снапшоты и отчёты содержат SSID и BSSID соседних сетей - проверьте их перед отправкой.
