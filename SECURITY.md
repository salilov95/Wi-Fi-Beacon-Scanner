# Security policy / Политика безопасности

**English**

Supported versions: the latest release only.

Please do not report vulnerabilities in public issues. Use the repository's **Security** tab →
"Report a vulnerability" if it is available, or write to the maintainer via the email in the GitHub profile
[@salilov95](https://github.com/salilov95). Include the version, steps to reproduce and the impact.

What the app does that matters for security:
- the local server listens on `127.0.0.1` only and requires a one-time token; requests with a foreign `Host` or
  `Origin` are rejected;
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
- локальный сервер слушает только `127.0.0.1` и требует одноразовый токен; запросы с чужим `Host` или `Origin`
  отклоняются;
- права администратора не нужны; программа только читает данные Wi-Fi, настройки сетевого адаптера и журнал
  WLAN-AutoConfig;
- в интернет программа выходит только по кнопке «Проверить обновления» (один запрос к `api.github.com`);
- снапшоты и отчёты содержат SSID и BSSID соседних сетей - проверьте их перед отправкой.
