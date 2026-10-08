# Как вносить изменения

1. Ветка от `main`: `feature/<что-делаем>` или `fix/<что-чиним>`.
2. Код без внешних зависимостей: программа должна запускаться на чистом Windows с одним Python
   и собираться в exe. Для тестов можно использовать `requirements-dev.txt`.
3. Тесты: `python -m unittest discover -s tests`. Новая логика - с тестом; разбор IE проверяется
   на байтах, собранных по стандарту (`wifi_beacon_scanner/synth.py`), а не на выводе самого парсера.
4. Интерфейс смотреть на демо-данных: `python -m wifi_beacon_scanner gui --demo`.
5. Изменения описать в [CHANGELOG.md](CHANGELOG.md), раздел «Не выпущено».
6. Сообщения коммитов: первая строка в повелительном наклонении до ~70 символов
   (`Fix PDF export on Windows`), дальше - что и почему.
7. Pull request в `main`; CI должен быть зелёным.

Выпуск версии описан в [docs/development.md](docs/development.md#сборка).
