# VulnManager

Движок управления уязвимостями: принимает отчёты сканеров, приводит находки к единому виду и
схлопывает дубликаты в кластеры. Сервисы: `ingest`, `normalize`, `processing`.

## Поддерживаемые инструменты

| Инструмент | Формат отчёта | `X-Tool` |
|---|---|---|
| Trivy 0.75.0 | JSON (`--format json`) | `trivy` |
| Semgrep 1.180.0 | SARIF (`--sarif`) | `semgrep` |

## Запуск локально

Нужны только Docker и `make`.

```bash
make up              # собрать .deb и образы и поднять стенд
make down            # остановить
make clean           # остановить и удалить данные
```

Отправить отчёт:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/reports \
  -H 'X-Tool: <tool_name>' -H 'X-Scope: <product>/<context>' --data-binary @<report_file>
```

## Тесты

```bash
make test            # юнит-тесты и линтеры (в Docker)
make e2e             # сквозные тесты, перед запуском нужно поднять стенд (make up)
make integration     # в каталоге ingest или normalize, стенд не нужен
```

| Вид | Где |
|---|---|
| Юнит и golden | `*_test.go`, `services/normalize/internal/parsers/testdata/golden` |
| Контрактные сьюты точек расширения | `parsertest`, `normtest`, `fptest`, `deduptest` |
| Интеграционные | `services/ingest/tests/integration`, `services/normalize/tests/integration` |
| Сквозные | `tests/e2e` |

Для e2e-тестов сначала нужно поднять стенд (`make up`): `make e2e` сам его не поднимает.

## Точки расширения

Новый инструмент подключается через реестры, ключ в них — значение `X-Tool`.

- **`normalize`:** реестр адаптеров (`services/normalize/internal/adapters`) сопоставляет инструмент
  с парсером и цепочкой нормализаторов; для неизвестного инструмента используется запасной адаптер.
  Регистрация в `adapters/tools.go`.
- **`processing`:** реестр наборов отпечатков (`services/processing/internal/fingerprint`)
  сопоставляет инструмент со стратегиями отпечатков; для неизвестного используется запасной набор; повторная регистрация имени возвращает ошибку.
  Регистрация в `services/processing/internal/adapters/tools.go`.

