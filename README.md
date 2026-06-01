# GOST TLS Exporter

![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Docker Image](https://img.shields.io/badge/docker-ghcr.io/dmitry-lyutenko/gost--tls--exporter-blue)

**GOST TLS Exporter** — это Prometheus-экспортер для мониторинга срока действия SSL/TLS сертификатов на хостах, использующих российские криптографические алгоритмы (ГОСТ). 

Проект позволяет легко отслеживать состояние сертификатов на ресурсах, поддерживающих ГОСТ TLS, без необходимости установки тяжеловесного ПО (такого как КриптоПро CSP) или сборки кастомных версий OpenSSL.

## ✨ Ключевые особенности

* 🚀 **Pure Go Implementation**: Написан на чистом Go. Не требует наличия установленных СКЗИ (КриптоПро и др.) или специфических системных библиотек на хосте.
* 🛡️ **ГОСТ Cipher Suites**: Поддерживает кастомный TLS 1.2 Handshake с использованием шифронаборов `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` и `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`.
* ⚡ **Built-in Caching**: Встроенный кэш защищает целевые ГОСТ-шлюзы от избыточных запросов («шторма» проверок) при частом опросе.
* 📊 **Blackbox Compatibility**: Метрики совместимы со стандартными дашбордами Grafana для [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter).

## 🛠 Как это работает

Экспортер реализует механизм "multi-target" (аналогично Blackbox Exporter). При получении запроса на `/probe?target=<URL>`, он:
1. Инициирует TLS-соединение.
2. Извлекает цепочку сертификатов.
3. Извлекает данные о сроке действия и других атрибутах.
4. Кэширует результат для оптимизации нагрузки.

## 📈 Метрики

Экспортер предоставляет следующие метрики:

| Метрика | Тип | Описание |
| :--- | :--- | :--- |
| `probe_ssl_earliest_cert_expiry` | Gauge | Unix timestamp даты окончания действия сертификата. |
| `probe_ssl_last_chain_expiry_timestamp_seconds` | Gauge | Дублирующая метрика для совместимости с Blackbox Exporter. |
| `probe_ssl_last_chain_info` | Gauge | Текстовая метрика с лейблами: `subject`, `issuer`, `subjectdnsnames`, `serialnumber`. |

## 🚀 Быстрый старт

### Запуск через Docker

```bash
docker run -d \
  -p 9100:9100 \
  --name gost-tls-exporter \
  ghcr.io/dmitry-lyutenko/gost-tls-exporter:latest \
  -port=9100 \
  -cache-ttl=10m
```

### Запуск из исходных файлов

Предварительно убедитесь, что у вас установлен Go 1.25+.

```bash
go build -o gost-tls-exporter .
./gost-tls-exporter -port=9100
```

## ⚙️ Конфигурация

Экспортер поддерживает следующие флаги командной строки:

| Флаг | Значение по умолчанию | Описание |
| :--- | :--- | :--- |
| `-port` | `9100` | Порт для прослушивания HTTP-сервера. |
| `-address` | `0.0.0.0` | Адрес прослушивания. |
| `-cache-ttl` | `60m` | Время жизни кэша (например, `10m`, `1h`). |
| `-log-level` | `info` | Уровень логирования: `debug`, `info`, `warn`, `error`. |
| `-log-format` | `text` | Формат логов: `text` или `json`. |

## 📝 Настройка Prometheus

Для сбора метрик используйте конфигурацию `scrape_config` с механизмом `relabel_configs` (как в Blackbox Exporter):

```yaml
scrape_configs:
  - job_name: 'gost_ssl_targets'
    metrics_path: /probe
    static_configs:
      - targets:
        - https://testca2012.cryptopro.ru
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: gost-tls-exporter:9100 # Адрес вашего экспортера
```

## VictoriaMetrics

Пример сбора метрик при помощи VMProbe (VictoriaMetrics)

```yaml
---
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMProbe
metadata:
  name: gost-tls-exporter
  namespace: gost-tls-exporter
spec:
  jobName: gost-tls-exporter
  vmProberSpec:
    url: gost-tls-exporter.gost-tls-exporter.svc:9100
    path: /probe
  targets:
    staticConfig:
      targets:
        # Указание протокола https может быть пропущено и будет подставлено автоматически
        - https://testca2012.cryptopro.ru
```

## 📄 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
