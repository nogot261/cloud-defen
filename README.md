# Explainable Cloud Risk Scoring

Explainable Cloud Risk Scoring - это веб-сервис для анализа риска пользовательской сессии. Система собирает доступные сетевые, браузерные, устройственные и поведенческие признаки, рассчитывает риск по прозрачной формуле, показывает найденные экспозиции и формирует понятное объяснение без обязательного использования LLM.

По умолчанию сервис работает в формульном режиме и подходит для небольших облачных инстансов, включая бесплатный тариф Render.

## Возможности

- FastAPI backend.
- Веб-дашборд для диагностики сессии.
- Формульный risk engine с прозрачными весами.
- Анализ сетевых и браузерных экспозиций.
- Обнаружение смены VPN/proxy по сравнению с прошлой проверкой.
- Сохранение локального snapshot сессии в `localStorage`.
- Опциональное объяснение через локальный Ollama.
- Docker и конфигурация для Render.

## Архитектура

```text
Browser dashboard
  -> сбор признаков сессии и fingerprint
  -> FastAPI backend
  -> risk engine
  -> exposure analysis
  -> формульное объяснение
  -> dashboard report
```

Опциональный локальный режим:

```text
risk report -> Ollama -> LLM-assisted explanation
```

## Быстрый запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
USE_LLM=0 uvicorn app.main:app --reload
```

Локальный адрес:

```text
http://localhost:8000
```

Для доступа из локальной сети сервер должен слушать все интерфейсы:

```bash
USE_LLM=0 uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Адрес в локальной сети:

```text
http://<server-lan-ip>:8000
```

## Режимы анализа

### Формульный режим

Формульный режим включен по умолчанию:

```bash
USE_LLM=0 uvicorn app.main:app --reload
```

В этом режиме вывод строится только по правилам и фактическим данным сессии:

- IP, страна, ASN, тип сети;
- timezone и язык браузера;
- WebGL renderer;
- canvas/audio fingerprint;
- расхождение локального времени с сервером;
- Battery Status API, если браузер разрешает;
- performance-профиль браузера;
- предыдущий snapshot из `localStorage`;
- поведенческие счетчики: ошибки входа, скачивания, запросы к защищенным ресурсам.

### Опциональный режим с локальной LLM

LLM-режим предназначен для локальной демонстрации и отключен в облачном деплое.

```bash
ollama pull gemma3:1b
ollama serve
```

В другом терминале:

```bash
USE_LLM=1 OLLAMA_MODEL=gemma3:1b uvicorn app.main:app --reload
```

Можно указать другую локальную модель:

```bash
USE_LLM=1 OLLAMA_MODEL=qwen3:8b uvicorn app.main:app --reload
```

## Формула риска

Итоговый риск считается как сумма баллов всех сработавших risk-сигналов с ограничением сверху:

```text
risk_score = min(sum(risk_signal_points), 100)
```

В математической форме:

```text
Пусть S = {s1, s2, ..., sn} - множество risk-сигналов.
Для каждого сигнала si задан вес wi и логическое условие Ci(x).

Ii(x) = 1, если Ci(x) истинно
Ii(x) = 0, если Ci(x) ложно

risk_score(x) = min(100, Σ wi * Ii(x))
```

Где `x` - текущий набор данных сессии:

```text
x = {
  ip, asn, country, timezone, accept_language,
  previous_countries,
  failed_logins_last_5_min,
  downloaded_docs_last_10_min,
  protected_requests_last_2_min,
  webrtc_leak,
  ipv6_enabled,
  browser_fingerprint_hash,
  device_profile,
  network_profile,
  previous_snapshot
}
```

Уровень риска:

```text
0-24   -> low
25-49  -> medium
50-74  -> high
75-100 -> critical
```

Формально уровень риска задается кусочной функцией:

```text
level(score) =
  low,      если 0  <= score < 25
  medium,   если 25 <= score < 50
  high,     если 50 <= score < 75
  critical, если 75 <= score <= 100
```

### Логические условия risk-сигналов

Ниже приведены основные условия в логической форме. Обозначения:

```text
NT      = network_type
PC      = previous_countries
PS      = previous_snapshot
FP      = browser_fingerprint_hash
TZC     = country_from_timezone(timezone)
LANG    = language_region(accept_language)
```

```text
C_datacenter =
  NT = "datacenter/hosting"

C_new_country =
  PC не пусто AND country ∉ PC

C_known_device_new_region =
  device_seen_before = true AND PC не пусто AND country ∉ PC

C_timezone_mismatch =
  TZC определен AND country != "UNKNOWN" AND TZC != country

C_language_mismatch =
  LANG определен AND LANG ∉ common_language_regions(country)

C_failed_logins =
  failed_logins_last_5_min > 10

C_mass_download =
  downloaded_docs_last_10_min > 30

C_api_anomaly =
  protected_requests_last_2_min > 120

C_webrtc_leak =
  webrtc_leak = true

C_no_ipv6 =
  ipv6_enabled = false

C_ip_changed =
  PS.ip определен AND ip определен AND PS.ip != ip

C_country_changed =
  PS.country определен AND country определен AND PS.country != country

C_asn_changed =
  PS.asn определен AND asn определен AND PS.asn != asn

C_timezone_changed_without_country =
  PS.timezone != timezone AND NOT C_country_changed

C_same_device_new_network =
  FP определен
  AND PS.browser_fingerprint_hash = FP
  AND (C_ip_changed OR C_country_changed OR C_asn_changed)

C_gpu_changed =
  PS.device_profile.webgl_renderer определен
  AND device_profile.webgl_renderer определен
  AND PS.device_profile.webgl_renderer != device_profile.webgl_renderer

C_network_type_conflict =
  network_profile.connection_type ∈ {"cellular", "none"}
  AND NT = "datacenter/hosting"

C_hybrid_fingerprint =
  device_profile.touch_points > 0
  AND "Win" входит в device_profile.platform

C_clock_skew =
  abs(device_profile.clock.server_skew_ms) > 120000

C_low_battery =
  battery.supported = true
  AND battery.level_percent <= 10
  AND battery.charging = false

C_battery_api_hidden =
  battery.supported = false

C_high_js_heap =
  performance.js_heap_usage_percent > 80

C_event_loop_lag =
  performance.event_loop_lag_ms > 80
```

Таким образом, например, вклад признака “то же устройство, другая сеть” считается так:

```text
r_same_device_new_network = 20 * I(
  FP = PS.browser_fingerprint_hash
  AND (ip != PS.ip OR country != PS.country OR asn != PS.asn)
)
```

А общий риск можно разложить как:

```text
risk_score =
min(100,
  25 * I(C_datacenter)
+ 15 * I(C_new_country)
+ 15 * I(C_known_device_new_region)
+ 10 * I(C_timezone_mismatch)
+  5 * I(C_language_mismatch)
+ 20 * I(C_failed_logins)
+ 20 * I(C_mass_download)
+ 10 * I(C_api_anomaly)
+ 10 * I(C_webrtc_leak)
+  2 * I(C_no_ipv6)
+ 18 * I(C_ip_changed)
+ 18 * I(C_country_changed)
+ 12 * I(C_asn_changed)
+  8 * I(C_timezone_changed_without_country)
+ 20 * I(C_same_device_new_network)
+ 10 * I(C_gpu_changed)
+  8 * I(C_network_type_conflict)
+  4 * I(C_hybrid_fingerprint)
+ 10 * I(C_clock_skew)
+  4 * I(C_low_battery)
+  1 * I(C_battery_api_hidden)
+  5 * I(C_high_js_heap)
+  5 * I(C_event_loop_lag)
)
```

### Risk-сигналы

| Условие | Баллы |
|---|---:|
| IP/ASN похож на датацентр, hosting, VPS, VPN или cloud-провайдера | 25 |
| Текущая страна не встречалась в истории аккаунта | 15 |
| Устройство известно, но сетевой регион новый | 15 |
| Timezone браузера не совпадает со страной IP | 10 |
| Язык браузера слабо согласуется с регионом IP | 5 |
| Больше 10 неудачных входов за 5 минут | 20 |
| Больше 30 скачанных документов за 10 минут | 20 |
| Больше 120 запросов к защищенным ресурсам за 2 минуты | 10 |
| WebRTC раскрывает дополнительный сетевой адрес | 10 |
| IPv6 не обнаружен | 2 |
| IP изменился с прошлой проверки | 18 |
| Страна IP изменилась с прошлой проверки | 18 |
| ASN/провайдер изменился с прошлой проверки | 12 |
| Timezone изменился без смены страны | 8 |
| Fingerprint тот же, но сеть изменилась | 20 |
| WebGL/GPU изменился с прошлой проверки | 10 |
| Тип соединения браузера конфликтует с datacenter/VPN-сетью | 8 |
| Гибридный fingerprint: touch-ввод вместе с desktop-платформой | 4 |
| Системное время отличается от серверного больше чем на 120 секунд | 10 |
| Заряд батареи 10% или ниже и устройство не заряжается | 4 |
| Battery API недоступен | 1 |
| JS heap страницы использован больше чем на 80% | 5 |
| Event loop задерживается больше чем на 80 мс | 5 |

### Пример расчета

Если сработали признаки:

```text
Инфраструктурная сеть                 +25
Новая страна аккаунта                 +15
То же устройство, другая сеть          +20
Много неудачных входов                 +20
Массовое скачивание                    +20
```

Тогда:

```text
risk_score = min(25 + 15 + 20 + 20 + 20, 100) = 100
risk_level = critical
```

## Формула экспозиции

Экспозиция показывает, насколько много признаков браузер и сеть раскрывают для идентификации или антифрод-анализа.

```text
exposure_score = min(sum(exposure_finding_points), 100)
```

Математическая запись аналогична risk-модели:

```text
Пусть E = {e1, e2, ..., em} - множество exposure-findings.
Для каждого finding ej задан вес vj и условие Dj(x).

Jj(x) = 1, если Dj(x) истинно
Jj(x) = 0, если Dj(x) ложно

exposure_score(x) = min(100, Σ vj * Jj(x))
```

Уровень экспозиции:

```text
0-24   -> low
25-49  -> medium
50-74  -> high
75-100 -> critical
```

### Логические условия exposure-findings

```text
D_vpn_like_network =
  NT = "datacenter/hosting"

D_webrtc_candidates =
  webrtc_leak = true

D_no_ipv6 =
  ipv6_enabled = false

D_timezone_ip_conflict =
  TZC определен AND TZC != country

D_language_identifies_user =
  LANG определен AND LANG != country

D_network_changed_same_device =
  FP = PS.browser_fingerprint_hash
  AND (ip != PS.ip OR country != PS.country OR asn != PS.asn)

D_webgl_identifies_device =
  device_profile.webgl_renderer определен

D_webgl_hidden =
  device_profile.webgl_supported = false

D_canvas_available =
  canvas_hash определен AND canvas_hash != "unavailable"

D_audio_available =
  audio_hash определен
  AND audio_hash ∉ {"unavailable", "blocked"}

D_ua_hints_available =
  ua_hints.available = true

D_cpu_threads_available =
  hardware_concurrency определен

D_ram_bucket_available =
  device_memory_gb определен

D_battery_available =
  battery.supported = true

D_clock_skew =
  abs(clock.server_skew_ms) > 120000

D_js_heap_available =
  performance.memory.supported = true

D_event_loop_lag =
  performance.event_loop_lag_ms > 80

D_network_info_available =
  network_profile.effective_type определен
  OR network_profile.connection_type определен
```

Полная формула:

```text
exposure_score =
min(100,
  18 * J(D_vpn_like_network)
+ 12 * J(D_webrtc_candidates)
+  4 * J(D_no_ipv6)
+ 12 * J(D_timezone_ip_conflict)
+  5 * J(D_language_identifies_user)
+ 24 * J(D_network_changed_same_device)
+ 10 * J(D_webgl_identifies_device)
+  1 * J(D_webgl_hidden)
+  8 * J(D_canvas_available)
+  6 * J(D_audio_available)
+  6 * J(D_ua_hints_available)
+  4 * J(D_cpu_threads_available)
+  4 * J(D_ram_bucket_available)
+  5 * J(D_battery_available)
+ 10 * J(D_clock_skew)
+  2 * J(D_js_heap_available)
+  5 * J(D_event_loop_lag)
+  2 * J(D_network_info_available)
)
```

### Exposure-findings

| Finding | Категория | Баллы |
|---|---|---:|
| VPN/VPS-подобная сеть | network | 18 |
| WebRTC раскрывает сетевые кандидаты | browser | 12 |
| IPv6 не виден | network | 4 |
| Timezone конфликтует с IP-страной | consistency | 12 |
| Язык браузера выделяет пользователя | fingerprint | 5 |
| Смена сети при стабильном устройстве | vpn-change | 24 |
| GPU/WebGL хорошо идентифицирует устройство | fingerprint | 10 |
| WebGL скрыт или недоступен | browser | 1 |
| Canvas fingerprint доступен | fingerprint | 8 |
| Audio fingerprint доступен | fingerprint | 6 |
| UA Client Hints раскрыты | browser | 6 |
| Количество CPU-потоков доступно | device | 4 |
| RAM bucket доступен | device | 4 |
| Battery API раскрывает состояние питания | device | 5 |
| Локальные часы сбиты | consistency | 10 |
| JS heap memory доступна | performance | 2 |
| Браузерная вкладка заметно тормозит | performance | 5 |
| Network Information API доступен | network | 2 |

Каждая экспозиция содержит:

- категорию;
- severity;
- вклад в score;
- evidence из текущей сессии;
- рекомендацию.

## Что собирается из браузера

Сервис собирает только признаки, доступные обычному веб-приложению:

- timezone;
- Accept-Language;
- User-Agent;
- экран, viewport, DPR, color depth;
- WebGL vendor/renderer;
- canvas hash;
- audio hash;
- UA Client Hints;
- `navigator.hardwareConcurrency`;
- `navigator.deviceMemory`, если поддерживается;
- Battery Status API, если браузер разрешает;
- Network Information API, если доступен;
- JS heap через `performance.memory`, если доступен;
- FPS, event-loop lag, synthetic JavaScript CPU benchmark;
- WebRTC-кандидаты;
- IPv6 availability check;
- публичный IP/страну/ASN через внешний lookup в браузере.

Современные браузеры намеренно не раскрывают сайту часть системных данных. Веб-приложение не может надежно получить:

- емкость батареи в mAh;
- точную модель CPU;
- точную модель ноутбука;
- реальную загрузку CPU/GPU/RAM всей ОС;
- температуру компонентов;
- полный список системных процессов.

Такие данные доступны только нативному агенту с правами операционной системы.

## Сравнение с предыдущей сессией

После каждого анализа браузер сохраняет короткий snapshot в `localStorage`. При следующем анализе сравниваются:

- IP;
- страна;
- ASN/провайдер;
- timezone;
- browser fingerprint hash;
- WebGL renderer.

Если fingerprint устройства остается тем же, но IP/страна/ASN меняются, система считает это сильным признаком смены VPN/proxy.

## Docker

```bash
docker build -t cloud-risk-monitor .
docker run --rm -p 8000:8000 -e USE_LLM=0 cloud-risk-monitor
```

Docker Compose запускает backend вместе с Ollama для локальной демонстрации LLM-режима:

```bash
docker compose up --build
```

После первого запуска Compose нужно загрузить модель в контейнер Ollama:

```bash
docker compose exec ollama ollama pull gemma3:1b
```

## Деплой на Render

В проекте есть `render.yaml` и Dockerfile с поддержкой переменной окружения `$PORT`.

Для Render используется конфигурация:

```text
USE_LLM=0
```

Порядок деплоя:

1. Загрузить проект в GitHub-репозиторий.
2. Создать в Render Blueprint или Docker-based Web Service.
3. Указать репозиторий проекта.
4. Render автоматически соберет Docker image.
5. Приложение запустится на порту, который Render передаст через `$PORT`.

На бесплатном тарифе Ollama не запускается. IP lookup и fingerprint собираются в браузере клиента, а сервер выполняет только формульный расчет.

## Связь с учебным пособием

В проекте используется `Учебно-методическое пособие по облакам.pdf` как методическая основа:

Назаров А.Н., Андрианова Е.Г. "Расчетное обоснование облачных решений", 2024.

Соответствие темам пособия:

- защита университетских баз данных представлена как защита доступа к закрытым ресурсам;
- угрозы информационной безопасности представлены подозрительными сетями, несогласованными регионами, аномалиями аккаунта и поведения;
- мониторинговый облачный кластер представлен цепочкой сбора, обогащения, расчета и визуализации событий;
- IaaS-моделирование представлено сервисной архитектурой backend/dashboard/risk engine;
- расчетный подход реализован через формулы `risk_score` и `exposure_score`.

PDF используется не как источник кода, а как обоснование предметной области, архитектуры мониторинга и расчетной модели.

## API

Health check:

```text
GET /api/health
```

Конфигурация:

```text
GET /api/config
```

Серверное время для clock-skew analysis:

```text
GET /api/time
```

Анализ сессии:

```text
POST /api/analyze
```

Ответ `/api/analyze` содержит:

- `risk_score`;
- `risk_level`;
- `signals`;
- `exposure_score`;
- `exposure_level`;
- `exposures`;
- формульное или опциональное LLM-объяснение.
