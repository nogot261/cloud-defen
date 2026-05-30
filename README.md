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

$$
\mathrm{risk\_score} = \min \left( \sum \mathrm{risk\_signal\_points}, 100 \right)
$$

В математической форме:

Пусть:

$$
S = \{s_1, s_2, \ldots, s_n\}
$$

где $S$ - множество risk-сигналов.

Для каждого сигнала $s_i$ задан вес $w_i$ и логическое условие $C_i(x)$.

Индикатор срабатывания сигнала:

$$
I_i(x)=
\begin{cases}
1, & \text{если } C_i(x) = \mathrm{true}, \\
0, & \text{если } C_i(x) = \mathrm{false}.
\end{cases}
$$

Итоговая формула:

$$
\mathrm{risk\_score}(x)
=
\min \left(
100,
\sum_{i=1}^{n} w_i \cdot I_i(x)
\right)
$$

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

Формально уровень риска задается кусочной функцией:

$$
\mathrm{level}(r)=
\begin{cases}
\mathrm{low},      & 0 \le r < 25, \\
\mathrm{medium},   & 25 \le r < 50, \\
\mathrm{high},     & 50 \le r < 75, \\
\mathrm{critical}, & 75 \le r \le 100.
\end{cases}
$$

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

$$
\begin{aligned}
C_{\mathrm{datacenter}} &\equiv NT = \mathrm{datacenter/hosting} \\
C_{\mathrm{new\_country}} &\equiv PC \ne \varnothing \land country \notin PC \\
C_{\mathrm{known\_device\_new\_region}} &\equiv device\_seen\_before \land PC \ne \varnothing \land country \notin PC \\
C_{\mathrm{timezone\_mismatch}} &\equiv TZC \ne \varnothing \land country \ne \mathrm{UNKNOWN} \land TZC \ne country \\
C_{\mathrm{language\_mismatch}} &\equiv LANG \ne \varnothing \land LANG \notin common\_language\_regions(country) \\
C_{\mathrm{failed\_logins}} &\equiv failed\_logins\_last\_5\_min > 10 \\
C_{\mathrm{mass\_download}} &\equiv downloaded\_docs\_last\_10\_min > 30 \\
C_{\mathrm{api\_anomaly}} &\equiv protected\_requests\_last\_2\_min > 120 \\
C_{\mathrm{webrtc\_leak}} &\equiv webrtc\_leak = true \\
C_{\mathrm{no\_ipv6}} &\equiv ipv6\_enabled = false
\end{aligned}
$$

$$
\begin{aligned}
C_{\mathrm{ip\_changed}} &\equiv PS.ip \ne \varnothing \land ip \ne \varnothing \land PS.ip \ne ip \\
C_{\mathrm{country\_changed}} &\equiv PS.country \ne \varnothing \land country \ne \varnothing \land PS.country \ne country \\
C_{\mathrm{asn\_changed}} &\equiv PS.asn \ne \varnothing \land asn \ne \varnothing \land PS.asn \ne asn \\
C_{\mathrm{timezone\_changed\_without\_country}} &\equiv PS.timezone \ne timezone \land \neg C_{\mathrm{country\_changed}} \\
C_{\mathrm{same\_device\_new\_network}} &\equiv FP \ne \varnothing \land PS.browser\_fingerprint\_hash = FP \\
&\quad \land (C_{\mathrm{ip\_changed}} \lor C_{\mathrm{country\_changed}} \lor C_{\mathrm{asn\_changed}}) \\
C_{\mathrm{gpu\_changed}} &\equiv PS.device\_profile.webgl\_renderer \ne \varnothing \\
&\quad \land device\_profile.webgl\_renderer \ne \varnothing \\
&\quad \land PS.device\_profile.webgl\_renderer \ne device\_profile.webgl\_renderer
\end{aligned}
$$

$$
\begin{aligned}
C_{\mathrm{network\_type\_conflict}} &\equiv network\_profile.connection\_type \in \{\mathrm{cellular}, \mathrm{none}\} \\
&\quad \land NT = \mathrm{datacenter/hosting} \\
C_{\mathrm{hybrid\_fingerprint}} &\equiv device\_profile.touch\_points > 0 \land \mathrm{Win} \subset device\_profile.platform \\
C_{\mathrm{clock\_skew}} &\equiv |device\_profile.clock.server\_skew\_ms| > 120000 \\
C_{\mathrm{low\_battery}} &\equiv battery.supported \land battery.level\_percent \le 10 \land \neg battery.charging \\
C_{\mathrm{battery\_api\_hidden}} &\equiv battery.supported = false \\
C_{\mathrm{high\_js\_heap}} &\equiv performance.js\_heap\_usage\_percent > 80 \\
C_{\mathrm{event\_loop\_lag}} &\equiv performance.event\_loop\_lag\_ms > 80
\end{aligned}
$$

Таким образом, например, вклад признака “то же устройство, другая сеть” считается так:

$$
r_{\mathrm{same\_device\_new\_network}}
=
20 \cdot
\mathbb{1}
\left[
FP = PS.browser\_fingerprint\_hash
\land
(ip \ne PS.ip \lor country \ne PS.country \lor asn \ne PS.asn)
\right]
$$

А общий риск можно разложить как:

$$
\begin{aligned}
\mathrm{risk\_score} = \min(100,\;&
25I(C_{\mathrm{datacenter}})
+15I(C_{\mathrm{new\_country}})
+15I(C_{\mathrm{known\_device\_new\_region}}) \\
&+10I(C_{\mathrm{timezone\_mismatch}})
+5I(C_{\mathrm{language\_mismatch}})
+20I(C_{\mathrm{failed\_logins}}) \\
&+20I(C_{\mathrm{mass\_download}})
+10I(C_{\mathrm{api\_anomaly}})
+10I(C_{\mathrm{webrtc\_leak}})
+2I(C_{\mathrm{no\_ipv6}}) \\
&+18I(C_{\mathrm{ip\_changed}})
+18I(C_{\mathrm{country\_changed}})
+12I(C_{\mathrm{asn\_changed}}) \\
&+8I(C_{\mathrm{timezone\_changed\_without\_country}})
+20I(C_{\mathrm{same\_device\_new\_network}})
+10I(C_{\mathrm{gpu\_changed}}) \\
&+8I(C_{\mathrm{network\_type\_conflict}})
+4I(C_{\mathrm{hybrid\_fingerprint}})
+10I(C_{\mathrm{clock\_skew}}) \\
&+4I(C_{\mathrm{low\_battery}})
+1I(C_{\mathrm{battery\_api\_hidden}})
+5I(C_{\mathrm{high\_js\_heap}})
+5I(C_{\mathrm{event\_loop\_lag}})
)
\end{aligned}
$$

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

$$
\mathrm{risk\_score}
=
\min(25 + 15 + 20 + 20 + 20,\;100)
=
100
$$

$$
\mathrm{risk\_level} = \mathrm{critical}
$$

## Формула экспозиции

Экспозиция показывает, насколько много признаков браузер и сеть раскрывают для идентификации или антифрод-анализа.

```text
exposure_score = min(sum(exposure_finding_points), 100)
```

$$
\mathrm{exposure\_score}
=
\min \left( \sum \mathrm{exposure\_finding\_points}, 100 \right)
$$

Математическая запись аналогична risk-модели:

Пусть:

$$
E = \{e_1, e_2, \ldots, e_m\}
$$

где $E$ - множество exposure-findings.

Для каждого finding $e_j$ задан вес $v_j$ и условие $D_j(x)$.

$$
J_j(x)=
\begin{cases}
1, & \text{если } D_j(x) = \mathrm{true}, \\
0, & \text{если } D_j(x) = \mathrm{false}.
\end{cases}
$$

$$
\mathrm{exposure\_score}(x)
=
\min \left(
100,
\sum_{j=1}^{m} v_j \cdot J_j(x)
\right)
$$

Уровень экспозиции:

$$
\mathrm{exposure\_level}(e)=
\begin{cases}
\mathrm{low},      & 0 \le e < 25, \\
\mathrm{medium},   & 25 \le e < 50, \\
\mathrm{high},     & 50 \le e < 75, \\
\mathrm{critical}, & 75 \le e \le 100.
\end{cases}
$$

### Логические условия exposure-findings

$$
\begin{aligned}
D_{\mathrm{vpn\_like\_network}} &\equiv NT = \mathrm{datacenter/hosting} \\
D_{\mathrm{webrtc\_candidates}} &\equiv webrtc\_leak = true \\
D_{\mathrm{no\_ipv6}} &\equiv ipv6\_enabled = false \\
D_{\mathrm{timezone\_ip\_conflict}} &\equiv TZC \ne \varnothing \land TZC \ne country \\
D_{\mathrm{language\_identifies\_user}} &\equiv LANG \ne \varnothing \land LANG \ne country \\
D_{\mathrm{network\_changed\_same\_device}} &\equiv FP = PS.browser\_fingerprint\_hash \\
&\quad \land (ip \ne PS.ip \lor country \ne PS.country \lor asn \ne PS.asn) \\
D_{\mathrm{webgl\_identifies\_device}} &\equiv device\_profile.webgl\_renderer \ne \varnothing \\
D_{\mathrm{webgl\_hidden}} &\equiv device\_profile.webgl\_supported = false \\
D_{\mathrm{canvas\_available}} &\equiv canvas\_hash \ne \varnothing \land canvas\_hash \ne \mathrm{unavailable} \\
D_{\mathrm{audio\_available}} &\equiv audio\_hash \ne \varnothing \land audio\_hash \notin \{\mathrm{unavailable}, \mathrm{blocked}\}
\end{aligned}
$$

$$
\begin{aligned}
D_{\mathrm{ua\_hints\_available}} &\equiv ua\_hints.available = true \\
D_{\mathrm{cpu\_threads\_available}} &\equiv hardware\_concurrency \ne \varnothing \\
D_{\mathrm{ram\_bucket\_available}} &\equiv device\_memory\_gb \ne \varnothing \\
D_{\mathrm{battery\_available}} &\equiv battery.supported = true \\
D_{\mathrm{clock\_skew}} &\equiv |clock.server\_skew\_ms| > 120000 \\
D_{\mathrm{js\_heap\_available}} &\equiv performance.memory.supported = true \\
D_{\mathrm{event\_loop\_lag}} &\equiv performance.event\_loop\_lag\_ms > 80 \\
D_{\mathrm{network\_info\_available}} &\equiv network\_profile.effective\_type \ne \varnothing \\
&\quad \lor network\_profile.connection\_type \ne \varnothing
\end{aligned}
$$

Полная формула:

$$
\begin{aligned}
\mathrm{exposure\_score} = \min(100,\;&
18J(D_{\mathrm{vpn\_like\_network}})
+12J(D_{\mathrm{webrtc\_candidates}})
+4J(D_{\mathrm{no\_ipv6}}) \\
&+12J(D_{\mathrm{timezone\_ip\_conflict}})
+5J(D_{\mathrm{language\_identifies\_user}})
+24J(D_{\mathrm{network\_changed\_same\_device}}) \\
&+10J(D_{\mathrm{webgl\_identifies\_device}})
+1J(D_{\mathrm{webgl\_hidden}})
+8J(D_{\mathrm{canvas\_available}})
+6J(D_{\mathrm{audio\_available}}) \\
&+6J(D_{\mathrm{ua\_hints\_available}})
+4J(D_{\mathrm{cpu\_threads\_available}})
+4J(D_{\mathrm{ram\_bucket\_available}}) \\
&+5J(D_{\mathrm{battery\_available}})
+10J(D_{\mathrm{clock\_skew}})
+2J(D_{\mathrm{js\_heap\_available}}) \\
&+5J(D_{\mathrm{event\_loop\_lag}})
+2J(D_{\mathrm{network\_info\_available}})
)
\end{aligned}
$$

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
