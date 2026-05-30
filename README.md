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

Итоговый риск считается как сумма весов всех сработавших признаков. Каждый признак задается логическим условием. Если условие истинно, его вес добавляется к итоговой оценке.

Пусть:

$$
S = \{s_{1}, s_{2}, \ldots, s_{n}\}
$$

где $S$ - множество risk-сигналов.

Для каждого сигнала $s_{i}$ задаются:

$$
w_{i} \in \mathbb{R}_{+}
$$

$$
C_{i}(x) \in \{0, 1\}
$$

где $w_{i}$ - вес сигнала, а $C_{i}(x)$ - логическое условие, проверяемое на данных текущей сессии $x$.

Индикатор срабатывания:

$$
I_{i}(x)=
\begin{cases}
1, & C_{i}(x)=\mathrm{true}, \\
0, & C_{i}(x)=\mathrm{false}.
\end{cases}
$$

Итоговая формула:

$$
R(x)=\min\left(100,\sum_{i=1}^{n} w_{i} I_{i}(x)\right)
$$

Здесь $R(x)$ - итоговый `risk_score`.

### Вектор признаков

Текущая сессия описывается набором признаков:

$$
x=(IP, ASN, CTR, TZ, LANG, Hist, FL5, DL10, RQ2, WL, V6, FP, Dev, Net, Prev)
$$

Обозначения:

| Обозначение | Смысл |
|---|---|
| `IP` | текущий IP-адрес |
| `ASN` | провайдер или автономная система |
| `CTR` | страна IP |
| `TZ` | timezone браузера |
| `LANG` | основной язык браузера |
| `Hist` | история стран аккаунта |
| `FL5` | число неудачных входов за 5 минут |
| `DL10` | число скачанных документов за 10 минут |
| `RQ2` | число запросов к защищенным ресурсам за 2 минуты |
| `WL` | наличие WebRTC leak |
| `V6` | наличие IPv6 |
| `FP` | browser fingerprint hash |
| `Dev` | профиль устройства |
| `Net` | профиль сети |
| `Prev` | предыдущий snapshot сессии |

### Уровень риска

Уровень риска задается кусочной функцией:

$$
Level(R)=
\begin{cases}
\mathrm{low},      & 0 \le R < 25, \\
\mathrm{medium},   & 25 \le R < 50, \\
\mathrm{high},     & 50 \le R < 75, \\
\mathrm{critical}, & 75 \le R \le 100.
\end{cases}
$$

### Логические условия risk-сигналов

Для краткости используются следующие обозначения:

| Обозначение | Смысл |
|---|---|
| `NT` | тип сети |
| `TZC` | страна, соответствующая timezone |
| `LC` | регион языка браузера |
| `IPprev` | IP из предыдущей проверки |
| `IPcur` | текущий IP |
| `CTRprev` | страна из предыдущей проверки |
| `CTRcur` | текущая страна |
| `ASNprev` | ASN из предыдущей проверки |
| `ASNcur` | текущий ASN |
| `FPprev` | fingerprint из предыдущей проверки |
| `FPcur` | текущий fingerprint |
| `GPUprev` | WebGL renderer из предыдущей проверки |
| `GPUcur` | текущий WebGL renderer |

Основные условия:

$$
\begin{aligned}
C_{1}  &\equiv NT=\text{datacenter/hosting}, \\
C_{2}  &\equiv Hist\ne\varnothing \land CTRcur\notin Hist, \\
C_{3}  &\equiv Seen\land Hist\ne\varnothing\land CTRcur\notin Hist, \\
C_{4}  &\equiv TZC\ne\varnothing\land CTRcur\ne\mathrm{UNKNOWN}\land TZC\ne CTRcur, \\
C_{5}  &\equiv LC\ne\varnothing\land LC\notin CommonLang(CTRcur), \\
C_{6}  &\equiv FL5>10, \\
C_{7}  &\equiv DL10>30, \\
C_{8}  &\equiv RQ2>120, \\
C_{9}  &\equiv WL=1, \\
C_{10} &\equiv V6=0.
\end{aligned}
$$

$$
\begin{aligned}
C_{11} &\equiv IPprev\ne\varnothing\land IPcur\ne\varnothing\land IPprev\ne IPcur, \\
C_{12} &\equiv CTRprev\ne\varnothing\land CTRcur\ne\varnothing\land CTRprev\ne CTRcur, \\
C_{13} &\equiv ASNprev\ne\varnothing\land ASNcur\ne\varnothing\land ASNprev\ne ASNcur, \\
C_{14} &\equiv TZprev\ne TZcur\land \neg C_{12}, \\
C_{15} &\equiv FPprev=FPcur\land (C_{11}\lor C_{12}\lor C_{13}), \\
C_{16} &\equiv GPUprev\ne\varnothing\land GPUcur\ne\varnothing\land GPUprev\ne GPUcur, \\
C_{17} &\equiv Conn\in\{\mathrm{cellular},\mathrm{none}\}\land NT=\text{datacenter/hosting}, \\
C_{18} &\equiv Touch>0\land Platform=\mathrm{Windows}, \\
C_{19} &\equiv |Skew|>120000, \\
C_{20} &\equiv Bat\le10\land Chg=0, \\
C_{21} &\equiv BatAPI=0, \\
C_{22} &\equiv Heap>80, \\
C_{23} &\equiv Lag>80.
\end{aligned}
$$

Пример отдельного вклада для признака “то же устройство, другая сеть”:

$$
r_{15}=20\cdot\mathbb{1}\left[FPprev=FPcur\land(IPprev\ne IPcur\lor CTRprev\ne CTRcur\lor ASNprev\ne ASNcur)\right]
$$

Полная формула риска:

$$
\begin{aligned}
R(x)=\min(100,\;&
25I(C_{1})+15I(C_{2})+15I(C_{3})+10I(C_{4})+5I(C_{5}) \\
&+20I(C_{6})+20I(C_{7})+10I(C_{8})+10I(C_{9})+2I(C_{10}) \\
&+18I(C_{11})+18I(C_{12})+12I(C_{13})+8I(C_{14})+20I(C_{15}) \\
&+10I(C_{16})+8I(C_{17})+4I(C_{18})+10I(C_{19}) \\
&+4I(C_{20})+1I(C_{21})+5I(C_{22})+5I(C_{23})
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

Тогда итоговая оценка равна:

$$
R=\min(25+15+20+20+20,100)=100
$$

Уровень риска:

$$
Level(R)=\mathrm{critical}
$$

## Формула экспозиции

Экспозиция показывает, насколько много признаков браузер и сеть раскрывают для идентификации, связывания повторных визитов или антифрод-анализа.

Пусть:

$$
E = \{e_{1},e_{2},\ldots,e_{m}\}
$$

где $E$ - множество exposure-findings.

Для каждого finding $e_{j}$ задаются вес $v_{j}$ и логическое условие $D_{j}(x)$.

$$
J_{j}(x)=
\begin{cases}
1, & D_{j}(x)=\mathrm{true}, \\
0, & D_{j}(x)=\mathrm{false}.
\end{cases}
$$

Итоговая формула:

$$
ES(x)=\min\left(100,\sum_{j=1}^{m}v_{j}J_{j}(x)\right)
$$

Здесь $ES(x)$ - итоговый `exposure_score`.

Уровень экспозиции:

$$
ExposureLevel(ES)=
\begin{cases}
\mathrm{low},      & 0\le ES<25, \\
\mathrm{medium},   & 25\le ES<50, \\
\mathrm{high},     & 50\le ES<75, \\
\mathrm{critical}, & 75\le ES\le100.
\end{cases}
$$

### Логические условия exposure-findings

$$
\begin{aligned}
D_{1}  &\equiv NT=\text{datacenter/hosting}, \\
D_{2}  &\equiv WL=1, \\
D_{3}  &\equiv V6=0, \\
D_{4}  &\equiv TZC\ne\varnothing\land TZC\ne CTRcur, \\
D_{5}  &\equiv LC\ne\varnothing\land LC\ne CTRcur, \\
D_{6}  &\equiv FPprev=FPcur\land(IPprev\ne IPcur\lor CTRprev\ne CTRcur\lor ASNprev\ne ASNcur), \\
D_{7}  &\equiv GPUcur\ne\varnothing, \\
D_{8}  &\equiv WebGL=0, \\
D_{9}  &\equiv Canvas\ne\varnothing, \\
D_{10} &\equiv Audio\ne\varnothing\land Audio\notin\{\mathrm{unavailable},\mathrm{blocked}\}.
\end{aligned}
$$

$$
\begin{aligned}
D_{11} &\equiv Hints=1, \\
D_{12} &\equiv Threads\ne\varnothing, \\
D_{13} &\equiv Mem\ne\varnothing, \\
D_{14} &\equiv BatAPI=1, \\
D_{15} &\equiv |Skew|>120000, \\
D_{16} &\equiv HeapInfo=1, \\
D_{17} &\equiv Lag>80, \\
D_{18} &\equiv NetInfo=1.
\end{aligned}
$$

Полная формула экспозиции:

$$
\begin{aligned}
ES(x)=\min(100,\;&
18J(D_{1})+12J(D_{2})+4J(D_{3})+12J(D_{4})+5J(D_{5}) \\
&+24J(D_{6})+10J(D_{7})+1J(D_{8})+8J(D_{9})+6J(D_{10}) \\
&+6J(D_{11})+4J(D_{12})+4J(D_{13})+5J(D_{14}) \\
&+10J(D_{15})+2J(D_{16})+5J(D_{17})+2J(D_{18})
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
