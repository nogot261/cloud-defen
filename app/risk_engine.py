from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RiskSignal:
    title: str
    severity: str
    points: int
    explanation: str


@dataclass(frozen=True)
class ExposureFinding:
    title: str
    category: str
    severity: str
    points: int
    evidence: str
    recommendation: str


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _network_type(ip: str, asn: str) -> str:
    text = f"{ip} {asn}".lower()
    hosting_markers = (
        "hosting",
        "cloud",
        "data",
        "datacenter",
        "vps",
        "vpn",
        "nano",
        "hetzner",
        "ovh",
        "amazon",
        "google",
        "microsoft",
        "digitalocean",
    )
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.")

    if ip.startswith(private_prefixes):
        return "local/private"
    if any(marker in text for marker in hosting_markers):
        return "datacenter/hosting"
    return "residential/unknown"


def _country_from_timezone(timezone: str) -> str | None:
    tz_map = {
        "Europe/Moscow": "RU",
        "Europe/Riga": "LV",
        "Europe/Warsaw": "PL",
        "Europe/Berlin": "DE",
        "Asia/Yerevan": "AM",
        "Asia/Almaty": "KZ",
        "America/New_York": "US",
    }
    return tz_map.get(timezone)


def _language_region(accept_language: str) -> str | None:
    first = accept_language.split(",")[0].strip()
    if "-" not in first:
        return None
    return first.split("-")[-1].upper()


def _changed(current: Any, previous: Any) -> bool:
    return current not in (None, "", []) and previous not in (None, "", []) and current != previous


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _bool_text(value: Any) -> str:
    return "да" if bool(value) else "нет"


def _exposure_summary(findings: list[ExposureFinding]) -> dict[str, Any]:
    score = min(sum(finding.points for finding in findings), 100)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    by_category: dict[str, int] = {}
    for finding in findings:
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    return {"score": score, "level": level, "by_category": by_category}


def calculate_exposures(
    *,
    ip: str,
    country: str,
    asn: str,
    timezone: str,
    accept_language: str,
    network_type: str,
    lang_region: str | None,
    tz_country: str | None,
    previous_snapshot: dict[str, Any],
    fingerprint_hash: str,
    device_profile: dict[str, Any],
    network_profile: dict[str, Any],
    webrtc_leak: bool,
    ipv6_enabled: bool,
) -> list[ExposureFinding]:
    findings: list[ExposureFinding] = []
    battery = device_profile.get("battery") or {}
    clock = device_profile.get("clock") or {}
    performance_profile = device_profile.get("performance") or {}
    memory = performance_profile.get("memory") or {}
    ua_hints = device_profile.get("ua_hints") or {}

    if network_type == "datacenter/hosting":
        findings.append(
            ExposureFinding(
                "VPN/VPS-подобная сеть",
                "network",
                "high",
                18,
                f"ASN/провайдер: {asn or 'не указан'}, классификация сети: {network_type}.",
                "Для реального аккаунта проверить reputation IP/ASN и требовать дополнительное подтверждение входа.",
            )
        )

    if webrtc_leak:
        findings.append(
            ExposureFinding(
                "WebRTC раскрывает сетевые кандидаты",
                "browser",
                "medium",
                12,
                "Браузер отдал WebRTC-кандидаты, которые могут дополнять основной IP-профиль.",
                "Отключить WebRTC leak в браузере/VPN или использовать браузерный профиль с защитой WebRTC.",
            )
        )

    if not ipv6_enabled:
        findings.append(
            ExposureFinding(
                "IPv6 не виден",
                "network",
                "low",
                4,
                "Проверка IPv6 не вернула публичный IPv6 адрес.",
                "Это не уязвимость само по себе, но полезно сравнить с обычной сетью пользователя.",
            )
        )

    if tz_country and country != "UNKNOWN" and tz_country != country:
        findings.append(
            ExposureFinding(
                "Timezone конфликтует с IP-страной",
                "consistency",
                "medium",
                12,
                f"IP country={country}, timezone={timezone}.",
                "Согласовать timezone с заявленным регионом или учитывать это как антифрод-сигнал.",
            )
        )

    if lang_region and country != "UNKNOWN" and lang_region != country:
        findings.append(
            ExposureFinding(
                "Язык браузера выделяет пользователя",
                "fingerprint",
                "low",
                5,
                f"Accept-Language={accept_language}, IP country={country}.",
                "Для приватности использовать профиль языка, соответствующий выбранному региону.",
            )
        )

    previous_ip = previous_snapshot.get("ip")
    previous_country = str(previous_snapshot.get("country") or "").upper()
    previous_asn = previous_snapshot.get("asn")
    previous_fingerprint = previous_snapshot.get("browser_fingerprint_hash")
    if fingerprint_hash and previous_fingerprint == fingerprint_hash and (
        _changed(ip, previous_ip) or _changed(country, previous_country) or _changed(asn, previous_asn)
    ):
        findings.append(
            ExposureFinding(
                "Смена сети при стабильном устройстве",
                "vpn-change",
                "critical",
                24,
                f"Fingerprint совпал, но сеть изменилась: IP {previous_ip} -> {ip}, country {previous_country or 'нет'} -> {country}, ASN {previous_asn or 'нет'} -> {asn or 'нет'}.",
                "Считать это сильным индикатором VPN/proxy и проверять аккаунт дополнительным фактором.",
            )
        )

    webgl_renderer = device_profile.get("webgl_renderer")
    if webgl_renderer:
        findings.append(
            ExposureFinding(
                "GPU/WebGL хорошо идентифицирует устройство",
                "fingerprint",
                "medium",
                10,
                f"WebGL renderer: {webgl_renderer}.",
                "Если нужна приватность, использовать браузер, который маскирует WebGL renderer.",
            )
        )
    elif device_profile.get("webgl_supported") is False:
        findings.append(
            ExposureFinding(
                "WebGL скрыт или недоступен",
                "browser",
                "info",
                1,
                "Браузер не предоставил WebGL.",
                "Это снижает точность fingerprint, но может само выглядеть как privacy-защита.",
            )
        )

    if device_profile.get("canvas_hash") not in (None, "", "unavailable"):
        findings.append(
            ExposureFinding(
                "Canvas fingerprint доступен",
                "fingerprint",
                "medium",
                8,
                f"Canvas hash: {str(device_profile.get('canvas_hash'))[:16]}...",
                "Canvas hash можно использовать для связи повторных визитов одного браузерного профиля.",
            )
        )

    if device_profile.get("audio_hash") not in (None, "", "unavailable", "blocked"):
        findings.append(
            ExposureFinding(
                "Audio fingerprint доступен",
                "fingerprint",
                "low",
                6,
                f"Audio hash: {str(device_profile.get('audio_hash'))[:16]}...",
                "Audio fingerprint усиливает связку устройства между сессиями.",
            )
        )

    if ua_hints.get("available"):
        model = _first_present(ua_hints.get("model"), "model hidden")
        findings.append(
            ExposureFinding(
                "UA Client Hints раскрыты",
                "browser",
                "low",
                6,
                f"Platform={ua_hints.get('platform')}, arch={ua_hints.get('architecture')}, bitness={ua_hints.get('bitness')}, model={model}.",
                "Client Hints полезны для классификации устройства; часть данных можно ограничивать политиками браузера.",
            )
        )

    if device_profile.get("hardware_concurrency") not in (None, "", "unknown"):
        findings.append(
            ExposureFinding(
                "Количество CPU-потоков доступно",
                "device",
                "low",
                4,
                f"hardwareConcurrency={device_profile.get('hardware_concurrency')}.",
                "Это не модель CPU, но сильный признак класса устройства.",
            )
        )

    if device_profile.get("device_memory_gb") not in (None, "", "unknown"):
        findings.append(
            ExposureFinding(
                "RAM bucket доступен",
                "device",
                "low",
                4,
                f"deviceMemory={device_profile.get('device_memory_gb')} GB.",
                "Это приблизительная оценка памяти, которую можно использовать в fingerprint.",
            )
        )

    if battery.get("supported"):
        findings.append(
            ExposureFinding(
                "Battery API раскрывает состояние питания",
                "device",
                "low",
                5,
                f"Заряд={battery.get('level_percent')}%, charging={_bool_text(battery.get('charging'))}.",
                "Заряд батареи помогает отличать реальные мобильные/ноутбучные устройства от части виртуальных сред.",
            )
        )

    skew = clock.get("server_skew_ms")
    if isinstance(skew, (int, float)) and abs(skew) > 120_000:
        findings.append(
            ExposureFinding(
                "Локальные часы сбиты",
                "consistency",
                "medium",
                10,
                f"Расхождение с сервером примерно {round(abs(skew) / 1000)} секунд.",
                "Синхронизировать системное время; для антифрода это признак необычной среды.",
            )
        )

    if memory.get("supported"):
        findings.append(
            ExposureFinding(
                "JS heap memory доступна",
                "performance",
                "info",
                2,
                f"JS heap: {memory.get('used_js_heap_size_human')} / {memory.get('js_heap_size_limit_human')}.",
                "Это не вся RAM устройства, но показатель состояния браузерной вкладки.",
            )
        )

    event_loop_lag = performance_profile.get("event_loop_lag_ms")
    if isinstance(event_loop_lag, (int, float)) and event_loop_lag > 80:
        findings.append(
            ExposureFinding(
                "Браузерная вкладка заметно тормозит",
                "performance",
                "low",
                5,
                f"Event-loop lag около {event_loop_lag} мс.",
                "При интерпретации fingerprint учитывать нагрузку вкладки и устройства.",
            )
        )

    connection = network_profile.get("effective_type") or network_profile.get("connection_type")
    if connection and connection != "unknown":
        findings.append(
            ExposureFinding(
                "Network Information API доступен",
                "network",
                "info",
                2,
                f"effectiveType={network_profile.get('effective_type')}, downlink={network_profile.get('downlink_mbps')}, rtt={network_profile.get('rtt_ms')}.",
                "Эти данные помогают отличить мобильную, слабую или десктопную сеть.",
            )
        )

    return sorted(findings, key=lambda finding: (SEVERITY_RANK[finding.severity], finding.points), reverse=True)


def calculate_risk(session: dict[str, Any]) -> dict[str, Any]:
    ip = str(session.get("ip") or "")
    asn = str(session.get("asn") or "")
    country = str(session.get("country") or "UNKNOWN").upper()
    timezone = str(session.get("timezone") or "")
    accept_language = str(session.get("accept_language") or "")
    previous_countries = [str(c).upper() for c in session.get("previous_countries", [])]
    failed_logins = int(session.get("failed_logins_last_5_min") or 0)
    downloads = int(session.get("downloaded_docs_last_10_min") or 0)
    protected_requests = int(session.get("protected_requests_last_2_min") or 0)
    device_seen_before = bool(session.get("device_seen_before"))
    webrtc_leak = bool(session.get("webrtc_leak"))
    ipv6_enabled = bool(session.get("ipv6_enabled"))
    device_profile = session.get("device_profile") or {}
    network_profile = session.get("network_profile") or {}
    previous_snapshot = session.get("previous_snapshot") or {}
    fingerprint_hash = str(session.get("browser_fingerprint_hash") or "")
    battery = device_profile.get("battery") or {}
    performance_profile = device_profile.get("performance") or {}
    clock = device_profile.get("clock") or {}

    signals: list[RiskSignal] = []
    network_type = _network_type(ip, asn)
    tz_country = _country_from_timezone(timezone)
    lang_region = _language_region(accept_language)

    if network_type == "datacenter/hosting":
        signals.append(
            RiskSignal(
                "Инфраструктурная сеть",
                "high",
                25,
                "IP или ASN похож на датацентр, VPS, VPN или облачного провайдера, а не на обычного домашнего оператора.",
            )
        )

    if previous_countries and country not in previous_countries:
        signals.append(
            RiskSignal(
                "Новая страна для аккаунта",
                "medium",
                15,
                f"Текущая страна {country} раньше не встречалась в истории аккаунта: {', '.join(previous_countries)}.",
            )
        )

    if device_seen_before and previous_countries and country not in previous_countries:
        signals.append(
            RiskSignal(
                "Известное устройство, новый регион",
                "high",
                15,
                "Fingerprint устройства уже был замечен ранее, но сетевой регион изменился. Это часто бывает при VPN или прокси.",
            )
        )

    if tz_country and country != "UNKNOWN" and tz_country != country:
        signals.append(
            RiskSignal(
                "Часовой пояс не совпадает с IP",
                "medium",
                10,
                f"Браузер сообщает timezone {timezone}, а IP указывает на страну {country}.",
            )
        )

    common_language_regions = {country}
    if country == "LV":
        common_language_regions.update({"RU", "EN"})
    if country == "KZ":
        common_language_regions.update({"RU", "EN"})
    if lang_region and lang_region not in common_language_regions:
        signals.append(
            RiskSignal(
                "Язык браузера слабо согласуется с регионом",
                "low",
                5,
                f"Основной язык {lang_region} не выглядит типичным для IP-региона {country}. Сам по себе это слабый сигнал.",
            )
        )

    if failed_logins > 10:
        signals.append(
            RiskSignal(
                "Много неудачных входов",
                "high",
                20,
                f"За последние 5 минут было {failed_logins} неудачных попыток входа.",
            )
        )

    if downloads > 30:
        signals.append(
            RiskSignal(
                "Массовое скачивание",
                "high",
                20,
                f"После входа скачано документов за короткий период: {downloads}.",
            )
        )

    if protected_requests > 120:
        signals.append(
            RiskSignal(
                "Нетипичная активность API",
                "medium",
                10,
                f"За 2 минуты выполнено {protected_requests} запросов к защищенным ресурсам.",
            )
        )

    if webrtc_leak:
        signals.append(
            RiskSignal(
                "WebRTC раскрывает дополнительный адрес",
                "medium",
                10,
                "Через WebRTC обнаружен дополнительный сетевой адрес, который может конфликтовать с заявленной IP-географией.",
            )
        )

    if not ipv6_enabled:
        signals.append(
            RiskSignal(
                "IPv6 отсутствует",
                "info",
                2,
                "Отсутствие IPv6 не доказывает VPN, но иногда встречается у туннельных или прокси-конфигураций.",
            )
        )

    previous_ip = previous_snapshot.get("ip")
    previous_country = str(previous_snapshot.get("country") or "").upper()
    previous_asn = previous_snapshot.get("asn")
    previous_timezone = previous_snapshot.get("timezone")
    previous_fingerprint = previous_snapshot.get("browser_fingerprint_hash")
    previous_gpu = (previous_snapshot.get("device_profile") or {}).get("webgl_renderer")

    if _changed(ip, previous_ip):
        signals.append(
            RiskSignal(
                "IP изменился с прошлой проверки",
                "high",
                18,
                f"Предыдущий IP был {previous_ip}, текущий IP {ip}. При неизменном устройстве это сильный признак смены сети или VPN.",
            )
        )

    if _changed(country, previous_country):
        signals.append(
            RiskSignal(
                "Страна IP изменилась",
                "high",
                18,
                f"Страна изменилась с {previous_country} на {country}. Это один из главных признаков переключения VPN-региона.",
            )
        )

    if _changed(asn, previous_asn):
        signals.append(
            RiskSignal(
                "Провайдер/ASN изменился",
                "medium",
                12,
                f"Сетевой провайдер изменился: было '{previous_asn}', стало '{asn}'. Это часто видно при переключении между VPN-узлами.",
            )
        )

    if _changed(timezone, previous_timezone) and not _changed(country, previous_country):
        signals.append(
            RiskSignal(
                "Timezone изменился без смены страны",
                "medium",
                8,
                f"Timezone изменился с {previous_timezone} на {timezone}, хотя IP-страна не изменилась.",
            )
        )

    if fingerprint_hash and previous_fingerprint == fingerprint_hash and (
        _changed(ip, previous_ip) or _changed(country, previous_country) or _changed(asn, previous_asn)
    ):
        signals.append(
            RiskSignal(
                "То же устройство, другая сеть",
                "high",
                20,
                "Стабильный браузерный fingerprint совпал с прошлой проверкой, но сетевые признаки изменились. Это очень похоже на смену VPN/proxy.",
            )
        )

    webgl_renderer = device_profile.get("webgl_renderer")
    if _changed(webgl_renderer, previous_gpu):
        signals.append(
            RiskSignal(
                "GPU/WebGL изменился",
                "medium",
                10,
                f"WebGL renderer изменился: было '{previous_gpu}', стало '{webgl_renderer}'. Это может быть другой браузер, устройство или антидетект/виртуализация.",
            )
        )

    if network_profile.get("connection_type") in {"cellular", "none"} and network_type == "datacenter/hosting":
        signals.append(
            RiskSignal(
                "Тип соединения конфликтует с сетью",
                "medium",
                8,
                "Браузер сообщает один тип соединения, а IP/ASN выглядит как датацентр или VPN-инфраструктура.",
            )
        )

    if device_profile.get("touch_points", 0) > 0 and "Win" in str(device_profile.get("platform", "")):
        signals.append(
            RiskSignal(
                "Гибридный fingerprint устройства",
                "low",
                4,
                "Устройство сообщает touch-ввод вместе с desktop-платформой. Это не риск само по себе, но полезно для fingerprint-сравнения.",
            )
        )

    clock_skew_ms = abs(float(clock.get("server_skew_ms") or 0))
    if clock_skew_ms > 120_000:
        signals.append(
            RiskSignal(
                "Системное время заметно сбито",
                "medium",
                10,
                f"Время устройства отличается от серверного примерно на {round(clock_skew_ms / 1000)} секунд. Для антифрода это признак странной среды или неверных настроек.",
            )
        )

    if battery.get("supported") and battery.get("level_percent") is not None:
        level = float(battery.get("level_percent") or 0)
        if level <= 10 and not battery.get("charging"):
            signals.append(
                RiskSignal(
                    "Очень низкий заряд батареи",
                    "low",
                    4,
                    f"Батарея устройства на уровне {level:.0f}% и не заряжается. Это не VPN-признак, но полезная характеристика реального устройства.",
                )
            )

    if battery.get("supported") is False:
        signals.append(
            RiskSignal(
                "Battery API недоступен",
                "info",
                1,
                "Браузер не отдал Battery API. Это нормально для многих современных браузеров из-за защиты приватности.",
            )
        )

    memory_usage = performance_profile.get("js_heap_usage_percent")
    if isinstance(memory_usage, (int, float)) and memory_usage > 80:
        signals.append(
            RiskSignal(
                "Высокая загрузка JS-памяти",
                "low",
                5,
                f"JS heap страницы использован примерно на {memory_usage:.0f}%. Это не вся RAM устройства, но показатель нагрузки браузерной вкладки.",
            )
        )

    event_loop_lag = performance_profile.get("event_loop_lag_ms")
    if isinstance(event_loop_lag, (int, float)) and event_loop_lag > 80:
        signals.append(
            RiskSignal(
                "Высокая задержка event loop",
                "low",
                5,
                f"Event loop задерживается примерно на {event_loop_lag:.0f} мс. Устройство или браузерная вкладка могут быть нагружены.",
            )
        )

    exposures = calculate_exposures(
        ip=ip,
        country=country,
        asn=asn,
        timezone=timezone,
        accept_language=accept_language,
        network_type=network_type,
        lang_region=lang_region,
        tz_country=tz_country,
        previous_snapshot=previous_snapshot,
        fingerprint_hash=fingerprint_hash,
        device_profile=device_profile,
        network_profile=network_profile,
        webrtc_leak=webrtc_leak,
        ipv6_enabled=ipv6_enabled,
    )
    exposure_summary = _exposure_summary(exposures)

    score = min(sum(signal.points for signal in signals), 100)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "network_type": network_type,
        "signals": [signal.__dict__ for signal in signals],
        "exposure_score": exposure_summary["score"],
        "exposure_level": exposure_summary["level"],
        "exposure_by_category": exposure_summary["by_category"],
        "exposures": [finding.__dict__ for finding in exposures],
        "summary": {
            "ip": ip,
            "country": country,
            "asn": asn,
            "timezone": timezone,
            "accept_language": accept_language,
            "device_seen_before": device_seen_before,
            "previous_countries": previous_countries,
            "failed_logins_last_5_min": failed_logins,
            "downloaded_docs_last_10_min": downloads,
            "protected_requests_last_2_min": protected_requests,
            "webrtc_leak": webrtc_leak,
            "ipv6_enabled": ipv6_enabled,
            "public_ip_source": session.get("public_ip_source"),
            "browser_fingerprint_hash": fingerprint_hash,
            "device_profile": device_profile,
            "network_profile": network_profile,
            "previous_snapshot": previous_snapshot,
        },
    }
