from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx


OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3:1b")
USE_LLM = os.getenv("USE_LLM", "0").lower() in {"1", "true", "yes", "on"}


def clean_llm_text(text: str) -> str:
    text = re.sub(r"[*_`#>]+", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def fallback_explanation(report: dict[str, Any]) -> str:
    score = report["risk_score"]
    level = report["risk_level"]
    summary = report["summary"]
    signals = report["signals"]
    exposures = report.get("exposures", [])

    if not signals:
        return (
            f"Риск сессии низкий: {score}/100. Система не нашла сильных признаков VPN, прокси "
            "или компрометации аккаунта. Это не гарантирует полную безопасность, но текущая "
            "картина выглядит обычной для учебного антифрод-мониторинга."
        )

    top = sorted(signals, key=lambda item: item["points"], reverse=True)[:5]
    reasons = "\n".join(f"{idx}. {item['explanation']}" for idx, item in enumerate(top, start=1))
    top_exposures = sorted(exposures, key=lambda item: item["points"], reverse=True)[:5]
    exposure_text = "\n".join(
        f"{idx}. {item['title']}: {item['evidence']} Рекомендация: {item['recommendation']}"
        for idx, item in enumerate(top_exposures, start=1)
    )
    if not exposure_text:
        exposure_text = "Существенных browser/network exposure по доступным данным не найдено."

    action = [
        "Сравнить текущий fingerprint с предыдущими проверками.",
        "Проверить IP/ASN reputation и страну входа.",
        "Посмотреть серверные журналы поведения: ошибки входа, скачивания, частоту запросов.",
    ]
    return (
        f"Формульный анализ сессии: риск {level}, {score}/100. "
        f"Оценка экспозиции устройства и браузера: {report.get('exposure_level', 'low')}, {report.get('exposure_score', 0)}/100.\n\n"
        f"Контекст: IP-регион {summary['country']}, тип сети {report['network_type']}, "
        f"ASN: {summary['asn'] or 'не указан'}.\n\n"
        f"Главные причины:\n{reasons}\n\n"
        f"Уязвимости и экспозиции по данным пользователя:\n{exposure_text}\n\n"
        "Интерпретация: система не утверждает, что пользователь точно использует VPN или что аккаунт "
        "точно взломан. Вывод основан только на переданных признаках этой сессии: сеть, браузерный "
        "fingerprint, локальные характеристики устройства и поведенческие счетчики.\n\n"
        "Что проверить дальше:\n"
        + "\n".join(f"{idx}. {item}" for idx, item in enumerate(action, start=1))
    )


async def explain_with_local_llm(report: dict[str, Any]) -> dict[str, Any]:
    deterministic = fallback_explanation(report)
    if not USE_LLM:
        return {"provider": "deterministic-formula", "text": deterministic}

    compact_brief = deterministic
    prompt = (
        "Ты объясняешь результат учебной антифрод-системы студенту на русском языке.\n"
        "Задача: перепиши готовый технический бриф в ясный человеческий анализ.\n"
        "Жесткие правила:\n"
        "- не добавляй факты, которых нет в брифе или JSON;\n"
        "- не называй событие доказанным взломом, это только вероятностный риск;\n"
        "- не советуй случайные утилиты, команды и внешние инструменты;\n"
        "- не используй Markdown, звездочки, жирный шрифт, заголовки с # и таблицы;\n"
        "- не пиши слишком длинно: 4 коротких абзаца и 3 пункта что проверить дальше;\n"
        "- стиль: уверенно, понятно, без канцелярита, как хороший преподаватель на защите лабораторной.\n\n"
        f"Готовый бриф:\n{compact_brief}\n\n"
        f"JSON для проверки фактов:\n{json.dumps(report, ensure_ascii=False, indent=2)}"
    )

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.25},
                },
            )
            response.raise_for_status()
            text = response.json().get("response", "").strip()
            if text:
                return {"provider": f"ollama:{OLLAMA_MODEL}", "text": clean_llm_text(text)}
    except Exception as exc:
        return {
            "provider": "fallback",
            "error": str(exc),
            "text": fallback_explanation(report),
        }

    return {"provider": "fallback", "text": fallback_explanation(report)}
