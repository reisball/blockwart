from __future__ import annotations

import json
from collections.abc import Callable
from functools import cache, lru_cache
from importlib.resources import files
from typing import Any

from fastapi import Request

DEFAULT_LOCALE = "en"
LOCALE_COOKIE = "blockwart-language"


@lru_cache(maxsize=1)
def supported_locales() -> tuple[str, ...]:
    locale_dir = files("blockwart.ui").joinpath("locales")
    return tuple(
        sorted(
            resource.name.removesuffix(".json")
            for resource in locale_dir.iterdir()
            if resource.is_file() and resource.name.endswith(".json")
        )
    )


@cache
def load_catalog(locale: str) -> dict[str, str]:
    selected = locale if locale in supported_locales() else DEFAULT_LOCALE
    resource = files("blockwart.ui").joinpath(
        "locales",
        f"{selected}.json",
    )
    raw_catalog = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(raw_catalog, dict):
        raise ValueError(f"Locale catalog {selected!r} must be a JSON object")
    return {
        str(key): str(value)
        for key, value in raw_catalog.items()
    }


def resolve_locale(request: Request) -> str:
    candidates = [
        request.query_params.get("lang", ""),
        request.cookies.get(LOCALE_COOKIE, ""),
        *_accepted_languages(request.headers.get("accept-language", "")),
    ]
    supported = set(supported_locales())
    for candidate in candidates:
        normalized = candidate.strip().lower().replace("_", "-")
        if normalized in supported:
            return normalized
        base = normalized.split("-", 1)[0]
        if base in supported:
            return base
    return DEFAULT_LOCALE


def translation_context(request: Request) -> dict[str, Any]:
    locale = resolve_locale(request)
    catalog = load_catalog(locale)
    fallback = load_catalog(DEFAULT_LOCALE)

    def translate(key: str, **values: object) -> str:
        message = catalog.get(key, fallback.get(key, key))
        return message.format(**values) if values else message

    translator: Callable[..., str] = translate
    return {
        "locale": locale,
        "supported_locales": supported_locales(),
        "t": translator,
    }


def _accepted_languages(value: str) -> list[str]:
    weighted: list[tuple[float, str]] = []
    for item in value.split(","):
        language, *parameters = item.strip().split(";")
        if not language or language == "*":
            continue
        quality = 1.0
        for parameter in parameters:
            key, separator, raw_quality = parameter.strip().partition("=")
            if key == "q" and separator:
                try:
                    quality = float(raw_quality)
                except ValueError:
                    quality = 0.0
        weighted.append((quality, language))
    return [
        language
        for _, language in sorted(
            weighted,
            key=lambda item: item[0],
            reverse=True,
        )
    ]
