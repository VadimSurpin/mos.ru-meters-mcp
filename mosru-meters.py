#!/usr/bin/env python3
"""mosru-meters.py — mos.ru в одном файле: QR-вход, счётчики воды и электричества.

Возможности
-----------
- Аутентификация через QR-код: скрипт получает ссылку для входа
  (get_qr_url()), вы показываете её как QR на своём UI или отправляете
  себе; подтверждение — в приложении mos.ru / «Госуслуги Москвы»
  (биометрия/ключ доступа телефона). Поддержан второй фактор: SMS или
  код из приложения-аутентификатора. Альтернативно — вход по паролю с
  proof-of-work (если портал покажет CAPTCHA, автоматизация честно
  останавливается).
- Список помещений (квартир) и счётчиков: номера, типы (ХВС/ГВС),
  сроки и статус поверки, доступность передачи показаний.
- Последние показания (с источником внесения: mos.ru / ГИС / сервисная проверка).
- Полная история показаний воды (архив с 2000 года, дробные значения),
  истории в «Электронном доме» и электричества (тарифы T1/T2/T3).
- Передача новых показаний воды и удаление последнего показания.
- Передача показаний электричества через mos.ru (pgu2/counters → МЭС) —
  по лицевому счёту с квитанции, без учётной записи Мосэнергосбыт.
- Сохранение/восстановление сессии (cookies, права 0600).

Зависимости: requests.

Только свой аккаунт и свои показания. API неофициальный и может измениться.

CLI:
    python mosru-meters.py places                    # помещения с id (--place для команд)
    python mosru-meters.py meters --place 1298746    # счётчики: id, тип (ХВС/ГВС/ЭЛ), поверка
    python mosru-meters.py latest --place 1298746    # последние показания воды и электричества
    python mosru-meters.py latest --place 1298746 --meter "1113272,19751508"
    python mosru-meters.py history --json > h.json   # вся история в JSON
    python mosru-meters.py history --csv > h.csv
    python mosru-meters.py history --meter "1113272,19751508" --limit 30
    python mosru-meters.py water-send --place 1298746 --values "1113272:123,1113273:124"
    python mosru-meters.py electro-send --account 1234567890-12-345 \
        --values "T1:2836,T2:2859,T3:3676"      # через mos.ru, ЛС МЭС с квитанции
    python mosru-meters.py electro-accounts                  # ЛС и счётчики из профиля pgu2
    python mosru-meters.py latest --place 1298746 --account 08296-104-95 --meter 19751508
    python mosru-meters.py electro-send --account 08296-104-95 --meter 19751508 \
        --values "T1:2836,T2:2859,T3:3676"    # через mos.ru
    python mosru-meters.py remove-last --place 1298746 --counter-id 1113272 --yes

Все команды данных принимают --json / --csv / --md (взаимоисключающие;
по умолчанию — Markdown), вывод в stdout.

Библиотечно:
    from mosru import MosRuAuth, MosRuReadings

    auth = MosRuAuth()

    # 1) Получить URL для аутентификации (показать как QR на своём UI,
    #    отправить в телеграм и т.п.)
    url = auth.get_qr_url()

    # 2) Дождаться подтверждения в приложении (при истечении QR обновится
    #    и on_url вызовется с новой ссылкой)
    factor = auth.qr_login(on_url=lambda u: print("URL:", u))
    if factor == SecondFactor.SMS:
        auth.submit_sms_code(input("Код из SMS: "))
    auth.save("mosru_session.json")

    readings = MosRuReadings(auth)
    for place in readings.list_places():
        print(readings.get_water_archive(place))
"""
from __future__ import annotations

import argparse
import calendar
import csv
import getpass
import html.parser
import json
import logging
import math
import os
import re
import secrets
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import date
from typing import Callable, Iterable, Sequence

import requests

__all__ = [
    "MosRuAuth",
    "MosRuReadings",
    "MosEnergoSbyt",
    "SecondFactor",
    "AlreadySubmittedError",
    "ApiError",
    "AuthError",
    "CaptchaRequiredError",
    "MosRuError",
    "ReadingValidationError",
    "TemporaryError",
]

LOGGER = logging.getLogger("mosru")

# ── Константы ───────────────────────────────────────────────────────────────

TIMEOUT = 30

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

TRUSTED_HOSTS = frozenset({"login.mos.ru", "www.mos.ru", "ed.mos.ru", "my.mos.ru"})

BROWSER_HINTS = {
    "Accept-Language": "ru,en;q=0.9",
    "sec-ch-ua": '"Chromium";v="148", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
}

XHR_HEADERS = {
    **BROWSER_HINTS,
    "Accept": "application/json, text/plain, */*",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
}

NAV_HEADERS = {
    **BROWSER_HINTS,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}

MAX_RESPONSE_BYTES = 2_000_000
TRANSIENT_STATUS = (429, 500, 502, 503, 504)
TRANSIENT_CODES = {"retry_later", "service_unavailable", "temporarily_unavailable"}
RETRY_ATTEMPTS = 2  # дополнительные попытки для идемпотентных запросов
RETRY_DELAY = 5

# login.mos.ru
ACS_LOGIN_URL = "https://www.mos.ru/api/acs/v1/login"
ACS_PROBE_URL = "https://www.mos.ru/api/acs/v1/probe"
ACS_PROBE_BACK_URL = "https://www.mos.ru/shared/acs/core0521.html?fieldName=status"
LOGIN_PAGE_URL = "https://login.mos.ru/sps/login/methods/password"
QR_PULL_URL = "https://login.mos.ru/sps/login/methods/headless/qrCode/pull"
QR_REFRESH_URL = "https://login.mos.ru/sps/login/methods/headless/qrCode/refresh"
QR_COMPLETE_URL = "https://login.mos.ru/sps/login/methods/qrCode/complete"
SMS_URL = "https://login.mos.ru/sps/login/methods/sms"
TOTP_PATH = "/sps/login/methods2/totp"

# «Электронный дом» (ed.mos.ru) — показания и счётчики
ED_URL = "https://ed.mos.ru"
ED_API = f"{ED_URL}/api"
ED_REDIRECT_URI = f"{ED_URL}/security/callback/sudir/login"
ED_OAUTH_URL = (
    "https://login.mos.ru/sps/oauth/ae"
    "?scope=openid+profile"
    "&access_type=offline"
    "&response_type=code"
    f"&redirect_uri={ED_REDIRECT_URI}"
    "&client_id=ed.mos.ru"
)
ED_COUNTERS = f"{ED_API}/efp/counters"
ED_WATER_HISTORY_LIST = f"{ED_COUNTERS}/water/historyList"
ED_WATER_HISTORY = f"{ED_COUNTERS}/water/history"
ED_LIGHT_API = f"{ED_API}/efp"
ED_LIGHT_ALL_INDICATIONS = f"{ED_LIGHT_API}/v2/light/allIndications/"
ED_LIGHT_LAST_INDICATION = f"{ED_LIGHT_API}/v2/light/getLastIndication/"

# www.mos.ru utility-meter — архив показаний и список счётчиков воды
WWW_UTILITY_METER = "https://www.mos.ru/api/utility-meter/v1"
WWW_UTILITY_SERVICE_PAGE = "https://www.mos.ru/services/pokazaniya-vodi-i-tepla/new/"

# pgu2/counters — «Приём показаний и оплата электроэнергии» (прокси к МЭС).
# Авторизация: OAuth client_id=mpgu2.0 поверх SSO mos.ru (cookie SESSID),
# лицевой счёт МЭС: "<код плательщика>-<номер>-<код>".
PGU_COUNTERS_API = "https://www.mos.ru/pgu2/counters/api"
PGU_COUNTERS_PAGE = "https://www.mos.ru/pgu2/counters"
MES_TARIFFS = ("T1", "T2", "T3")

COLD_TYPE = "ХВС"
HOT_TYPE = "ГВС"
ELECTRICITY_TYPE_PREFIXES = ("Э",)
ELECTRICITY_TYPES = {"ЭЛ", "ЭЭ", "ЭНС", "ЭЛЕКТРО", "ЭЛЕКТР", "Э/Э"}


# ── Исключения ──────────────────────────────────────────────────────────────


class MosRuError(Exception):
    """Базовая ошибка клиента."""


class AuthError(MosRuError):
    """Ошибка авторизации (сессия истекла, вход не завершён)."""


class CaptchaRequiredError(AuthError):
    """Портал показал CAPTCHA (Yandex SmartCaptcha) — используйте QR-вход."""


class ApiError(MosRuError):
    """Ошибка API сервиса."""


class TemporaryError(ApiError):
    """Временный сбой mos.ru — имеет смысл повторить позже."""


class AlreadySubmittedError(ApiError):
    """Показание за этот расчётный период уже внесено на портале."""


class ReadingValidationError(MosRuError):
    """Показание не прошло локальную валидацию."""


class SecondFactor:
    NONE = "none"
    SMS = "sms"
    TOTP = "totp"
    WEBAUTHN = "webauthn"  # порталом пока не предлагается; зарезервировано


# ── HTTP-сессия ─────────────────────────────────────────────────────────────


def trusted_url(value: str, *, qr: bool = False) -> str:
    """Отклонить посторонние origin до перехода по редиректу или публикации ссылки."""
    parts = urllib.parse.urlsplit(value)
    hosts = {"login.mos.ru"} if qr else TRUSTED_HOSTS
    if (
        parts.scheme != "https"
        or parts.hostname not in hosts
        or parts.port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or any(c in value for c in "\\<>[]()")
        or any(ord(c) <= 32 for c in value)
    ):
        raise ApiError("Недопустимый адрес сервиса mos.ru")
    return value


class MosRuSession(requests.Session):
    """Сессия с браузерными заголовками, проверкой хостов и лимитом ответа.

    my.mos.ru и ed.mos.ru отдают 403 без полного набора браузерных заголовков —
    антибот смотрит именно на них. Прокси из окружения отключены: сессия
    привязана к клиенту.
    """

    def __init__(self) -> None:
        super().__init__()
        self.trust_env = False
        self.hooks["response"].append(self._bounded_response)
        self.headers.update({"User-Agent": USER_AGENT})

    @staticmethod
    def _bounded_response(response, **kwargs):
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(65536):
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise requests.RequestException("Ответ сервиса слишком большой")
                chunks.append(chunk)
        except Exception:
            response.close()
            raise
        response._content = b"".join(chunks)
        response._content_consumed = True
        return response

    def send(self, request, **kwargs):
        trusted_url(request.url)
        kwargs["stream"] = True
        return super().send(request, **kwargs)


def parse_api_response(resp: requests.Response) -> dict:
    """Проверить HTTP-ответ API и вернуть JSON.

    Raises:
        AuthError: сессия истекла (401/403).
        TemporaryError: временный сбой (5xx, 429, code=retry_later).
        ApiError: прочие ошибки (с текстом сервера, если он есть).
    """
    if resp.status_code in (401, 403):
        raise AuthError("Сессия истекла, требуется повторная авторизация")
    if resp.status_code in TRANSIENT_STATUS:
        raise TemporaryError(f"HTTP {resp.status_code}, сервис временно недоступен")
    try:
        data = resp.json()
    except ValueError as err:
        raise ApiError("Неожиданный формат ответа") from err
    if not isinstance(data, dict):
        raise ApiError("Неожиданный формат ответа")

    code = str(data.get("code", "")).lower()
    if code in TRANSIENT_CODES:
        raise TemporaryError(f"сервис временно недоступен ({code})")
    err_text = data.get("error") if isinstance(data.get("error"), str) else None
    if err_text and "уже внесено" in err_text:
        raise AlreadySubmittedError("Показание за период уже внесено")
    if not resp.ok:
        raise ApiError(f"HTTP {resp.status_code}: {err_text or 'запрос отклонён'}")
    if err_text:
        raise ApiError(f"Ошибка API: {err_text}")
    if data.get("error") is True:
        raise ApiError("Ошибка API")
    return data


def cookies_to_dict(session: requests.Session) -> dict:
    return {
        c.name: {"value": c.value, "domain": c.domain or "", "path": c.path or "/"}
        for c in session.cookies
    }


def restore_cookies(session: requests.Session, cookies: dict) -> None:
    for name, data in cookies.items():
        if isinstance(data, dict):
            session.cookies.set(
                name, data["value"],
                domain=data.get("domain") or None,
                path=data.get("path") or "/",
            )
        else:  # старый формат: имя -> значение
            session.cookies.set(name, data)


def save_session_file(session: requests.Session, path: str) -> None:
    """Cookies — это полный доступ к аккаунту: файл создаётся с правами 0600."""
    payload = {"cookies": cookies_to_dict(session)}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)


def load_session_file(session: requests.Session, path: str) -> None:
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    restore_cookies(session, payload.get("cookies", {}))


# ── Proof-of-work формы входа (pOfw.js) ─────────────────────────────────────

POW_ALPHABET = "0123456789/+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
POW_MAX_NONCE_LEN = 25


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        for shift in range(7, -1, -1):
            if (byte >> shift) & 1 == 0:
                bits += 1
            else:
                return bits
    return bits


def _pow_increment(digits: bytearray) -> bool:
    for i in range(len(digits) - 1, -1, -1):
        if digits[i] < len(POW_ALPHABET) - 1:
            digits[i] += 1
            return False
        digits[i] = 0
    return True


def pow_solve(prefix: str, bits: int) -> str:
    """Подобрать nonce: SHA-1(prefix + nonce) должен иметь >= bits нулевых битов."""
    import hashlib

    digits = bytearray(1)
    sha1 = hashlib.sha1
    while True:
        nonce = "".join(POW_ALPHABET[d] for d in digits)
        if leading_zero_bits(sha1((prefix + nonce).encode()).digest()) >= bits:
            return nonce
        if _pow_increment(digits):
            if len(digits) >= POW_MAX_NONCE_LEN:
                raise AuthError("PoW: переполнение счётчика (>25 символов)")
            digits.append(0)


def build_pow(seed: str) -> str:
    """Посчитать proofOfWork из значения скрытого поля формы входа."""
    parts = seed.split(":")
    if len(parts) < 3 or not parts[1].isdigit():
        raise AuthError("PoW: некорректный seed формы входа")
    bits = int(parts[1])
    normalized = seed if seed.endswith(":") else seed + ":"
    return normalized + pow_solve(normalized, bits)


# ── Разбор HTML-форм входа ──────────────────────────────────────────────────


class _FormParser(html.parser.HTMLParser):
    def __init__(self, form_id: str | None = None) -> None:
        super().__init__()
        self._form_id = form_id
        self.action = ""
        self.hidden: dict[str, str] = {}
        self._active = False
        self._found = False

    def handle_starttag(self, tag, attrs):
        values = {k: v or "" for k, v in attrs}
        if tag == "form" and not self._found:
            if self._form_id is None or values.get("id") == self._form_id:
                self._active = True
                self._found = True
                self.action = values.get("action", "")
            return
        if tag != "input" or not self._active or values.get("type", "").lower() != "hidden":
            return
        if values.get("name"):
            self.hidden[values["name"]] = values.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._active:
            self._active = False


def parse_form(html_text: str, *, form_id: str | None = None) -> tuple[str, dict]:
    """(action, hidden-поля) первой или именованной формы на странице."""
    parser = _FormParser(form_id)
    parser.feed(html_text)
    return parser.action, parser.hidden


def _unfinished_login_step(url: str) -> str | None:
    """Путь шага входа, если цепочка остановилась на login.mos.ru."""
    parts = urllib.parse.urlsplit(url)
    if parts.netloc == "login.mos.ru" and parts.path.startswith("/sps/login/"):
        return parts.path
    return None


# ── Вспомогательные функции показаний ───────────────────────────────────────


def normalized_reading(value: float) -> int:
    """Валидация перед округлением: конечное неотрицательное число."""
    if not math.isfinite(value) or value < 0 or value > 1_000_000_000:
        raise ReadingValidationError("Недопустимое показание счётчика")
    return int(round(value))


def period_end_of_month(today: date | None = None) -> str:
    """Последний день месяца (YYYY-MM-DD) — формат расчётного периода портала."""
    day = today or date.today()
    last = calendar.monthrange(day.year, day.month)[1]
    return day.replace(day=last).isoformat()


def submission_period(today: date | None = None) -> str:
    """Расчётный период для отправки — как у фронтенда портала.

    До 3-го числа включительно показание уходит за прошедший месяц
    (конец предыдущего месяца), позже — за текущий.
    """
    day = today or date.today()
    if day.day <= 3:
        day = day.replace(day=1)
        if day.month == 1:
            day = day.replace(year=day.year - 1, month=12)
        else:
            day = day.replace(month=day.month - 1)
    return period_end_of_month(day)


def parse_indication_value(value) -> float | None:
    """Показание портала → число: ``533`` / ``533.0`` / ``"533 м³"`` / ``"532,415 м³"``."""
    if value in ("", None):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    for suffix in ("м³", "м3", "м\u00b3"):
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
    text = text.replace("\xa0", "").replace(" ", "").replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return None


def normalize_period(value) -> str:
    """Период/дату портала привести к единому формату YYYY-MM-DD.

    Вода приходит как "2026-11-30", электричество — как
    "2026-11-17T00:00:00+03:00"; в таблицах оба вида выглядят одинаково.
    """
    if value in ("", None):
        return ""
    return str(value)[:10]


def counter_type(counter: dict) -> str:
    return str(counter.get("type") or "").strip().upper()


def is_electricity(counter: dict) -> bool:
    t = counter_type(counter)
    return t in ELECTRICITY_TYPES or t.startswith(ELECTRICITY_TYPE_PREFIXES)


def is_cold_water(counter: dict) -> bool:
    return counter_type(counter) == COLD_TYPE


def is_hot_water(counter: dict) -> bool:
    return counter_type(counter) == HOT_TYPE


def _norm(value) -> object:
    """Пустые строки/None → None."""
    return None if value in ("", None) else value


def _normalize_water_history_item(raw: dict) -> dict:
    """Элемент ЭД historyList (data.periods): {period, periodDate, counters:[…]}.

    Показание приходит строкой с единицами ("532,415 м³") — приводится к числу.
    """
    counters = []
    for c in raw.get("counters") or []:
        indication_raw = _norm(c.get("indication"))
        counters.append(
            {
                "type": c.get("typeName") or "",
                "number": _norm(c.get("num")),
                "indication": parse_indication_value(indication_raw),
                "indication_raw": indication_raw,
                "can_submit": bool(c.get("enableTransfer")),
                "available": c.get("isAvailable", True),
            }
        )
    return {
        "period": raw.get("period") or "",
        "period_date": (raw.get("periodDate") or "")[:10] or None,
        "counters": counters,
    }


def _normalize_water_details_item(raw: dict) -> dict:
    """Элемент деталей истории воды (water/history?date=…)."""
    return {
        "type": raw.get("typeName") or "",
        "number": _norm(raw.get("num")),
        "input_date": _norm(raw.get("inputDate")),
        "indication": parse_indication_value(raw.get("indication")),
        "indication_raw": _norm(raw.get("indication")),
        "consumption": parse_indication_value(raw.get("consumption")),
        "inspection_end_date": _norm(raw.get("endDate")),
        "can_submit": bool(raw.get("enableTransfer")),
        "unavailable_reason": _norm(raw.get("transferUnavailableReason")),
    }


def _normalize_archive_item(raw: dict) -> dict:
    """Элемент архива utility-meter: {indication, period, source, readonly}."""
    return {
        "period": raw.get("period") or "",
        "indication": parse_indication_value(raw.get("indication")),
        "source": _norm(raw.get("source")),
        "readonly": bool(raw.get("readonly")),
    }


def _normalize_electricity_history_item(raw: dict) -> dict:
    """Элемент истории электричества (тарифы приходят полями nameT1/valueT1/…)."""
    tariffs = []
    for i in (1, 2, 3):
        name = raw.get(f"nameT{i}")
        if name in (None, ""):
            continue
        tariffs.append(
            {
                "key": f"T{i}",
                "name": name,
                "value": _norm(raw.get(f"valueT{i}")),
                "usage": _norm(raw.get(f"usageT{i}")),
            }
        )
    return {
        "meter_number": _norm(raw.get("meterNumber")),
        "date": _norm(raw.get("dateLastMeterReadings")),
        "source": _norm(raw.get("sourceCaption")),
        "inspection_end_date": _norm(raw.get("dateEndMPI")),
        "tariffs": tariffs,
    }


def _normalize_electricity_last_item(raw: dict) -> dict:
    """Последние показания электричества (getLastIndication): currentValueT*.

    Отдельного id у электросчётчика ЭД не отдаёт — идентификатор для фильтра
    --meter это meterNumber.
    """
    tariffs = []
    for i in (1, 2, 3):
        name = raw.get(f"nameT{i}")
        if name in (None, ""):
            continue
        tariffs.append(
            {
                "key": f"T{i}",
                "name": name,
                "value": _norm(raw.get(f"currentValueT{i}")),
                "usage": None,
            }
        )
    return {
        "meter_number": _norm(raw.get("meterNumber")),
        "date": _norm(raw.get("dateLastMeterReadings")),
        "transfer_period": _norm(raw.get("transferIndicationPeriod")),
        "inspection_end_date": _norm(raw.get("dateEndMPI")),
        "tariffs": tariffs,
    }


# ── Авторизация ─────────────────────────────────────────────────────────────


class MosRuAuth:
    """Вход на mos.ru (login.mos.ru), ведение SSO-сессии, OAuth ed.mos.ru.

    Проверенная цепочка: GET www.mos.ru/api/acs/v1/login (ACS-SESSID +
    authorization request) → первый фактор (QR-код или пароль с PoW) →
    второй фактор (SMS / TOTP, если включён) → страница askToTrust →
    cookie Ltpatoken2. Далее — тихий OAuth на ed.mos.ru поверх SSO.
    """

    def __init__(self, session: MosRuSession | None = None) -> None:
        self.session = session or MosRuSession()
        self._login_referer = "https://login.mos.ru/"
        self._poll_counter = int(time.time() * 1000)
        self._sms_page_url = ""
        self._sms_form_action = ""
        self._sms_hidden: dict = {}
        self._totp_page_url = ""

    # ── Инициализация OAuth ────────────────────────────────────────────

    def init_oauth(self) -> str:
        """Начать OAuth mos.ru; возвращает финальный URL страницы входа."""
        try:
            resp = self.session.get(
                ACS_LOGIN_URL, allow_redirects=True, timeout=TIMEOUT, headers=NAV_HEADERS
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка при инициализации входа") from err
        self._login_referer = resp.url
        return resp.url

    # ── Первый фактор: пароль ──────────────────────────────────────────

    def password_login(self, login: str, password: str, *, bfp: str | None = None) -> str:
        """Вход по логину и паролю (с решением SHA-1 proof-of-work).

        При CAPTCHA поднимается CaptchaRequiredError — автоматизировать её
        нельзя, используйте QR-вход. Возвращает запрошенный второй фактор.
        """
        page_url = self.init_oauth()
        try:
            resp = self.session.get(page_url, timeout=TIMEOUT, headers=NAV_HEADERS)
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка при загрузке страницы входа") from err
        if resp.status_code == 403:
            raise CaptchaRequiredError("Портал отдал страницу входа с кодом 403 (антибот)")

        form_action, _ = parse_form(resp.text)
        pow_match = re.search(
            r'name="proofOfWork"[^>]*value=\'([^\']+)\'', resp.text
        ) or re.search(r'name="proofOfWork"[^>]*value="([^"]+)"', resp.text)
        if not form_action or not pow_match:
            raise CaptchaRequiredError(
                "На странице входа нет стандартной формы с proofOfWork — "
                "вероятно, портал требует CAPTCHA. Используйте QR-вход."
            )
        proof = build_pow(pow_match.group(1))
        if form_action.startswith("/"):
            form_action = f"https://login.mos.ru{form_action}"
        trusted_url(form_action)

        try:
            resp = self.session.post(
                form_action,
                data={
                    "login": login,
                    "password": password,
                    "proofOfWork": proof,
                    "isDelayed": "false",
                    # fingerprint браузера (fingerprintjs); стабильное случайное значение
                    "bfp": bfp or secrets.token_hex(16),
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "ru,en;q=0.9",
                    "Origin": "https://login.mos.ru",
                    "Referer": page_url,
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-User": "?1",
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=False,
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка при отправке формы входа") from err

        resp = self._follow_redirects(resp)
        return self._classify_login_result(resp)

    # ── Первый фактор: QR-код ──────────────────────────────────────────

    def get_qr_url(self) -> str:
        """URL для аутентификации через QR-код.

        Инициализирует OAuth-сессию и создаёт QR-сессию входа. Ссылку можно
        показать как QR-код на любом своём UI (терминал, веб, телеграм-бот),
        отправить себе и отсканировать приложением mos.ru /
        «Госуслуги Москвы». Повторный вызов создаёт новую сессию; для
        ожидания подтверждения используйте qr_login().

        Returns: ссылка вида https://login.mos.ru/sps/...
        """
        return self.start_qr_session()["link"]

    def start_qr_session(self) -> dict:
        """Создать QR-сессию входа. Returns: {"link": str, "expires": float}."""
        try:
            self.init_oauth()
            resp = self.session.post(
                QR_REFRESH_URL,
                data="{}",
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "text/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": self._login_referer,
                },
                timeout=TIMEOUT,
            )
            data = resp.json()
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        except ValueError as err:
            raise ApiError("Неожиданный формат ответа QR-сессии") from err
        if not data.get("link"):
            raise ApiError("QR-сессия не запустилась")
        return {"link": trusted_url(data["link"], qr=True), "expires": data.get("expires", 0)}

    def refresh_qr(self) -> dict:
        """Обновить истёкший QR-код."""
        try:
            resp = self.session.post(
                QR_REFRESH_URL,
                data="{}",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "text/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": self._login_referer,
                },
                timeout=TIMEOUT,
            )
            data = resp.json()
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        return {"link": trusted_url(data.get("link", ""), qr=True), "expires": data.get("expires", 0)}

    def poll_qr(self) -> str:
        """Опросить QR-сессию: showQRCode | askForConfirm | needComplete | needRefresh."""
        try:
            self._poll_counter += 1
            resp = self.session.get(
                QR_PULL_URL,
                params={"_": self._poll_counter},
                headers={
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": self._login_referer,
                },
                allow_redirects=False,
                timeout=TIMEOUT,
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                raise ApiError("Неожиданный редирект QR-сессии")
            return resp.json().get("command", "")
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        except ValueError as err:
            raise ApiError("Неожиданный формат ответа опроса QR") from err

    def complete_qr_auth(self) -> str:
        """Завершить QR-авторизацию: POST qrCode/complete → второй фактор."""
        try:
            resp = self.session.post(
                QR_COMPLETE_URL,
                data={},
                headers={"Referer": self._login_referer},
                allow_redirects=True,
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        if resp.status_code >= 400:
            raise AuthError("Ошибка завершения QR-авторизации")
        return self._classify_login_result(resp)

    def qr_login(
        self,
        *,
        on_url: Callable[[str], None] | None = None,
        poll_interval: float = 3.0,
        timeout: float = 240.0,
    ) -> str:
        """Полный QR-вход: создать ссылку, ждать подтверждения в приложении.

        on_url(url) вызывается для каждой ссылки входа — первой и при
        обновлении истёкшего QR. Ссылку можно рисовать как QR-код на своём
        UI; подтверждение в приложении mos.ru выполняется биометрией или
        ключом доступа телефона — практический «passkey»-путь для mos.ru.

        Returns: запрошенный после подтверждения второй фактор
        (SecondFactor.NONE — вход завершён).
        """
        url = self.start_qr_session()["link"]
        if on_url:
            on_url(url)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            command = self.poll_qr()
            if command == "needRefresh":
                url = self.refresh_qr()["link"]
                if on_url:
                    on_url(url)
            elif command == "needComplete":
                factor = self.complete_qr_auth()
                if factor == SecondFactor.NONE:
                    self._require_ltpatoken()
                return factor
            time.sleep(poll_interval)
        raise AuthError("Время ожидания подтверждения QR истекло")

    # ── Вторые факторы ─────────────────────────────────────────────────

    def submit_sms_code(self, code: str) -> None:
        """Отправить SMS-код подтверждения и завершить вход."""
        if not self._sms_form_action:
            raise AuthError("Нет незавершённого входа с SMS-подтверждением")
        action = self._sms_form_action
        if action.startswith("/"):
            action = f"https://login.mos.ru{action}"
        elif not action.startswith("http"):
            bo = urllib.parse.quote(
                "/sps/oauth/ae?scope=profile+openid+contacts+usr_grps+esia"
                "&response_type=code"
                "&redirect_uri=https://www.mos.ru/api/acs/v1/login/satisfy"
                "&client_id=mos.ru",
                safe="",
            )
            action = f"{SMS_URL}?bo={bo}"
        trusted_url(action)
        try:
            resp = self.session.post(
                action,
                data={**self._sms_hidden, "sms-code": code},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self._sms_page_url or action,
                },
                allow_redirects=True,
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        if resp.status_code >= 400:
            raise AuthError("Неверный SMS-код")
        if "methods2/sms" in resp.url or "/methods/sms" in resp.url:
            self._sms_form_action, self._sms_hidden = parse_form(resp.text)
            raise AuthError("Неверный или просроченный SMS-код")
        self._finish_after_factor(resp)

    def submit_totp_code(self, code: str) -> None:
        """Отправить 6-значный код из приложения-аутентификатора."""
        page_url = self._totp_page_url
        if not page_url:
            raise AuthError("Нет незавершённого входа с TOTP-кодом")
        try:
            resp = self.session.post(
                page_url,
                data={"otp": code},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": page_url,
                    "Origin": "https://login.mos.ru",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-User": "?1",
                },
                allow_redirects=False,
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        resp = self._follow_redirects(resp)
        if urllib.parse.urlsplit(resp.url).path == TOTP_PATH:
            raise AuthError("Неверный код из приложения-аутентификатора")
        self._finish_after_factor(resp)

    # ── Разбор результата шага входа ───────────────────────────────────

    def _classify_login_result(self, resp: requests.Response) -> str:
        """Определить, куда привела цепочка входа, и подготовить следующий шаг."""
        if resp.status_code == 403:
            raise CaptchaRequiredError("HTTP 403: антибот/CAPTCHA при входе")
        url = resp.url
        path = urllib.parse.urlsplit(url).path

        if "/methods2/sms" in path or "/methods/sms" in url:
            self._sms_page_url = resp.url
            self._sms_form_action, self._sms_hidden = parse_form(resp.text)
            return SecondFactor.SMS
        if path == TOTP_PATH:
            self._totp_page_url = resp.url
            return SecondFactor.TOTP
        if "webauthn" in path.lower():
            return SecondFactor.WEBAUTHN
        if "askToTrust" in url:
            self._trust_device(resp)
            return SecondFactor.NONE
        step = _unfinished_login_step(url)
        if step:
            err_text = re.search(
                r'<blockquote[^>]*blockquote-danger[^>]*>.*?blockquote-message">(.*?)</div>',
                resp.text,
                re.S,
            )
            detail = ""
            if err_text:
                detail = re.sub(r"<[^>]+>", "", err_text.group(1)).strip()
            if "captcha" in resp.text.lower() or "SmartCaptcha" in resp.text:
                raise CaptchaRequiredError("Портал показал CAPTCHA: " + detail)
            raise AuthError(f"Вход не завершён (шаг {step}): {detail or 'причина не показана'}")
        return SecondFactor.NONE

    def _finish_after_factor(self, resp: requests.Response) -> None:
        factor = self._classify_login_result(resp)
        if factor != SecondFactor.NONE:
            raise AuthError(f"После второго фактора портал запросил ещё и {factor}")
        self._require_ltpatoken()

    def _require_ltpatoken(self) -> None:
        if "Ltpatoken2" not in {c.name for c in self.session.cookies}:
            raise AuthError("Авторизация не завершена: Ltpatoken2 не установлен")

    def _trust_device(self, resp: requests.Response) -> None:
        """Ответить «доверять устройству» на странице askToTrust."""
        page_url = resp.url
        action, hidden = parse_form(resp.text)
        if action.startswith("/"):
            action = f"https://login.mos.ru{action}"
        elif not action.startswith("http"):
            action = page_url
        try:
            resp2 = self.session.post(
                action,
                data={**hidden, "action": "trust"},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": page_url,
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-User": "?1",
                },
                allow_redirects=False,
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка mos.ru") from err
        resp2 = self._follow_redirects(resp2)
        if 400 <= resp2.status_code < 500:
            raise AuthError("Ошибка подтверждения доверия устройству")
        self._require_ltpatoken()

    def _follow_redirects(self, resp: requests.Response) -> requests.Response:
        """Пройти редиректы вручную с браузерными sec-fetch-* заголовками."""
        for _ in range(15):
            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 303, 307, 308) or not location:
                break
            if not location.startswith("http"):
                location = urllib.parse.urljoin(resp.url, location)
            try:
                resp = self.session.get(
                    location,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": resp.url,
                        "Sec-Fetch-Dest": "document",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "same-site",
                        "Sec-Fetch-User": "?1",
                        "Upgrade-Insecure-Requests": "1",
                    },
                    allow_redirects=False,
                    timeout=TIMEOUT,
                )
            except requests.RequestException as err:
                raise TemporaryError("Сетевая ошибка mos.ru") from err
        return resp

    # ── Состояние сессии ───────────────────────────────────────────────

    def is_alive(self) -> bool:
        """Проверить SSO-сессию официальным probe-эндпоинтом портала.

        Сеть до портала бывает нестабильна — при сетевом сбое одна
        повторная попытка.
        """
        last_err: requests.RequestException | None = None
        for attempt in range(2):
            try:
                resp = self.session.get(
                    ACS_PROBE_URL,
                    params={"back_url": ACS_PROBE_BACK_URL},
                    headers=NAV_HEADERS,
                    allow_redirects=True,
                    timeout=TIMEOUT,
                )
                return "status=200" in resp.url
            except requests.RequestException as err:
                last_err = err
                if attempt == 0:
                    time.sleep(2)
        raise TemporaryError("Сетевая ошибка при проверке сессии") from last_err

    def try_refresh_acst(self) -> bool:
        """Обновить acst (OAuth через Ltpatoken2) — нужно API www.mos.ru.

        Браузер вызывает /api/acs/v1/probe при каждой загрузке страницы;
        если acst истёк, probe тихо выдаёт новый перед редиректом
        на back_url?status=200.
        """
        return self.is_alive()

    def warm_session(self) -> None:
        """GET главной mos.ru — инициализация сессий портала после OAuth."""
        try:
            self.session.get(
                "https://www.mos.ru/", allow_redirects=True, timeout=TIMEOUT, headers=NAV_HEADERS
            )
        except requests.RequestException:
            LOGGER.warning("Не удалось прогреть сессию mos.ru")

    # ── OAuth ed.mos.ru поверх SSO ─────────────────────────────────────

    def authorize_ed(self) -> None:
        """Авторизоваться в ed.mos.ru поверх действующей SSO-сессии."""
        status = self._exchange_ed_code()
        if status in (401, 403) and self._drop_ed_cookies():
            LOGGER.info("ed.mos.ru отклонил устаревшие cookies; повторяем вход без них")
            status = self._exchange_ed_code()
        if status in (401, 403):
            raise AuthError("ed.mos.ru отклонил авторизацию")

    def _exchange_ed_code(self) -> int:
        try:
            resp = self.session.get(
                ED_OAUTH_URL, headers=NAV_HEADERS, allow_redirects=True, timeout=TIMEOUT
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка при входе в ed.mos.ru") from err
        if resp.status_code in TRANSIENT_STATUS:
            raise TemporaryError(f"ed.mos.ru OAuth: HTTP {resp.status_code}")
        code_match = re.search(r"[?&]code=([^&]+)", resp.url)
        if not code_match:
            raise AuthError("Не удалось авторизоваться в ed.mos.ru: код не получен")
        try:
            auth = self.session.post(
                f"{ED_API}/profile/auth/web",
                params={"code": code_match.group(1)},
                headers={**XHR_HEADERS, "Referer": resp.url},
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise TemporaryError("Сетевая ошибка ed.mos.ru auth") from err
        if auth.status_code in TRANSIENT_STATUS:
            raise TemporaryError(f"ed.mos.ru auth: HTTP {auth.status_code}")
        return auth.status_code

    def _drop_ed_cookies(self) -> bool:
        stale = [c for c in self.session.cookies if (c.domain or "").lstrip(".") == "ed.mos.ru"]
        for cookie in stale:
            self.session.cookies.clear(cookie.domain, cookie.path, cookie.name)
        return bool(stale)

    # ── Сохранение/восстановление ──────────────────────────────────────

    def save(self, path: str) -> None:
        save_session_file(self.session, path)

    def restore(self, path: str) -> None:
        load_session_file(self.session, path)

    def cookie_names(self) -> list[str]:
        return sorted(c.name for c in self.session.cookies)


# ── Показания ───────────────────────────────────────────────────────────────


class MosRuReadings:
    """Счётчики, показания и история: ЭД (ed.mos.ru) + www.mos.ru utility-meter."""

    def __init__(self, auth: MosRuAuth) -> None:
        self._auth = auth

    def _request_json(self, method: str, url: str, *, retries: int = 0, **kwargs) -> dict:
        """Запрос к API с ретраями только для идемпотентных вызовов."""
        last_err: Exception = ApiError("Запрос не был выполнен")
        for attempt in range(retries + 1):
            if attempt:
                time.sleep(RETRY_DELAY)
            try:
                resp = self._auth.session.request(method, url, timeout=TIMEOUT, **kwargs)
            except requests.RequestException as err:
                last_err = ApiError("Сетевая ошибка mos.ru")
                continue
            try:
                return parse_api_response(resp)
            except TemporaryError as err:
                last_err = err
        raise last_err

    # ── Помещения ──────────────────────────────────────────────────────

    def list_places(self) -> list[dict]:
        """Квартиры из профиля ЭД: [{user_place_id, paycode, flat, address}]."""
        data = self._request_json(
            "GET", f"{ED_API}/profile/user/getInfo/", headers=XHR_HEADERS, retries=RETRY_ATTEMPTS
        )
        result: list[dict] = []
        seen: set[str] = set()
        for place in (data.get("data") or {}).get("addresses") or []:
            if not isinstance(place, dict) or not place.get("userPlaceId"):
                continue
            user_place_id = str(place["userPlaceId"])
            if user_place_id in seen:
                continue
            seen.add(user_place_id)
            result.append(
                {
                    "user_place_id": user_place_id,
                    "paycode": str(place.get("fls") or ""),
                    "flat": str(place.get("flat") or ""),
                    "address": str(place.get("addressCaption") or place.get("caption") or ""),
                }
            )
        return result

    def find_place(self, paycode: str = "", flat: str = "", user_place_id: str = "") -> dict:
        """Квартира по id помещения, коду плательщика и/или номеру.

        Приоритет: user_place_id → paycode+flat → единственная квартира.
        """
        places = self.list_places()
        if not places:
            raise ApiError("В профиле ed.mos.ru нет ни одной квартиры")
        if user_place_id:
            for place in places:
                if place["user_place_id"] == str(user_place_id):
                    return place
            known = ", ".join(p["user_place_id"] for p in places)
            raise ApiError(
                f"Помещение с id {user_place_id} не найдено. Доступные id: {known}"
            )
        if not paycode and not flat:
            if len(places) > 1:
                known = ", ".join(f"{p['user_place_id']} ({p['address']})" for p in places)
                raise ApiError(
                    "В профиле несколько квартир — укажите id помещения "
                    f"(--place). Доступные: {known}"
                )
            return places[0]
        for place in places:
            if paycode and place["paycode"] != str(paycode):
                continue
            if flat and place["flat"] != str(flat):
                continue
            return place
        raise ApiError(
            f"В профиле ed.mos.ru не найдена квартира ({paycode or ''} {flat or ''})".strip()
        )

    # ── Счётчики ───────────────────────────────────────────────────────

    def _counters_payload(self, user_place_id: str) -> list[dict]:
        data = self._request_json(
            "GET",
            f"{ED_COUNTERS}/listByPayerCode/",
            params={"userPlaceIds": user_place_id},
            headers=XHR_HEADERS,
            retries=RETRY_ATTEMPTS,
        )
        places = data.get("data")
        if not isinstance(places, list):
            raise ApiError("Неожиданный ответ сервиса счётчиков")
        return places

    def get_counters(self, user_place_id: str) -> list[dict]:
        """Активные счётчики квартиры: [{id, name, type}]."""
        result: list[dict] = []
        for place in self._counters_payload(user_place_id):
            for c in place.get("activeCounters") or []:
                counter_id = str(c.get("counterId") or "")
                if not counter_id:
                    continue
                result.append(
                    {"id": counter_id, "name": c.get("num", ""), "type": c.get("typeName", "")}
                )
        return result

    def get_device_info(self, user_place_id: str) -> dict[str, dict]:
        """Статус счётчиков из ЭД: текущее показание, поверка, доступность отправки."""
        result: dict[str, dict] = {}
        for place in self._counters_payload(user_place_id):
            for c in place.get("activeCounters") or []:
                counter_id = str(c.get("counterId") or "")
                if not counter_id or counter_id in result:
                    continue
                last = c.get("lastIndication") or {}
                result[counter_id] = {
                    "type": c.get("typeName", ""),
                    "number": c.get("num", ""),
                    "current_reading": last.get("indication"),
                    "reading_period": normalize_period(last.get("period")),
                    "readonly": not c.get("enableTransfer", True),
                    "inspection_date": c.get("checkUpDate"),
                    "inspection_status": c.get("checkupStatus", ""),
                }
        return result

    def get_meters(self, place: dict, *, include_recent: bool = True) -> list[dict]:
        """Полная карточка счётчиков квартиры: ЭД + www.mos.ru utility-meter.

        Каждый элемент: {id, type, number, inspection_date, inspection_status,
        current_reading, reading_period, can_submit, recent: [{period,
        indication, source}]}. recent (последние показания с источником
        внесения MOSRU / GUIS / SERVICE_CHECK) добавляется только при
        include_recent=True.
        """
        paycode, flat = place.get("paycode") or "", place.get("flat") or ""
        meters: dict[str, dict] = {}

        # База — ЭД (тип, поверка, доступность отправки, последнее показание).
        try:
            for counter_id, meta in self.get_device_info(place["user_place_id"]).items():
                meters[counter_id] = {
                    "id": counter_id,
                    "type": meta["type"],
                    "number": meta["number"],
                    "inspection_date": normalize_period(meta["inspection_date"]),
                    "inspection_status": meta["inspection_status"],
                    "current_reading": meta["current_reading"],
                    "reading_period": normalize_period(meta["reading_period"]),
                    "can_submit": not meta["readonly"],
                    "recent": [] if include_recent else None,
                }
        except ApiError as err:
            LOGGER.info("Список счётчиков из ЭД недоступен: %s", err)

        # Дополнение с www.mos.ru: последние показания с источниками, поверка.
        if paycode and flat:
            try:
                devices = self.get_devices(paycode, flat)
            except ApiError as err:
                LOGGER.info("utility-meter /device недоступен: %s", err)
                devices = {}
            for device in devices.get("active") or []:
                device_id = str(device.get("id") or "")
                if not device_id:
                    continue
                model = device.get("model") or {}
                base = meters.setdefault(
                    device_id,
                    {
                        "id": device_id,
                        "type": "ХВС" if model.get("type") == "cold" else "ГВС",
                        "number": device.get("number") or "",
                        "inspection_date": None,
                        "inspection_status": None,
                        "current_reading": None,
                        "reading_period": None,
                        "can_submit": None,
                        "recent": [] if include_recent else None,
                    },
                )
                base["inspection_date"] = base.get("inspection_date") or normalize_period(
                    device.get("inspection_date")
                )
                base["inspection_status"] = base.get("inspection_status") or device.get(
                    "inspection_status"
                )
                if base.get("current_reading") is None and device.get("recent_reading"):
                    rr = device["recent_reading"]
                    base["current_reading"] = rr.get("indication")
                    base["reading_period"] = normalize_period(rr.get("period"))
                if include_recent:
                    base["recent"] = [
                        {
                            "period": r.get("period"),
                            "indication": parse_indication_value(r.get("indication")),
                            "source": _norm(r.get("source")),
                        }
                        for r in device.get("readings") or []
                    ]

        return list(meters.values())

    # ── Отправка/удаление показаний ────────────────────────────────────

    def send_reading(
        self,
        user_place_id: str,
        counter_id: str,
        value: float,
        period: str | None = None,
    ) -> dict:
        """Передать показание счётчика (целое значение, как требует портал).

        Raises:
            AlreadySubmittedError: за этот период показание уже внесено.
        """
        data = self._request_json(
            "PUT",
            f"{ED_COUNTERS}/addIndications/",
            params={
                "userPlaceId": user_place_id,
                "counterId": counter_id,
                "indication": normalized_reading(value),
                "period": period or submission_period(),
            },
            headers=XHR_HEADERS,
        )
        if not (data.get("data") or {}).get("result"):
            raise ApiError("Показание не принято")
        return data

    def send_readings(
        self, place: dict, readings: dict[str, float], *, period: str | None = None
    ) -> dict:
        """Передать показания конкретных счётчиков: {counter_id: значение}.

        В помещении может быть больше двух счётчиков — передача ведётся по id
        из meters/latest. Все id проверяются по списку активных счётчиков
        помещения и все значения валидируются ДО первой отправки, чтобы
        опечатка не создала частичную передачу.

        Raises:
            AlreadySubmittedError: по одному из счётчиков показание за период
                уже внесено (ранее переданные в этом вызове счётчики видны
                в атрибуте args/results вызывающего кода).
        """
        if not readings:
            raise ReadingValidationError("Не передано ни одного показания")
        counters = {c["id"]: c for c in self.get_counters(place["user_place_id"])}
        unknown = [cid for cid in readings if cid not in counters]
        if unknown:
            known = ", ".join(f"{cid} ({c['type']})" for cid, c in counters.items())
            raise ReadingValidationError(
                f"Счётчик(и) {', '.join(unknown)} не принадлежат помещению "
                f"{place['user_place_id']} (place {place.get('address') or ''}). "
                f"Счётчики помещения: {known}"
            )
        # Валидация всех значений до отправки первого.
        values = {cid: normalized_reading(v) for cid, v in readings.items()}
        results: dict[str, dict] = {}
        for counter_id, value in values.items():
            results[counter_id] = self.send_reading(
                place["user_place_id"], counter_id, value, period=period
            )
        return results

    def remove_last_indication(self, user_place_id: str, counter_id: str) -> dict:
        """Удалить последнее показание счётчика — ТОЛЬКО по явной команде.

        addIndications не перезаписывает значение: чтобы исправить показание
        за период, сначала удаляется прежнее. Удаляется последнее показание
        независимо от того, кто его внёс.
        """
        data = self._request_json(
            "DELETE",
            f"{ED_COUNTERS}/removeLastValue/",
            params={"counterId": counter_id, "userPlaceId": user_place_id},
            headers=XHR_HEADERS,
        )
        if not (data.get("data") or {}).get("result"):
            raise ApiError("Показание не удалено")
        return data

    # ── utility-meter API (www.mos.ru): устройства и архив ─────────────

    def _utility_meter_get(self, path: str, paycode: str, flat: str) -> dict:
        """GET к utility-meter API с автообновлением acst при 401."""

        def fetch():
            return self._auth.session.get(
                f"{WWW_UTILITY_METER}{path}",
                params={"flat": str(flat), "payer_code": str(paycode)},
                headers={**XHR_HEADERS, "Referer": WWW_UTILITY_SERVICE_PAGE},
                timeout=TIMEOUT,
            )

        try:
            resp = fetch()
        except requests.RequestException as err:
            raise ApiError("Сетевая ошибка www.mos.ru") from err
        if resp.status_code == 401:
            # acst истёк — обновляем через официальный probe и повторяем один раз.
            self._auth.try_refresh_acst()
            try:
                resp = fetch()
            except requests.RequestException as err:
                raise ApiError("Сетевая ошибка www.mos.ru") from err
        if resp.status_code in (401, 403):
            raise ApiError(f"utility-meter API: сессия отклонена (HTTP {resp.status_code})")
        if resp.status_code >= 400:
            raise ApiError(f"utility-meter API: HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as err:
            raise ApiError("utility-meter API: неожиданный формат ответа") from err
        code = str(body.get("code", "")).upper()
        if code and code not in ("SUCCESS", "METERS_NOT_FOUND"):
            message = (body.get("message") or "").strip()
            raise ApiError(f"utility-meter API: {message or code}")
        return body

    def get_devices(self, paycode: str, flat: str) -> dict:
        """Счётчики воды квартиры напрямую с www.mos.ru, без ЭД.

        Returns: {"active": […], "inactive": […], "address": {…}}; счётчик:
        {id, number, model:{class,type}, inspection_date, inspection_status,
        recent_reading, readings: [последние показания с источником]}.
        Нет счётчиков → {"active": [], "inactive": []} (METERS_NOT_FOUND).
        """
        body = self._utility_meter_get("/device", paycode, flat)
        data = body.get("data") or {}
        return {
            "active": data.get("active") or [],
            "inactive": data.get("inactive") or [],
            "address": data.get("address") or {},
        }

    def get_device_indication_archive(
        self, counter_id: str, paycode: str, flat: str, *, include_empty: bool = False
    ) -> list[dict]:
        """Архив показаний одного счётчика — то же, что в веб-сервисе портала.

        Все расчётные периоды с 2000 года (от новых к старым) с дробными
        значениями: {period, indication, source, readonly}. Пустые периоды
        (показание не передавалось) отбрасываются, кроме include_empty=True.
        """
        body = self._utility_meter_get(f"/device/{counter_id}/indication/archive", paycode, flat)
        items = (body.get("data") or {}).get("items") or []
        result = [_normalize_archive_item(raw) for raw in items]
        if not include_empty:
            result = [item for item in result if item["indication"] is not None]
        return result

    def get_water_archive(self, place: dict, *, include_empty: bool = False) -> dict[str, dict]:
        """Архив показаний всех счётчиков воды квартиры.

        Id счётчиков — из ЭД; если ЭД недоступен — напрямую с www.mos.ru.

        Returns: {counter_id: {type, number, items: [{period, indication,
        source, readonly}]}}.
        """
        paycode, flat = place.get("paycode") or "", place.get("flat") or ""
        if not paycode or not flat:
            raise ReadingValidationError(
                "Архив показаний требует paycode (payer_code) и flat — "
                "возьмите их из readings.list_places()"
            )

        counters: list[dict] = []
        try:
            counters = [
                c for c in self.get_counters(place["user_place_id"])
                if is_cold_water(c) or is_hot_water(c)
            ]
        except ApiError as err:
            LOGGER.info("Список счётчиков из ЭД недоступен: %s", err)

        if not counters:
            devices = self.get_devices(paycode, flat)
            counters = [
                {
                    "id": d["id"],
                    "type": "ХВС" if (d.get("model") or {}).get("type") == "cold" else "ГВС",
                    "name": d.get("number") or "",
                }
                for d in devices.get("active") or []
                if (d.get("model") or {}).get("class") == "water"
            ]

        if not counters:
            raise ApiError(
                f"Счётчики воды для квартиры {place.get('address')} "
                "не зарегистрированы в системе (METERS_NOT_FOUND)"
            )

        archive: dict[str, dict] = {}
        for counter in counters:
            archive[counter["id"]] = {
                "type": counter["type"],
                "number": counter["name"],
                "items": self.get_device_indication_archive(
                    counter["id"], paycode, flat, include_empty=include_empty
                ),
            }
        return archive

    # ── История в «Электронном доме» ───────────────────────────────────

    def _paged_history(
        self,
        url: str,
        base_params: dict,
        *,
        page_size: int,
        max_pages: int | None,
        what: str,
        list_key: str = "indications",
    ) -> list[dict]:
        """Постраничная выгрузка истории ЭД.

        Мягкие случаи (возвращаем то, что успели получить):
        - 400 «Не удалось получить данные счётчиков» — квартира без счётчиков в ЭД;
        - 5xx/временная недоступность — сервис данных МЭС в ЭД периодически падает.
        """
        items: list[dict] = []
        page = 1
        while True:
            params = {**base_params, "page": page, "pageSize": page_size}
            try:
                data = self._request_json("GET", url, params=params, headers=XHR_HEADERS)
            except ApiError as err:
                text = str(err)
                if "Не удалось получить данные" in text:
                    LOGGER.info("%s: %s", what, text)
                    return items
                if isinstance(err, TemporaryError):
                    LOGGER.warning("%s: сервис временно недоступен (%s)", what, text)
                    return items
                raise
            payload = data.get("data") or {}
            indications = (
                payload.get(list_key) if isinstance(payload, dict) else payload
            ) or []
            items.extend(indications)
            # pagesCount у ЭД лежит внутри data (верхнего уровня может не быть)
            pages = int(
                (payload.get("pagesCount") if isinstance(payload, dict) else None)
                or data.get("pagesCount")
                or 1
            )
            if max_pages is not None and page >= max_pages:
                break
            if page >= pages:
                break
            page += 1
        return items

    def get_water_history(
        self, user_place_id: str, *, page_size: int = 50, max_pages: int | None = None
    ) -> list[dict]:
        """История воды в ЭД (data.periods): {period, period_date, counters: […]}."""
        raw_items = self._paged_history(
            ED_WATER_HISTORY_LIST,
            {"userPlaceId": user_place_id},
            page_size=page_size,
            max_pages=max_pages,
            what="История воды (ЭД)",
            list_key="periods",
        )
        return [_normalize_water_history_item(raw) for raw in raw_items]

    def get_water_history_details(self, user_place_id: str, period_date: str) -> list[dict]:
        """Детали показаний воды на расчётную дату: расход, дата ввода."""
        data = self._request_json(
            "GET",
            ED_WATER_HISTORY,
            params={"userPlaceId": user_place_id, "date": period_date},
            headers=XHR_HEADERS,
            retries=RETRY_ATTEMPTS,
        )
        payload = data.get("data") or {}
        indications = (
            payload.get("indications") if isinstance(payload, dict) else payload
        ) or []
        return [_normalize_water_details_item(raw) for raw in indications]

    def get_electricity_history(
        self,
        user_place_id: str,
        *,
        page_size: int = 50,
        max_pages: int | None = None,
        period: str = "YEAR",
    ) -> list[dict]:
        """История показаний электричества из ЭД (если связана с ЛК МЭС).

        Элементы: {meter_number, date, source, tariffs: [{key, name, value,
        usage}], inspection_end_date}.
        """
        raw_items = self._paged_history(
            ED_LIGHT_ALL_INDICATIONS,
            {"userPlaceId": user_place_id, "period": period},
            page_size=page_size,
            max_pages=max_pages,
            what="История электричества",
        )
        return [_normalize_electricity_history_item(raw) for raw in raw_items]

    def get_electricity_last(self, user_place_id: str) -> dict:
        """Последние показания электросчётчиков из ЭД (getCurrentT1..T3, поверка)."""
        data = self._request_json(
            "GET",
            ED_LIGHT_LAST_INDICATION,
            params={"userPlaceId": user_place_id},
            headers=XHR_HEADERS,
            retries=RETRY_ATTEMPTS,
        )
        payload = data.get("data") or data
        if isinstance(payload, list):
            payload = payload[0] if payload else {}
        return _normalize_electricity_last_item(payload) if payload else {}

    # ── Электричество через mos.ru (pgu2/counters → МЭС) ─────────────────

    def _pgu_api_get(self, path: str, params: dict) -> dict:
        """GET /pgu2/counters/api/<path> с автопрохождением OAuth pgu2 при 401.

        При 401 (нет cookie SESSID pgu2) выполняется OAuth client_id=mpgu2.0
        через живую SSO-сессию и запрос повторяется один раз. Возвращает
        тело ответа целиком.
        """
        def fetch():
            return self._auth.session.get(
                f"{PGU_COUNTERS_API}/{path.lstrip('/')}",
                params=params,
                headers={**XHR_HEADERS, "Referer": PGU_COUNTERS_PAGE},
                timeout=TIMEOUT,
            )

        try:
            resp = fetch()
        except requests.RequestException as err:
            raise ApiError("Сетевая ошибка www.mos.ru") from err
        if resp.status_code == 401:
            self._pgu_authorize()
            try:
                resp = fetch()
            except requests.RequestException as err:
                raise ApiError("Сетевая ошибка www.mos.ru") from err
        if resp.status_code in (401, 403):
            raise AuthError(f"pgu2/counters: доступ запрещён (HTTP {resp.status_code})")
        if resp.status_code >= 400:
            raise ApiError(f"pgu2/counters API: HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError as err:
            raise ApiError("pgu2/counters API: неожиданный формат ответа") from err

    def _pgu_get(self, action: str, params: dict) -> dict:
        """MES-экшен через прокси: GET /pgu2/counters/api/mes/<action>.

        Фронтенд кладёт полезную нагрузку в поле result ответа.
        """
        body = self._pgu_api_get(f"mes/{action}", params)
        result = body.get("result")
        return result if isinstance(result, dict) else {"result": result}

    def _pgu_authorize(self) -> None:
        """OAuth client_id=mpgu2.0 поверх SSO: ae → callback → cookie SESSID."""
        s = self._auth.session
        nav = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": PGU_COUNTERS_PAGE,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Upgrade-Insecure-Requests": "1",
        }
        try:
            r = s.get(
                f"{PGU_COUNTERS_API}/mes/checkNewUser",
                headers={**XHR_HEADERS, "Referer": PGU_COUNTERS_PAGE},
                timeout=TIMEOUT,
            )
            login_url = (r.json() or {}).get("login_url")
        except (requests.RequestException, ValueError) as err:
            raise AuthError("pgu2 OAuth: не получен login_url") from err
        if not login_url:
            raise AuthError("pgu2 OAuth: сервер не вернул login_url")
        trusted_url(login_url)
        try:
            r2 = s.get(login_url, allow_redirects=False, timeout=TIMEOUT, headers=nav)
            location = r2.headers.get("Location")
            if not location:
                raise AuthError(
                    "pgu2 OAuth: SSO-сессия истекла — повторите python mosru-meters.py login"
                )
            trusted_url(location)
            s.get(location, allow_redirects=True, timeout=TIMEOUT, headers=nav)
        except requests.RequestException as err:
            raise ApiError("pgu2 OAuth: сетевая ошибка") from err

    @staticmethod
    def _split_account(account: str) -> dict:
        """Лицевой счёт МЭС "<код плательщика>-<номер>-<код>" → части.

        nm_kng/nm_abn/nn_kr — параметры checkNewUser/checkShetch; для прочих
        сервисов МЭС параметр nm_abn — второй сегмент (проверено на живом
        API: с seg1 getLastPok/getVlTarif/calcBalanceEx отдают данные,
        с seg0 — пусто или ошибку).
        """
        parts = [p.strip() for p in str(account).split("-")]
        if len(parts) != 3 or not all(parts):
            raise ReadingValidationError(
                "Лицевой счёт Мосэнергосбыт должен состоять из трёх частей через "
                "дефис (например 1234567890-12-345), как на квитанции ЕПД"
            )
        return {"nm_kng": parts[0], "nm_abn": parts[1], "nn_kr": parts[2]}

    def mes_check_meter(self, account: str, meter_number: str) -> dict:
        """checkShetch: счётчик по лицевому счёту → {ID_KNG, SCHEMA, …}."""
        parts = self._split_account(account)
        res = self._pgu_get(
            "checkShetch",
            {
                "nm_kng": parts["nm_kng"],
                "nm_abn": parts["nm_abn"],
                "nn_kr": parts["nn_kr"],
                "nn_schetch": str(meter_number),
            },
        )
        if not res.get("ID_KNG"):
            raise ApiError(
                f"Счётчик №{meter_number} не найден по лицевому счёту — "
                "проверьте --account и номер (см. meters/latest)"
            )
        return res

    def mes_check_transfer(self, account: str, id_kng) -> dict:
        """checkTransPok: принимает ли МЭС показания сейчас ({KD_RESULT, NM_RESULT})."""
        nm_abn = self._split_account(account)["nm_abn"]
        return self._pgu_get("checkTransPok", {"nm_abn": nm_abn, "id_kng": id_kng})

    def mes_check_account(self, account: str) -> dict:
        """checkNewUser: проверка лицевого счёта ({NN_ANS_CHECK_USR, …})."""
        parts = self._split_account(account)
        return self._pgu_get(
            "checkNewUser",
            {"nm_kng": parts["nm_kng"], "nm_abn": parts["nm_abn"], "nn_kr": parts["nn_kr"]},
        )

    def mes_account_info(self, account: str, id_kng, schema) -> dict:
        """Полная информация по счётчику ЛС: адрес, баланс, тарифы, показания.

        Один вызов собирает пакет сервисов МЭС, который использует фронтенд
        портала: generalInfo (ADDR, NM_UCHET), getSchetch (DT_DATE_MPI),
        getLastPok (POK_T1..3, NM_T1..3, SH_UST), getVlTarif (VL_TAR_T1..3),
        calcBalanceEx (SM_BALANCE, SM_DOLG, SM_RAS, SM_PAY, SM_RETURNS).
        Сбой одного сервиса не мешает остальным — в его месте {"error": …}.
        """
        nm_abn = self._split_account(account)["nm_abn"]
        base = {"nm_abn": nm_abn, "id_kng": id_kng, "schema": schema}
        services: dict = {}
        for name in ("generalInfo", "getSchetch", "getLastPok", "getVlTarif", "calcBalanceEx"):
            try:
                services[name] = self._pgu_get(name, dict(base))
            except MosRuError as err:
                services[name] = {"error": str(err)}
        return services

    def list_profile_houses(self) -> list[dict]:
        """Профиль pgu2 (info_blocks[]=HOUSE): помещения пользователя целиком.

        Каждое помещение содержит лицевой счёт МЭС (MES_ACCOUNT), счётчик
        (MES_METER), адрес, площадь и сервисные поля — то, что портал
        показывает на шаге 1 формы показаний электричества.
        """
        body = self._pgu_api_get("profile", {"info_blocks[]": "HOUSE"})
        houses: list[dict] = []
        for block in body.get("items") or []:
            if block.get("code") != "HOUSE":
                continue
            for entry in block.get("data") or []:
                if isinstance(entry, dict):
                    houses.append(entry)
        return houses

    def list_electricity_accounts(self) -> list[dict]:
        """Лицевые счёта МЭС и счётчики из профиля pgu2 — нормализованные строки.

        Один дом = одна запись; если на ЛС несколько счётчиков, дом
        повторяется с разными MES_METER (строки не склеиваются).
        """
        rows: list[dict] = []
        for house in self.list_profile_houses():
            rows.append(
                {
                    "account": str(house.get("MES_ACCOUNT") or ""),
                    "meter": str(house.get("MES_METER") or ""),
                    "address": house.get("ADDRESS_DESCRIPTION")
                    or house.get("ADDRESS_FULL")
                    or "",
                    "flat": house.get("FLAT") or "",
                    "total_area": house.get("TOTAL_AREA") or "",
                    "district": house.get("DISTRICTLABEL") or "",
                }
            )
        return rows

    def mes_last_readings(self, account: str, id_kng, schema) -> dict:
        """getLastPok: предыдущие показания и названия тарифов (NM_T1, POK_T1…)."""
        nm_abn = self._split_account(account)["nm_abn"]
        return self._pgu_get(
            "getLastPok", {"nm_abn": nm_abn, "id_kng": id_kng, "schema": schema}
        )

    def mes_readings_history(
        self, account: str, id_kng, schema, dt_beg: str, dt_end: str
    ) -> dict:
        """allSchetchPok: история показаний электричества за период (YYYY-MM-DD)."""
        nm_abn = self._split_account(account)["nm_abn"]
        return self._pgu_get(
            "allSchetchPok",
            {
                "nm_abn": nm_abn,
                "id_kng": id_kng,
                "schema": schema,
                "dt_beg": dt_beg,
                "dt_end": dt_end,
            },
        )

    def mes_electricity_latest(self, account: str, meter_number: str) -> dict:
        """Последние переданные показания и стоимость тарифов (getLastPok + getVlTarif).

        Returns: {"rows": [{meter_id, type, number, tariff, period,
        indication, usage, cost, source}]} — строка на тариф T1–T3.
        """
        shetch = self.mes_check_meter(account, meter_number)
        id_kng = shetch.get("ID_KNG")
        schema = shetch.get("SCHEMA")
        nm_abn = self._split_account(account)["nm_abn"]
        base = {"nm_abn": nm_abn, "id_kng": id_kng, "schema": schema}
        last = self._pgu_get("getLastPok", dict(base))
        tariffs = self._pgu_get("getVlTarif", dict(base))

        rows: list[dict] = []
        for i, key in enumerate(MES_TARIFFS, start=1):
            name = last.get(f"NM_T{i}")
            if name in (None, ""):
                continue
            clean_name = str(name).replace(f"(T{i}):", "").strip().rstrip(":").strip()
            rows.append(
                {
                    "meter_id": str(meter_number),
                    "type": "ЭЛ",
                    "number": str(meter_number),
                    "tariff": f"{key} ({clean_name})" if clean_name else key,
                    # getLastPok даты показаний не отдаёт — только значения
                    "period": "",
                    "indication": _norm(last.get(f"POK_T{i}")),
                    "usage": None,
                    "cost": _norm(tariffs.get(f"VL_TAR_T{i}")),
                    "source": "МЭС (mos.ru)",
                }
            )
        return {"id_kng": id_kng, "schema": schema, "rows": rows}

    def send_electricity(
        self, account: str, meter_number: str, tariffs: dict[str, int]
    ) -> dict:
        """Передать показания электричества через mos.ru (pgu2/counters → МЭС).

        tariffs: {"T1": 2836, "T2": 2859, "T3": 3676} — отсутствующие тарифы
        передаются нулём (как во фронтенде портала). Порядок не важен.
        Цепочка: checkShetch (ID_KNG, SCHEMA) → checkTransPok (приём открыт?)
        → doTransPok (передача). Портал принимает показания в окне приёма
        (обычно 15–26 число месяца) — иначе checkTransPok вернёт KD_RESULT≠0.
        """
        shetch = self.mes_check_meter(account, meter_number)
        id_kng = shetch.get("ID_KNG")
        schema = shetch.get("SCHEMA")

        check = self.mes_check_transfer(account, id_kng)
        if str(check.get("KD_RESULT")) != "0":
            message = check.get("NM_RESULT") or "передача показаний сейчас недоступна"
            raise ApiError(f"МЭС: {message}")

        # Фронтенд портала передаёт в doTransPok первый сегмент ЛС —
        # копируем поведение браузера точно.
        body = {
            "nm_abn": self._split_account(account)["nm_kng"],
            "id_kng": id_kng,
            "schema": schema,
        }
        for i, name in enumerate(MES_TARIFFS, start=1):
            body[f"vl_pok_t{i}"] = int(tariffs.get(name, 0))
        res = self._pgu_get("doTransPok", body)
        if str(res.get("KD_RESULT")) != "0":
            raise ApiError(f"Показания не приняты: {res.get('NM_RESULT')}")
        return res


# ── Мосэнергосбыт (электричество) ───────────────────────────────────────────


class MosEnergoSbyt:
    """Передача показаний электроэнергии через ЛК Мосэнергосбыта (gate_lkcomu).

    mos.ru электричество не хранит: сервис портала отдаёт данные в
    АО «Мосэнергосбыт». Двухшаговая отправка: CalcCharge → SaveIndications.
    У части аккаунтов включено подтверждение входа кодом (TFA) — тогда
    потребуется первый вход через мобильное приложение.
    """

    BASE_URL = "https://my.mosenergosbyt.ru/gate_lkcomu"
    SUCCESS_RESULT = "Показания успешно переданы"

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": "https://my.mosenergosbyt.ru",
            }
        )
        self._session_token = ""

    def _gate(self, *, query_params: dict, body: dict) -> dict:
        try:
            resp = self._session.post(
                self.BASE_URL,
                params=query_params,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=TIMEOUT,
            )
        except requests.RequestException as err:
            raise ApiError("Сетевая ошибка my.mosenergosbyt.ru") from err
        try:
            data = resp.json()
        except ValueError as err:
            raise ApiError(f"Неожиданный ответ ЛК МЭС (HTTP {resp.status_code})") from err
        if not isinstance(data, dict):
            raise ApiError("Неожиданный формат ответа ЛК МЭС")
        err_text = data.get("err_text") or ""
        if err_text:
            raise ApiError(f"ЛК МЭС: {err_text}")
        return data

    def login(self, login: str, password: str, *, password_is_md5: bool = False) -> str:
        """Авторизация в ЛК МЭС; возвращает session-токен."""
        if password_is_md5:
            import hashlib

            psw = hashlib.md5(password.encode()).hexdigest()
        else:
            psw = password
        data = self._gate(
            query_params={"action": "auth", "query": "login"},
            body={
                "login": login,
                "psw": psw,
                "remember": "true",
                "vl_device_info": json.dumps(
                    {
                        "appver": "1.17.1",
                        "type": "browser",
                        "userAgent": USER_AGENT,
                    }
                ),
            },
        )
        entries = data.get("data") or []
        session_token = entries[0].get("session") if entries else ""
        if not session_token:
            raise AuthError("ЛК МЭС: сессия не получена (проверьте логин/пароль)")
        self._session_token = session_token
        return session_token

    def send_indications(self, values: dict[str, int]) -> str:
        """Передать показания по тарифам: {"T1": 2836, "T2": 2859, "T3": 3676}.

        Ключи — T1/T2/T3 (регистр не важен), порядок не имеет значения;
        можно передавать любое подмножество (например, только T1 и T2).
        Двухшаговая отправка: расчёт (CalcCharge) → подтверждение
        (SaveIndications).
        """
        if not self._session_token:
            raise AuthError("Сначала выполните MosEnergoSbyt.login()")
        normalized = {k.strip().upper(): int(v) for k, v in values.items()}
        unknown = [k for k in normalized if k not in ("T1", "T2", "T3")]
        if unknown:
            raise ApiError(
                f"ЛК МЭС поддерживает тарифы T1–T3, переданы: {', '.join(sorted(unknown))}"
            )
        vl = {t: str(normalized[t]) if t in normalized else "" for t in ("T1", "T2", "T3")}
        provider = '{"id_kng": 173359, "nm_abn": 82}'

        calc = self._gate(
            query_params={"action": "sql", "query": "bytProxy", "session": self._session_token},
            body={
                "nn_phone": "+7 (499) 550-9-550",
                "plugin": "bytProxy",
                "pr_flat_meter": "0",
                "proxyquery": "CalcCharge",
                "vl_provider": provider,
                "vl_t1": vl["T1"],
                "vl_t2": vl["T2"],
                "vl_t3": vl["T3"],
            },
        )
        entries = calc.get("data") or []
        if not (entries and entries[0].get("nm_result")):
            raise ApiError("ЛК МЭС: CalcCharge не вернул результат — показания НЕ переданы")

        saved = self._gate(
            query_params={
                "action": "sql",
                "query": "SaveIndications",
                "session": self._session_token,
            },
            body={
                "plugin": "propagateMesInd",
                "pr_flat_meter": "0",
                "vl_provider": provider,
                "vl_t1": vl["T1"],
                "vl_t2": vl["T2"],
                "vl_t3": vl["T3"],
            },
        )
        entries = saved.get("data") or []
        nm_result = str(entries[0].get("nm_result")) if entries else ""
        if self.SUCCESS_RESULT not in nm_result:
            raise ApiError(f"ЛК МЭС: сохранение не подтвердилось ({nm_result or 'нет ответа'})")
        return nm_result

# ── CLI ─────────────────────────────────────────────────────────────────────

DEFAULT_SESSION_FILE = "mosru_session.json"

# Колонки таблиц (ключ в dict → заголовок).
PLACE_COLUMNS = [
    ("place_id", "id помещения"),
    ("address", "адрес"),
    ("flat", "квартира"),
    ("paycode", "код плательщика"),
]
METER_COLUMNS = [
    ("id", "id счётчика"),
    ("type", "тип"),
    ("number", "номер"),
    ("current_reading", "текущее показание"),
    ("reading_period", "период"),
    ("can_submit", "отправка"),
    ("inspection_date", "поверка до"),
    ("inspection_status", "статус поверки"),
]
LATEST_COLUMNS = [
    ("meter_id", "id счётчика"),
    ("type", "тип"),
    ("number", "номер"),
    ("tariff", "тариф"),
    ("period", "период"),
    ("indication", "показание"),
    ("usage", "расход"),
    ("cost", "стоимость, руб"),
    ("source", "источник"),
]
HISTORY_COLUMNS = [
    ("place", "квартира"),
    ("meter_id", "id счётчика"),
    ("type", "тип"),
    ("number", "номер"),
    ("tariff", "тариф"),
    ("period", "период"),
    ("indication", "показание"),
    ("usage", "расход"),
    ("source", "источник"),
]


def _parse_meter_filter(args) -> set[str]:
    """--meter: id счётчиков воды / номера электросчётчиков через запятую."""
    raw = getattr(args, "meter", "") or ""
    return {part.strip() for part in re.split(r"[,;]", raw) if part.strip()}


def _warn_unknown_meters(meter_filter: set[str], available: set[str]) -> None:
    """Подсказать, если какой-то id из --meter не совпал ни с одной записью."""
    available_str = {str(a) for a in available}
    unknown = {str(f) for f in meter_filter} - available_str
    if unknown:
        print(
            f"Не найдены счётчики: {', '.join(sorted(unknown))}. "
            f"Доступные id/номера: {', '.join(sorted(available_str))}",
            file=sys.stderr,
        )


# ── Вывод: json / csv / markdown ────────────────────────────────────────────


def _fmt(args) -> str:
    """Выбранный формат вывода: json | csv | md (по умолчанию)."""
    if getattr(args, "json", False):
        return "json"
    if getattr(args, "csv", False):
        return "csv"
    return "md"


def _md_cell(value) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _md_table(columns: Sequence[tuple[str, str]], items: list[dict]) -> str:
    headers = [h for _, h in columns]
    keys = [k for k, _ in columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for item in items:
        lines.append("| " + " | ".join(_md_cell(item.get(k)) for k in keys) + " |")
    return "\n".join(lines)


def output_items(args, items: list[dict], columns: Sequence[tuple[str, str]]) -> None:
    """Вывести таблицу записей в выбранном формате (--json/--csv/--md)."""
    fmt = _fmt(args)
    keys = [k for k, _ in columns]
    headers = [h for _, h in columns]
    if fmt == "json":
        print(json.dumps(items, ensure_ascii=False, indent=1))
    elif fmt == "csv":
        writer = csv.writer(sys.stdout, delimiter=";")
        writer.writerow(headers)
        for item in items:
            writer.writerow(["" if item.get(k) is None else item.get(k) for k in keys])
    else:
        print(_md_table(columns, items))


def output_kv(args, data: dict, *, title_key: str = "параметр", value_key: str = "значение") -> None:
    """Вывести словарь ключ-значение (whoami, логин)."""
    columns = [(title_key, title_key), (value_key, value_key)]
    items = [{title_key: k, value_key: v} for k, v in data.items()]
    fmt = _fmt(args)
    if fmt == "json":
        print(json.dumps(data, ensure_ascii=False, indent=1))
    elif fmt == "csv":
        output_items(args, items, columns)
    else:
        print(_md_table(columns, items))


def cmd_login(args) -> None:
    auth = MosRuAuth()
    if args.password:
        login = args.login or input("Логин (email/телефон/SNILS): ")
        password = getpass.getpass("Пароль: ")
        factor = auth.password_login(login, password)
    else:
        def show_url(url: str) -> None:
            print(
                "Ссылка для входа — отсканируйте приложением mos.ru / "
                f"«Госуслуги Москвы» (или откройте на телефоне):\n{url}"
            )

        factor = auth.qr_login(on_url=show_url)
    _handle_factor(auth, factor)
    auth.warm_session()
    auth.save(args.session)
    output_kv(
        args,
        {
            "статус": "вход выполнен",
            "файл сессии": args.session,
            "cookies": ", ".join(auth.cookie_names()),
        },
    )


def _handle_factor(auth: MosRuAuth, factor: str) -> None:
    """Добработать вход, если портал запросил второй фактор."""
    if factor == SecondFactor.SMS:
        auth.submit_sms_code(input("Код из SMS: "))
        print("SMS-код принят")
    elif factor == SecondFactor.TOTP:
        auth.submit_totp_code(input("Код из приложения-аутентификатора: "))
        print("TOTP-код принят")
    elif factor == SecondFactor.WEBAUTHN:
        raise AuthError(
            "Портал запросил WebAuthn как фактор входа — этот метод mos.ru "
            "в веб-входе не предлагает; войдите через QR или пароль"
        )


def _connect(args) -> tuple[MosRuAuth, MosRuReadings]:
    """Загрузить сессию, проверить живость, авторизовать ЭД."""
    auth = MosRuAuth()
    try:
        auth.restore(args.session)
    except FileNotFoundError:
        print(
            f"Файл сессии не найден: {args.session}. "
            f"Сначала: python {os.path.basename(sys.argv[0])} login"
        )
        sys.exit(2)
    if not auth.is_alive():
        print("Сессия истекла — повторите вход: python mosru-meters.py login")
        sys.exit(2)
    auth.authorize_ed()
    return auth, MosRuReadings(auth)


def _resolve_place(readings: MosRuReadings, args) -> dict:
    return readings.find_place(
        getattr(args, "paycode", "") or "",
        getattr(args, "flat", "") or "",
        getattr(args, "place", "") or "",
    )


def cmd_whoami(args) -> None:
    auth = MosRuAuth()
    try:
        auth.restore(args.session)
    except FileNotFoundError:
        print(f"Файл сессии не найден: {args.session}")
        sys.exit(2)
    cookies = auth.cookie_names()
    output_kv(
        args,
        {
            "сессия жива": "да" if auth.is_alive() else "нет",
            "cookies": ", ".join(cookies) if cookies else "—",
        },
    )


def cmd_places(args) -> None:
    _, readings = _connect(args)
    items = [
        {
            "place_id": place["user_place_id"],
            "address": place["address"],
            "flat": place["flat"] or "",
            "paycode": place["paycode"],
        }
        for place in readings.list_places()
    ]
    output_items(args, items, PLACE_COLUMNS)


def cmd_meters(args) -> None:
    """Счётчики помещения: id, тип, номер, показание, поверка, отправка."""
    _, readings = _connect(args)
    place = _resolve_place(readings, args)
    items = []
    for m in readings.get_meters(place, include_recent=False):
        can_submit = m.get("can_submit")
        items.append(
            {
                "id": m["id"],
                "type": m.get("type") or "",
                "number": m.get("number") or "",
                "current_reading": m.get("current_reading"),
                "reading_period": m.get("reading_period"),
                "can_submit": (
                    "доступна" if can_submit else
                    ("запрещена" if can_submit is False else "")
                ),
                "inspection_date": m.get("inspection_date"),
                "inspection_status": m.get("inspection_status"),
            }
        )
    # Электросчётчики: отдельного id ЭД не отдаёт — идентификатор = номер.
    try:
        last = readings.get_electricity_last(place["user_place_id"])
    except ApiError as err:
        LOGGER.info("Электросчётчики недоступны: %s", err)
        last = {}
    if last and last.get("meter_number"):
        tariffs = last.get("tariffs") or []
        items.append(
            {
                "id": last["meter_number"],
                "type": "ЭЛ",
                "number": last["meter_number"],
                "current_reading": (tariffs[0].get("value") if tariffs else None),
                "reading_period": normalize_period(last.get("date")),
                "can_submit": "",
                "inspection_date": normalize_period(last.get("inspection_end_date")),
                "inspection_status": "",
            }
        )
    output_items(args, items, METER_COLUMNS)


def cmd_latest(args) -> None:
    """Последние показания: вода (utility-meter) + электричество.

    С --account/--meter электричество берётся из API pgu2/counters
    (getLastPok + getVlTarif): предыдущие переданные показания по тарифам
    и стоимость каждого тарифа. --meter при этом — номер электросчётчика
    из вывода electro-accounts (совпадает с фильтром --meter).
    """
    _, readings = _connect(args)
    place = _resolve_place(readings, args)
    meter_filter = _parse_meter_filter(args)
    mes_account = (args.account or "").strip()
    items: list[dict] = []
    available: set[str] = set()

    for m in readings.get_meters(place):
        available.add(str(m["id"]))
        if meter_filter and str(m["id"]) not in meter_filter:
            continue
        recent = m.get("recent") or []
        if recent:
            for r in recent:
                items.append(
                    {
                        "meter_id": m["id"],
                        "type": m.get("type") or "",
                        "number": m.get("number") or "",
                        "tariff": "",
                        "period": normalize_period(r.get("period")),
                        "indication": r.get("indication"),
                        "usage": None,
                        "cost": None,
                        "source": r.get("source"),
                    }
                )
        else:
            items.append(
                {
                    "meter_id": m["id"],
                    "type": m.get("type") or "",
                    "number": m.get("number") or "",
                    "tariff": "",
                    "period": normalize_period(m.get("reading_period")),
                    "indication": m.get("current_reading"),
                    "usage": None,
                    "cost": None,
                    "source": None,
                }
            )

    if mes_account:
        # Электричество из API pgu2/counters: getLastPok + getVlTarif.
        meter_number = str(args.meter or "").strip()
        if not meter_number:
            raise SystemExit(
                "С --account укажите --meter <номер электросчётчика> "
                "(номер — из вывода electro-accounts)"
            )
        available.add(meter_number)
        info = readings.mes_electricity_latest(mes_account, meter_number)
        items.extend(info["rows"])
    else:
        try:
            last = readings.get_electricity_last(place["user_place_id"])
        except ApiError as err:
            LOGGER.info("Последние показания электричества недоступны: %s", err)
            last = {}
        if last and last.get("meter_number"):
            available.add(str(last["meter_number"]))
            if not meter_filter or str(last["meter_number"]) in meter_filter:
                for t in last.get("tariffs") or []:
                    tariff = f"{t['key']} ({t['name']})" if t.get("name") else t["key"]
                    items.append(
                        {
                            "meter_id": str(last["meter_number"]),
                            "type": "ЭЛ",
                            "number": str(last["meter_number"]),
                            "tariff": tariff,
                            "period": normalize_period(last.get("date")),
                            "indication": t.get("value"),
                            "usage": t.get("usage"),
                            "cost": None,
                            "source": None,
                        }
                    )

    if meter_filter:
        _warn_unknown_meters(meter_filter, available)
    output_items(args, items, LATEST_COLUMNS)


def cmd_history(args) -> None:
    """Вся имеющаяся история: вода (архив www.mos.ru) + электричество (ЭД).

    Вывод — единая таблица: квартира, id счётчика, тип, номер, период,
    показание, расход, источник. Для воды id — counterId, для электричества
    ЭД id не отдаёт — используется номер счётчика.
    """
    _, readings = _connect(args)
    meter_filter = _parse_meter_filter(args)
    if args.place or args.paycode or args.flat:
        places = [_resolve_place(readings, args)]
    else:
        places = readings.list_places()
        if not places:
            raise SystemExit("В профиле ed.mos.ru нет квартир")

    rows: list[dict] = []
    available: set[str] = set()
    for place in places:
        label = f"{place['address']} кв.{place['flat'] or '?'}"

        if args.kind in ("water", "all"):
            try:
                water = readings.get_water_archive(
                    place, include_empty=args.include_empty
                )
            except ApiError as err:
                LOGGER.info("Вода: архив недоступен — %s", err)
                water = {}
            for counter_id, meta in water.items():
                available.add(str(counter_id))
                if meter_filter and counter_id not in meter_filter:
                    continue
                for item in meta["items"]:
                    rows.append(
                        {
                            "place": label,
                            "meter_id": counter_id,
                            "type": meta["type"],
                            "number": meta["number"],
                            "tariff": "",
                            "period": normalize_period(item["period"]),
                            "indication": item["indication"],
                            "usage": None,
                            "source": item["source"],
                        }
                    )

        if args.kind in ("electricity", "all"):
            try:
                electricity = readings.get_electricity_history(place["user_place_id"])
            except ApiError as err:
                LOGGER.info("Электричество: недоступно — %s", err)
                electricity = []
            for item in electricity:
                meter_id = str(item.get("meter_number") or "")
                available.add(str(meter_id))
                if meter_filter and meter_id not in meter_filter:
                    continue
                for tariff in item["tariffs"]:
                    rows.append(
                        {
                            "place": label,
                            "meter_id": meter_id,
                            "type": "ЭЛ",
                            "number": meter_id,
                            "tariff": (
                                f"{tariff['key']} ({tariff['name']})"
                                if tariff.get("name") else tariff["key"]
                            ),
                            "period": normalize_period(item.get("date")),
                            "indication": tariff.get("value"),
                            "usage": tariff.get("usage"),
                            "source": item.get("source"),
                        }
                    )

    if meter_filter:
        _warn_unknown_meters(meter_filter, available)

    fmt = _fmt(args)
    if fmt == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=1))
    elif fmt == "csv":
        writer = csv.writer(sys.stdout, delimiter=";")
        writer.writerow([h for _, h in HISTORY_COLUMNS])
        for row in rows:
            writer.writerow([
                "" if row.get(k) is None else row.get(k)
                for k, _ in HISTORY_COLUMNS
            ])
    else:
        shown = rows if args.limit is None else rows[: args.limit]
        print(_md_table(HISTORY_COLUMNS, shown))
        if args.limit is not None and len(rows) > args.limit:
            print(f"\n… ещё {len(rows) - args.limit} записей")


def cmd_send(args) -> None:
    """Передать показания конкретных счётчиков: пары id_счётчика:значение."""
    _, readings = _connect(args)
    place = readings.find_place(user_place_id=args.place)

    pairs: dict[str, float] = {}
    for chunk in re.split(r"[,;]", args.values):
        chunk = chunk.strip()
        if not chunk:
            continue
        counter_id, sep, value_str = chunk.partition(":")
        counter_id = counter_id.strip()
        value_str = value_str.strip().replace(",", ".")
        if not sep or not counter_id:
            raise SystemExit(
                f"Некорректная пара «{chunk}» — ожидается id_счётчика:значение"
            )
        if counter_id in pairs:
            raise SystemExit(
                f"Счётчик {counter_id} указан дважды — передайте одно значение. "
                "Показания нескольких тарифов (T1/T2/T3) электросчётчика "
                "передаются командой electro-send."
            )
        try:
            pairs[counter_id] = float(value_str)
        except ValueError:
            raise SystemExit(
                f"Некорректное значение показания в паре «{chunk}»"
            )
    if not pairs:
        raise SystemExit("Не передано ни одной пары id_счётчика:значение")

    # Проверяем все id и значения ДО отправки — частичной передачи из-за опечатки не будет.
    counters = {c["id"]: c for c in readings.get_counters(place["user_place_id"])}
    unknown = [cid for cid in pairs if cid not in counters]
    if unknown:
        known = ", ".join(f"{cid} ({c['type']})" for cid, c in counters.items())
        raise SystemExit(
            f"Счётчик(и) {', '.join(unknown)} не принадлежат помещению "
            f"{place['user_place_id']}. Счётчики помещения: {known or '—'}"
        )
    values: dict[str, int] = {}
    for cid, value in pairs.items():
        try:
            values[cid] = normalized_reading(value)
        except ReadingValidationError as err:
            raise SystemExit(f"Счётчик {cid}: {err}")

    # Передаём поштучно: сбой по одному счётчику не мешает остальным.
    ok: dict[str, int] = {}
    failed: dict[str, str] = {}
    for cid, value in values.items():
        try:
            readings.send_reading(place["user_place_id"], cid, value, period=args.period)
            ok[cid] = value
        except MosRuError as err:
            failed[cid] = str(err)

    columns = [
        ("counter_id", "id счётчика"),
        ("value", "показание"),
        ("status", "статус"),
        ("message", "сообщение"),
    ]
    items = [
        {
            "counter_id": cid,
            "value": value,
            "status": "передано",
            "message": "",
        }
        for cid, value in ok.items()
    ] + [
        {"counter_id": cid, "value": values[cid], "status": "ошибка", "message": message}
        for cid, message in failed.items()
    ]
    output_items(args, items, columns)
    if failed:
        sys.exit(3)


def cmd_remove_last(args) -> None:
    """Удалить последнее показание счётчика (только с явным --yes)."""
    if not args.yes:
        print(
            "Удаление последнего показания необратимо (удаляется запись независимо "
            "от того, кто её внёс). Повторите команду с --yes для подтверждения.",
            file=sys.stderr,
        )
        sys.exit(3)
    _, readings = _connect(args)
    readings.remove_last_indication(args.place, args.counter_id)
    output_items(
        args,
        [{"counter_id": args.counter_id, "place": args.place, "status": "удалено"}],
        [("counter_id", "id счётчика"), ("place", "id помещения"), ("status", "статус")],
    )


ACCOUNTS_COLUMNS = [
    ("account", "лицевой счёт"),
    ("meter", "номер счётчика"),
    ("address", "адрес"),
    ("status", "статус ЛС"),
    ("id_kng", "ID_KNG"),
    ("schema", "схема"),
    ("nm_uchet", "номер учёта"),
    ("balance", "баланс"),
    ("debt", "долг"),
    ("tariff_values", "тарифы, руб"),
    ("last_readings", "предыдущие показания"),
    ("tariff_names", "названия тарифов"),
    ("inspection", "поверка до"),
    ("install", "установлен"),
    ("total_area", "площадь, м²"),
]


def _parse_list_arg(value: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,;]", value or "") if p.strip()]


def cmd_accounts(args) -> None:
    """Лицевые счёта Мосэнергосбыт и их счётчики: вся доступная информация.

    Основной источник — профиль pgu2 (info_blocks[]=HOUSE): все помещения
    пользователя с лицевыми счетами МЭС, счётчиками, адресами и площадями.
    Дополнительно можно указать --account/--meter. По каждому счётчику
    собирается пакет сервисов МЭС: generalInfo (адрес, номер учёта),
    getSchetch (поверка), getLastPok (предыдущие показания, названия
    тарифов, дата установки), getVlTarif (тарифы), calcBalanceEx
    (баланс, долг, начисления, платежи).
    """
    auth = MosRuAuth()
    try:
        auth.restore(args.session)
    except FileNotFoundError:
        print(f"Файл сессии не найден: {args.session}")
        sys.exit(2)
    if not auth.is_alive():
        print("Сессия истекла — повторите вход: python mosru-meters.py login")
        sys.exit(2)
    readings = MosRuReadings(auth)

    extra_meters = _parse_list_arg(getattr(args, "meter", ""))

    # 1) Профиль pgu2 — основной источник: помещения с ЛС и счётчиками.
    entries: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    try:
        profile_rows = readings.list_electricity_accounts()
    except MosRuError as err:
        LOGGER.warning("Профиль pgu2 недоступен: %s", err)
        profile_rows = []
    for row in profile_rows:
        key = (row["account"], row["meter"])
        if not row["account"] or key in seen_pairs:
            continue
        seen_pairs.add(key)
        entries.append({**row, "source": "профиль"})

    # 2) Ручные ЛС (--account) — для счётов, которых нет в профиле.
    manual_accounts: list[str] = []
    for value in args.account or []:
        for account in _parse_list_arg(value):
            if account not in manual_accounts:
                manual_accounts.append(account)
    for account in manual_accounts:
        key = (account, extra_meters[0] if extra_meters else "")
        if key not in seen_pairs:
            seen_pairs.add(key)
            entries.append(
                {
                    "account": account,
                    "meter": extra_meters[0] if extra_meters else "",
                    "address": "",
                    "source": "аргумент",
                }
            )

    if not entries:
        raise SystemExit(
            "Профиль pgu2 не вернул помещений с лицевыми счетами. "
            "Укажите --account <ЛС Мосэнергосбыт> и --meter."
        )

    rows: list[dict] = []
    account_status: dict[str, str] = {}
    for entry in entries:
        account = entry["account"]
        meter = entry["meter"]
        if account not in account_status:
            try:
                check = readings.mes_check_account(account)
                code = str(check.get("NN_ANS_CHECK_USR"))
                account_status[account] = "найден" if code == "1" else f"код {code or '?'}"
            except MosRuError as err:
                account_status[account] = f"ошибка: {err}"

        row = {
            "account": account,
            "status": account_status[account],
            "meter": meter,
            "id_kng": "",
            "schema": "",
            "address": entry.get("address", ""),
            "nm_uchet": "",
            "balance": "",
            "debt": "",
            "tariff_values": "",
            "last_readings": "",
            "tariff_names": "",
            "inspection": "",
            "install": "",
            "total_area": entry.get("total_area", ""),
            "source": entry.get("source", ""),
            "services": {},
        }
        if not meter:
            rows.append(row)
            continue
        try:
            shetch = readings.mes_check_meter(account, meter)
            id_kng = shetch.get("ID_KNG")
            schema = shetch.get("SCHEMA")
            row.update(id_kng=id_kng, schema=schema)
            if not row["status"].startswith("найден"):
                row["status"] = "ЛС и счётчик найдены"
            services = readings.mes_account_info(account, id_kng, schema)
            row["services"] = services

            g = services.get("generalInfo") or {}
            bal = services.get("calcBalanceEx") or {}
            sch = services.get("getSchetch") or {}
            lp = services.get("getLastPok") or {}
            vt = services.get("getVlTarif") or {}
            row["address"] = row["address"] or _norm(g.get("ADDR"))
            row["nm_uchet"] = _norm(g.get("NM_UCHET"))
            row["balance"] = _norm(bal.get("SM_BALANCE"))
            row["debt"] = _norm(bal.get("SM_DOLG"))
            row["inspection"] = _norm(sch.get("DT_DATE_MPI"))
            row["install"] = _norm(lp.get("SH_UST"))
            row["tariff_names"] = " / ".join(
                str(lp[f"NM_T{i}"]).replace(f"(T{i}):", "").strip().rstrip(":").strip()
                for i in (1, 2, 3)
                if lp.get(f"NM_T{i}") is not None
            )
            row["last_readings"] = " / ".join(
                str(lp[f"POK_T{i}"]) for i in (1, 2, 3) if lp.get(f"POK_T{i}") is not None
            )
            row["tariff_values"] = " / ".join(
                str(vt[f"VL_TAR_T{i}"])
                for i in (1, 2, 3)
                if vt.get(f"VL_TAR_T{i}") is not None
            )
        except MosRuError as err:
            row["status"] = f"счётчик не найден на ЛС ({err})"
        rows.append(row)

    output_items(args, rows, ACCOUNTS_COLUMNS)


def cmd_send_electricity(args) -> None:
    """Передать показания электричества через mos.ru (pgu2/counters → МЭС).

    --values: тарифы в любом порядке, номер тарифа берётся из ключа (T1–T3).
    --account — лицевой счёт Мосэнергосбыт с квитанции (три части через дефис);
    после первой успешной передачи сохраняется в файл сессии и дальше
    указывать не нужно.
    """
    pairs: dict[str, int] = {}
    for chunk in re.split(r"[,;]", args.values):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, sep, value_str = chunk.partition(":")
        # Кириллическая «Т» — частая опечатка, приводим к латинской T.
        key = key.strip().replace("Т", "T").replace("т", "T").upper()
        value_str = value_str.strip().replace(",", ".")
        if not sep or not key:
            raise SystemExit(
                f"Некорректная пара «{chunk}» — ожидается тариф:значение, например T1:2836"
            )
        if not re.fullmatch(r"T\d+", key):
            raise SystemExit(
                f"Некорректный тариф «{key}» в паре «{chunk}» — ожидается T1–T3"
            )
        if key in pairs:
            raise SystemExit(f"Тариф {key} указан дважды")
        try:
            pairs[key] = int(float(value_str))
        except ValueError:
            raise SystemExit(f"Некорректное значение показания в паре «{chunk}»")
    if not pairs:
        raise SystemExit("Не передано ни одной пары тариф:значение")
    bad = [k for k in pairs if k not in MES_TARIFFS]
    if bad:
        raise SystemExit(
            f"Тариф {', '.join(sorted(bad))} не поддерживается — используйте T1, T2 или T3"
        )

    auth, readings = _connect(args)
    account = args.account
    meter_number = str(args.meter)

    res = readings.send_electricity(account, meter_number, pairs)
    accepted = (
        res.get("NM_RESULT") or "Показания приняты"
    )
    output_items(
        args,
        [
            {
                "tariff": key,
                "value": pairs[key],
                "meter": meter_number,
                "status": accepted,
            }
            for key in sorted(pairs, key=lambda k: int(k[1:]))
        ],
        [
            ("tariff", "тариф"),
            ("value", "показание"),
            ("meter", "счётчик"),
            ("status", "результат"),
        ],
    )


PLACE_ARG = lambda p: (  # noqa: E731 — общий аргумент «id помещения»
    p.add_argument("--place", default="", help="id помещения (см. places)")
)

# Общие флаги формата вывода: --md по умолчанию, --json/--csv — альтернативы.
OUTPUT_FLAGS = argparse.ArgumentParser(add_help=False)
OUTPUT_GROUP = OUTPUT_FLAGS.add_mutually_exclusive_group()
OUTPUT_GROUP.add_argument("--json", action="store_true",
                          help="вывести в JSON (stdout)")
OUTPUT_GROUP.add_argument("--csv", action="store_true",
                          help="вывести в CSV с разделителем «;» (stdout)")
OUTPUT_GROUP.add_argument("--md", action="store_true",
                          help="вывести в Markdown (по умолчанию)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--session", default=DEFAULT_SESSION_FILE, help="файл cookies сессии")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "login", parents=[OUTPUT_FLAGS], help="вход на mos.ru (QR-код по умолчанию)"
    )
    p.add_argument("--password", action="store_true", help="вход по паролю вместо QR")
    p.add_argument("--login", help="логин (с --password)")

    p = sub.add_parser("whoami", parents=[OUTPUT_FLAGS], help="проверить живость сессии")
    p = sub.add_parser(
        "places", parents=[OUTPUT_FLAGS], help="список помещений (квартир) с id"
    )

    for name, help_text in (
        ("meters", "счётчики: id, тип, номер, поверка, отправка"),
        ("latest", "последние показания: вода + электричество"),
    ):
        p = sub.add_parser(name, parents=[OUTPUT_FLAGS], help=help_text)
        PLACE_ARG(p)
        p.add_argument("--meter", default="",
                       help="фильтр: id счётчиков воды / номера электросчётчиков через запятую; "
                       "с --account — номер электросчётчика МЭС")
        p.add_argument("--paycode", default="", help="код плательщика (ЕПД), вместо --place")
        p.add_argument("--flat", default="", help="номер квартиры, вместе с --paycode")
    sub.choices["latest"].add_argument(
        "--account", default="",
        help="лицевой счёт Мосэнергосбыт: latest по API pgu2 (стоимость тарифов)",
    )

    p = sub.add_parser(
        "history", parents=[OUTPUT_FLAGS],
        help="вся история показаний (вода + электричество), единая таблица",
    )
    p.add_argument("--kind", choices=("all", "water", "electricity"), default="all")
    p.add_argument("--include-empty", action="store_true",
                   help="включить периоды без показаний")
    p.add_argument("--meter", default="",
                   help="фильтр: id счётчиков воды / номера электросчётчиков через запятую")
    p.add_argument("--limit", type=int, default=None,
                   help="ограничить таблицу markdown (json/csv — всегда всё)")
    PLACE_ARG(p)
    p.add_argument("--paycode", default="", help="код плательщика (ЕПД), вместо --place")
    p.add_argument("--flat", default="", help="номер квартиры, вместе с --paycode")

    p = sub.add_parser(
        "water-send", parents=[OUTPUT_FLAGS],
        help="передать показания счётчиков (пары id_счётчика:значение)",
    )
    p.add_argument("--place", required=True, help="id помещения (см. places)")
    p.add_argument(
        "--values",
        required=True,
        help='пары через запятую: "1113272:123,1113273:124" (id счётчика — см. meters)',
    )
    p.add_argument("--period", help="YYYY-MM-DD (по умолчанию — расчётный период портала)")

    p = sub.add_parser(
        "remove-last", parents=[OUTPUT_FLAGS],
        help="удалить последнее показание счётчика",
    )
    p.add_argument("--counter-id", required=True, help="id счётчика (см. meters)")
    p.add_argument("--place", required=True, help="id помещения (см. places)")
    p.add_argument("--yes", action="store_true", help="подтвердить удаление")

    p = sub.add_parser(
        "electro-accounts", parents=[OUTPUT_FLAGS],
        help="лицевые счёта Мосэнергосбыт и счётчики: полная информация",
    )
    p.add_argument(
        "--account", action="append", default=[],
        help="лицевой счёт (можно несколько раз или через запятую); "
        "без аргумента — сохранённые в сессии",
    )
    p.add_argument(
        "--meter", default="",
        help="номера счётчиков через запятую — привязать к лицевому счёту(ам)",
    )

    p = sub.add_parser(
        "electro-send", parents=[OUTPUT_FLAGS],
        help="передать показания электричества через mos.ru (ЛС Мосэнергосбыт)",
    )
    p.add_argument(
        "--values", required=True,
        help='тарифы через запятую, порядок любой: "T1:2836,T2:2859,T3:3676"',
    )
    p.add_argument(
        "--account", required=True,
        help="лицевой счёт Мосэнергосбыт (из вывода electro-accounts)",
    )
    p.add_argument(
        "--meter", required=True,
        help="номер электросчётчика (из вывода electro-accounts)",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    handlers = {
        "login": cmd_login,
        "whoami": cmd_whoami,
        "places": cmd_places,
        "meters": cmd_meters,
        "latest": cmd_latest,
        "history": cmd_history,
        "water-send": cmd_send,
        "remove-last": cmd_remove_last,
        "electro-send": cmd_send_electricity,
        "electro-accounts": cmd_accounts,
    }
    try:
        handlers[args.command](args)
    except MosRuError as err:
        print(f"Ошибка: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
