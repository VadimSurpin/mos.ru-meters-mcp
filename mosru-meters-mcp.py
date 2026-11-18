#!/usr/bin/env python3
"""MCP-сервер mosru-meters-mcp — инструменты поверх mosru-meters.py.

Показывает инструменты MCP (Model Context Protocol) для работы с mos.ru:
QR-вход, помещения, счётчики, последние показания (вода и электричество,
включая стоимость тарифов), полная история, передача и удаление показаний.

Запуск (stdio):
    python mosru-meters-mcp.py

Подключение в клиенте (пример):
    {
      "mcpServers": {
        "mosru-meters-mcp": {
          "command": "/путь/к/.venv/bin/python",
          "args": ["/путь/к/mosru-meters-mcp.py"]
        }
      }
    }

Файл сессии — mosru_session.json рядом с mosru-meters.py (переопределяется
переменной окружения MOSRU_SESSION_FILE). Зависимости: requests, mcp>=2.

Инструменты
-----------
- session_status    — живость сессии и cookies.
- login_get_url     — получить ссылку для QR-входа.
- login_wait        — дождаться подтверждения в приложении (после сканирования).
- login_submit_code — второй фактор: код из SMS или приложения-аутентификатора.
- places            — помещения: id, адрес, код плательщика.
- meters            — счётчики помещения: id, тип, номер, поверка, отправка.
- latest            — последние показания; с account/meter — через МЭС со
                      стоимостью каждого тарифа.
- history           — вся история показаний (вода + электричество).
- water_send        — передать показания воды {id счётчика: значение}.
- water_remove_last — удалить последнее показание (только confirm=true).
- electro_accounts  — лицевые счёта МЭС и счётчики: адрес, баланс, тарифы…
- electro_send      — передать показания электричества {"T1": …, "T2": …}.
- electro_latest    — последние показания электричества через МЭС + стоимость.
"""
from __future__ import annotations

import functools
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB_PATH = HERE / "mosru-meters.py"
SESSION_FILE = os.environ.get("MOSRU_SESSION_FILE", str(HERE / "mosru_session.json"))


def _load_library():
    """Загрузить mosru-meters.py как модуль (имя файла содержит дефис)."""
    spec = importlib.util.spec_from_file_location("mosru_meters_lib", LIB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LIB = _load_library()

from mcp.server.mcpserver import MCPServer  # noqa: E402 — после загрузки библиотеки

server = MCPServer(
    "mosru-meters-mcp",
    instructions=(
        "Инструменты mos.ru: помещения, счётчики воды и электричества, "
        "последние показания и история, передача/удаление показаний. "
        "Для работы нужен вход: login_get_url → пользователь подтверждает "
        "QR в приложении mos.ru → login_wait (при необходимости "
        "login_submit_code). Данные: places → meters/latest/history; "
        "water_send для воды; electro-инструменты по лицевому счёту МЭС "
        "(electro_accounts показывает доступные счёта и номера счётчиков)."
    ),
)

# Состояние активного QR-входа (между вызовами login_*).
_login_state: dict = {"auth": None, "url": None, "factor": None}


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=1)


def _tool(fn):
    """Единый вывод ошибок API в JSON вместо исключений."""

    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return _json(fn(*a, **k))
        except LIB.MosRuError as err:
            return _json({"error": str(err), "kind": type(err).__name__})

    return wrapper


def _session_auth() -> LIB.MosRuAuth:
    """Аутентификация из файла сессии (без OAuth ЭД)."""
    auth = LIB.MosRuAuth()
    auth.restore(SESSION_FILE)  # FileNotFoundError, если файла нет
    if not auth.is_alive():
        raise LIB.AuthError(
            "Сессия истекла или отсутствует — выполните login_get_url + login_wait "
            "(или python mosru-meters.py login в терминале)"
        )
    return auth


def _connected() -> tuple[LIB.MosRuAuth, LIB.MosRuReadings]:
    """Аутентификация + авторизация «Электронного дома» (нужна для воды/ЭД)."""
    auth = _session_auth()
    auth.authorize_ed()
    return auth, LIB.MosRuReadings(auth)


# ── Вход ────────────────────────────────────────────────────────────────────


@server.tool()
@_tool
def session_status() -> str:
    """Живость сессии mos.ru и список cookies."""
    auth = LIB.MosRuAuth()
    try:
        auth.restore(SESSION_FILE)
    except FileNotFoundError:
        return _json({"alive": False, "session_file": SESSION_FILE, "note": "сессии нет"})
    return _json(
        {
            "alive": auth.is_alive(),
            "session_file": SESSION_FILE,
            "cookies": auth.cookie_names(),
        }
    )


@server.tool()
@_tool
def login_get_url() -> str:
    """Получить ссылку для QR-входа на mos.ru.

    Покажите ссылку пользователю как QR-код или отправьте на телефон;
    после подтверждения в приложении mos.ru / «Госуслуги Москвы»
    вызовите login_wait.
    """
    auth = LIB.MosRuAuth()
    url = auth.get_qr_url()
    _login_state.update(auth=auth, url=url, factor=None)
    return _json(
        {
            "url": url,
            "next": "login_wait",
            "hint": "отсканируйте приложением mos.ru / «Госуслуги Москвы»",
        }
    )


@server.tool()
@_tool
def login_wait(timeout_sec: int = 240, poll_interval_sec: float = 3.0) -> str:
    """Дождаться подтверждения QR-входа и завершить авторизацию.

    Если QR истёк — обновляется автоматически (новая ссылка вернётся в
    поле last_url, покажите её снова). Если аккаунт защищён вторым
    фактором — вернётся status "sms_required"/"totp_required", код
    передаётся через login_submit_code.
    """
    auth = _login_state.get("auth")
    if auth is None:
        raise RuntimeError("Сначала вызовите login_get_url")
    deadline = time.monotonic() + max(30, int(timeout_sec))
    while time.monotonic() < deadline:
        command = auth.poll_qr()
        if command == "needRefresh":
            _login_state["url"] = auth.refresh_qr()["link"]
        elif command == "needComplete":
            factor = auth.complete_qr_auth()
            if factor == LIB.SecondFactor.NONE:
                if "Ltpatoken2" not in auth.cookie_names():
                    raise LIB.AuthError("Авторизация не завершена: Ltpatoken2 не установлен")
                auth.warm_session()
                auth.save(SESSION_FILE)
                _login_state.update(auth=None, factor=None)
                return _json({"status": "done", "session_file": SESSION_FILE})
            _login_state.update(factor=factor, auth=auth)
            return _json(
                {
                    "status": factor,
                    "hint": "вызовите login_submit_code с кодом "
                    + ("из SMS" if factor == LIB.SecondFactor.SMS else "из приложения-аутентификатора"),
                }
            )
        time.sleep(max(1.0, float(poll_interval_sec)))
    return _json({"status": "timeout", "last_url": _login_state.get("url")})


@server.tool()
@_tool
def login_submit_code(code: str) -> str:
    """Отправить код второго фактора (SMS или приложение-аутентификатор).

    Вызывается после login_wait, если тот вернул status
    "sms_required"/"totp_required".
    """
    auth = _login_state.get("auth")
    factor = _login_state.get("factor")
    if not auth or not factor or factor == LIB.SecondFactor.NONE:
        raise RuntimeError("Нет активного входа со вторым фактором")
    if factor == LIB.SecondFactor.SMS:
        auth.submit_sms_code(code)
    elif factor == LIB.SecondFactor.TOTP:
        auth.submit_totp_code(code)
    else:
        raise RuntimeError(f"Неожиданный фактор: {factor}")
    auth.warm_session()
    auth.save(SESSION_FILE)
    _login_state.update(auth=None, factor=None)
    return _json({"status": "done", "session_file": SESSION_FILE})


# ── Данные ──────────────────────────────────────────────────────────────────


@server.tool()
@_tool
def places() -> str:
    """Помещения (квартиры): id помещения, адрес, квартира, код плательщика."""
    _, readings = _connected()
    return _json(readings.list_places())


@server.tool()
@_tool
def meters(place_id: str = "") -> str:
    """Счётчики помещения: id, тип (ХВС/ГВС/ЭЛ), номер, показание, поверка,
    доступность передачи показаний."""
    _, readings = _connected()
    place = readings.find_place(user_place_id=place_id)
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
                    "доступна" if can_submit
                    else ("запрещена" if can_submit is False else "")
                ),
                "inspection_date": m.get("inspection_date"),
                "inspection_status": m.get("inspection_status"),
            }
        )
    return _json(items)


@server.tool()
@_tool
def latest(place_id: str = "", account: str = "", meter: str = "") -> str:
    """Последние показания: вода (utility-meter) + электричество.

    С account и meter — электричество из МЭС (pgu2/counters): предыдущие
    переданные показания и стоимость каждого тарифа. Без них — из
    «Электронного дома».
    """
    _, readings = _connected()
    place = readings.find_place(user_place_id=place_id)
    items: list[dict] = []

    for m in readings.get_meters(place):
        recent = m.get("recent") or []
        if recent:
            for r in recent:
                items.append(
                    {
                        "meter_id": m["id"],
                        "type": m.get("type") or "",
                        "number": m.get("number") or "",
                        "tariff": "",
                        "period": LIB.normalize_period(r.get("period")),
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
                    "period": LIB.normalize_period(m.get("reading_period")),
                    "indication": m.get("current_reading"),
                    "usage": None,
                    "cost": None,
                    "source": None,
                }
            )

    if account and meter:
        info = readings.mes_electricity_latest(account, meter)
        items.extend(info["rows"])
    else:
        try:
            last = readings.get_electricity_last(place["user_place_id"])
        except LIB.ApiError:
            last = {}
        if last and last.get("meter_number"):
            for t in last.get("tariffs") or []:
                items.append(
                    {
                        "meter_id": str(last["meter_number"]),
                        "type": "ЭЛ",
                        "number": str(last["meter_number"]),
                        "tariff": f"{t['key']} ({t['name']})" if t.get("name") else t["key"],
                        "period": LIB.normalize_period(last.get("date")),
                        "indication": t.get("value"),
                        "usage": t.get("usage"),
                        "cost": None,
                        "source": None,
                    }
                )
    return _json(items)


@server.tool()
@_tool
def history(
    place_id: str = "",
    kind: str = "all",
    meter: str = "",
    limit: int | None = None,
    include_empty: bool = False,
) -> str:
    """Вся история показаний помещения: вода (архив с 2000 г.) + электричество.

    kind: all | water | electricity. meter — фильтр: id счётчиков воды /
    номера электросчётчиков через запятую. limit ограничивает число записей
    каждого типа.
    """
    _, readings = _connected()
    place = readings.find_place(user_place_id=place_id)
    meter_filter = {p.strip() for p in re.split(r"[,;]", meter or "") if p.strip()}

    water: list[dict] = []
    electricity: list[dict] = []
    if kind in ("water", "all"):
        try:
            archive = readings.get_water_archive(place, include_empty=include_empty)
        except LIB.ApiError as err:
            archive = {"_error": str(err)}
        for counter_id, meta in archive.items():
            for item in meta["items"]:
                if item["indication"] is None and not include_empty:
                    continue
                water.append(
                    {
                        "counter_id": counter_id,
                        "type": meta["type"],
                        "number": meta["number"],
                        "period": item["period"],
                        "indication": item["indication"],
                        "source": item["source"],
                    }
                )
        if limit is not None:
            water = water[:limit]

    if kind in ("electricity", "all"):
        try:
            electricity_items = readings.get_electricity_history(place["user_place_id"])
        except LIB.ApiError as err:
            electricity = [{"error": str(err)}]
            electricity_items = []
        for item in electricity_items:
            for tariff in item["tariffs"]:
                electricity.append(
                    {
                        "meter_number": item.get("meter_number") or "",
                        "period": LIB.normalize_period(item.get("date")),
                        "tariff": (
                            f"{tariff['key']} ({tariff['name']})"
                            if tariff.get("name") else tariff["key"]
                        ),
                        "indication": tariff.get("value"),
                        "usage": tariff.get("usage"),
                        "source": item.get("source"),
                    }
                )
        if meter_filter:
            electricity = [
                row for row in electricity
                if row.get("meter_number") in meter_filter
            ]
        if limit is not None:
            electricity = electricity[:limit]

    result: dict = {"place": place}
    if kind in ("water", "all"):
        result["water"] = water
    if kind in ("electricity", "all"):
        result["electricity"] = electricity
    return _json(result)


# ── Передача/удаление показаний ─────────────────────────────────────────────


@server.tool()
@_tool
def water_send(place_id: str, values: dict[str, float], period: str = "") -> str:
    """Передать показания воды: {id счётчика: значение}, счётчики — из meters.

    Значения округляются до целых м³. id проверяются на принадлежность
    помещению до отправки.
    """
    _, readings = _connected()
    place = readings.find_place(user_place_id=place_id)
    results = readings.send_readings(place, values, period=period or None)
    return _json({"submitted": {cid: resp for cid, resp in results.items()}})


@server.tool()
@_tool
def water_remove_last(place_id: str, counter_id: str, confirm: bool = False) -> str:
    """Удалить последнее показание счётчика воды. Требует confirm=true —
    удаление необратимо и убирает запись независимо от того, кто её внёс."""
    if not confirm:
        return _json(
            {
                "error": "требуется confirm=true",
                "note": "удаление необратимо: убирается последнее показание счётчика",
            }
        )
    _, readings = _connected()
    readings.remove_last_indication(place_id, counter_id)
    return _json({"removed": True, "counter_id": counter_id, "place": place_id})


# ── Электричество (pgu2/counters → МЭС) ─────────────────────────────────────


@server.tool()
@_tool
def electro_accounts(account: str = "", meter: str = "") -> str:
    """Лицевые счёта Мосэнергосбыт пользователя и счётчики на них: адрес,
    баланс, долг, тарифы (в т.ч. стоимость), предыдущие показания, поверка.

    По умолчанию — все счёта из профиля pgu2. account/meter — проверка
    конкретного счёта/счётчика.
    """
    _, readings = _connected()
    rows: list[dict] = []
    accounts = [a.strip() for a in re.split(r"[,;]", account or "") if a.strip()]

    if accounts:
        meters_list = [m.strip() for m in re.split(r"[,;]", meter or "") if m.strip()]
        for acc in accounts:
            try:
                check = readings.mes_check_account(acc)
                code = str(check.get("NN_ANS_CHECK_USR"))
                status = "найден" if code == "1" else f"код {code or '?'}"
            except LIB.MosRuError as err:
                status = f"ошибка: {err}"
            for m in meters_list or [None]:
                row = {"account": acc, "status": status, "meter": m or ""}
                if m:
                    try:
                        shetch = readings.mes_check_meter(acc, m)
                        id_kng = shetch.get("ID_KNG")
                        schema = shetch.get("SCHEMA")
                        row.update(
                            id_kng=id_kng,
                            schema=schema,
                            services=readings.mes_account_info(acc, id_kng, schema),
                        )
                    except LIB.MosRuError as err:
                        row["error"] = str(err)
                rows.append(row)
        return _json(rows)

    for house in readings.list_profile_houses():
        acc = str(house.get("MES_ACCOUNT") or "")
        m = str(house.get("MES_METER") or "")
        row = {
            "account": acc,
            "meter": m,
            "address": house.get("ADDRESS_DESCRIPTION")
            or house.get("ADDRESS_FULL")
            or "",
            "total_area": house.get("TOTAL_AREA"),
            "district": house.get("DISTRICTLABEL"),
        }
        if acc and m:
            try:
                shetch = readings.mes_check_meter(acc, m)
                id_kng = shetch.get("ID_KNG")
                schema = shetch.get("SCHEMA")
                row.update(
                    id_kng=id_kng,
                    schema=schema,
                    services=readings.mes_account_info(acc, id_kng, schema),
                )
            except LIB.MosRuError as err:
                row["error"] = str(err)
        rows.append(row)
    return _json(rows)


@server.tool()
@_tool
def electro_send(account: str, meter: str, values: dict[str, int]) -> str:
    """Передать показания электричества через mos.ru (pgu2/counters → МЭС).

    values: {tariff: показание}, например {"T1": 2836, "T2": 2859, "T3": 3676}
    — отсутствующие тарифы передаются нулём; принимается окно 15–26 число.
    account/meter — из electro_accounts.
    """
    _, readings = _connected()
    res = readings.send_electricity(account, meter, values)
    return _json(
        {
            "accepted": res.get("NM_RESULT") or "Показания приняты",
            "values": values,
            "meter": meter,
            "account": account,
        }
    )


@server.tool()
@_tool
def electro_latest(account: str, meter: str) -> str:
    """Последние переданные показания электричества и стоимость каждого
    тарифа через МЭС (getLastPok + getVlTarif). account/meter — из
    electro_accounts."""
    _, readings = _connected()
    return _json(readings.mes_electricity_latest(account, meter))


def main() -> None:
    server.run()  # stdio


if __name__ == "__main__":
    main()
