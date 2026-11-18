# mos.ru-meters-mcp

Python-проект для работы с порталом mos.ru: счётчики воды и электричества —
последние показания, полная история, передача и удаление. Состоит из
автономного CLI-скрипта **`mosru-meters.py`** и MCP-сервера
**`mosru-meters-mcp.py`** (Model Context Protocol) поверх него.

## Возможности

- Вход через QR-код: скрипт выдаёт ссылку, подтверждение — в приложении
  mos.ru / «Госуслуги Москвы» (биометрия/ключ доступа телефона). Второй
  фактор — SMS или код из приложения-аутентификатора.
- Помещения (квартиры) и счётчики: id, типы (ХВС/ГВС/ЭЛ), номера, поверка,
  доступность передачи показаний.
- Последние показания: вода — с источником внесения (mos.ru / ГИС /
  сервисная проверка); электричество — по тарифам T1/T2/T3 со стоимостью.
- Полная история показаний: вода — архив с 2000 года с дробными значениями
  (utility-meter API), электричество — из «Электронного дома».
- Передача показаний воды по id счётчиков и удаление последнего показания.
- Передача показаний электричества через mos.ru (`pgu2/counters` → МЭС) —
  по лицевому счёту с квитанции, без учётной записи Мосэнергосбыт.
- Лицевые счёта Мосэнергосбыт из профиля: адрес, баланс, долг, тарифы,
  предыдущие показания, поверка.
- MCP-сервер: те же операции как инструменты для ИИ-клиентов
  (Claude Desktop, OpenCode, Cursor и т.п.).

## Установка

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Зависимости: `requests`; для MCP-сервера — `mcp>=2`; для отображения QR в
терминале — `qrcode` (опционально).

## CLI (`mosru-meters.py`)

```bash
python mosru-meters.py login                  # QR-вход: ссылка → подтвердить на телефоне
python mosru-meters.py places                 # помещения: id, адрес, код плательщика
python mosru-meters.py meters --place 1298746 # счётчики: id, тип, поверка
python mosru-meters.py latest --place 1298746 # последние показания
python mosru-meters.py history --json > h.json
python mosru-meters.py water-send --place 1298746 --values "1113272:123,1113273:124"
python mosru-meters.py electro-accounts       # лицевые счёта МЭС и счётчики
python mosru-meters.py electro-send \
    --account 08296-104-95 --meter 19751508 \
    --values "T1:2836,T2:2859,T3:3676"
python mosru-meters.py remove-last --place 1298746 --counter-id 1113273 --yes
```

Формат вывода любой команды: `--md` (по умолчанию) / `--json` / `--csv`
(stdout). Полная справка: `python mosru-meters.py --help`.

Файл сессии `mosru_session.json` (права 0600) — это cookies с полным
доступом к аккаунту; **никогда не публикуйте и не пересылайте его**.

## MCP-сервер (`mosru-meters-mcp.py`)

Запуск: `python mosru-meters-mcp.py` (stdio). Подключение:

```json
{
  "mcpServers": {
    "mosru-meters-mcp": {
      "command": "/путь/к/mosru/.venv/bin/python",
      "args": ["/путь/к/mosru/mosru-meters-mcp.py"]
    }
  }
}
```

Инструменты: `session_status`, `login_get_url`, `login_wait`,
`login_submit_code`, `places`, `meters`, `latest`, `history`, `water_send`,
`water_remove_last`, `electro_accounts`, `electro_send`, `electro_latest`.

## Как это работает

| Сервис | API |
|---|---|
| Вход | login.mos.ru: OAuth + QR (`qrCode/refresh|pull|complete`), SMS/TOTP, proof-of-work для пароля |
| Вода: счётчики и архив | `www.mos.ru/api/utility-meter/v1` (`/device`, `/device/{id}/indication/archive`) |
| Вода: передача и история | «Электронный дом» `ed.mos.ru/api/efp/counters/*` |
| Электричество: история и показания | «Электронный дом» `ed.mos.ru/api/efp/v2/light/*` |
| Электричество: передача | mos.ru `pgu2/counters/api/mes/*` (прокси к МЭС: `checkShetch` → `checkTransPok` → `doTransPok`) |
| Лицевые счёта МЭС | `pgu2/counters/api/profile?info_blocks[]=HOUSE` |

Особенности портала, учтённые в клиенте:

- показания привязаны к расчётному периоду и не перезаписываются — за тот
  же период портал вернёт «уже внесено»; замена = удалить последнее +
  передать заново;
- расчётный период — как у фронта: до 3-го числа включительно показание
  уходит за прошедший месяц;
- электричество принимается в окне приёма (обычно 15–26 число месяца);
- значения передаются целыми числами (м³ / кВт·ч).

## Отказ от ответственности

API неофициальные и могут измениться в любой момент. Проект для управления
**собственным** аккаунтом и **собственными** показаниями. Не публикуйте
файл сессии — он даёт полный доступ к аккаунту.
