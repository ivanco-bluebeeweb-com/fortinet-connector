# Fortinet Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `fortinet-connector` (см.
`PREPARATION.md`).

**ВАЖНО (усвоено на Zscaler/Cisco Secure Access Connector — реальные ошибки
DUI-валидатора, не повторять):** `ui.Stack` НЕ принимает `width=`. `ui.Stats`
принимает `children=[ui.Stat(...)]`, НЕ `stats=[...]`/`items=[dict]`.
`ui.Alert` принимает `type=`, НЕ `variant=`. `ui.Input`/`ui.Password`/
`ui.Select` НЕ принимают `label=` — использовать соседний
`ui.Text(..., variant="caption")` внутри `ui.Stack(direction="v", gap=1)`.

## 0. Разница с реализацией сейчас

Реализация начинается с нуля вместе с этим документом — план строится ПЕРЕД
`panels.py`, по правилу APP_PREPARATION_STANDARD.md §9. Начальный `panels.py`
реализует ровно §1 ниже.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left) | `ui.Stack`(direction="v") + `ui.Text`(host/adom summary) + `ui.Divider` + navigation `ui.ListItem`(FortiGate / FortiManager / FortiSASE / Health) + `ui.Button`("App settings") | Без карточек, как Zscaler/Cisco Secure Access Connector. |
| Connect: FortiGate section | `ui.Stack`(direction="v", gap=1, children=[`ui.Text`("Host", variant="caption"), `ui.Input`(param_name="host", placeholder="https://fw01.company.com:443")]) + аналогично Password для api_token + submit `ui.Button` | Каждый инпут с явным лейблом-соседом, контекстный placeholder. |
| Connect: FortiManager section | `ui.Stack`(...) с host/username/password(Input/Input/Password) + adom(Input, placeholder="root") + submit | Явно раздельная секция, форма растянута на всю ширину сайдбара. |
| Connect: FortiSASE section | `ui.Stack`(...) с api_token(Password) + region(Input, placeholder="напр. us") + submit | Третья независимая секция. |
| Empty (нет ни одного подключения) | `ui.Empty`(message="Подключите FortiGate, FortiManager или FortiSASE", action=Connect) | Стандартный первый экран. |
| Empty (одна поверхность не подключена) | `ui.Empty`(message="FortiManager не подключен", action=Connect FortiManager) | Явная, не молчаливая пустота — из IDEAL_ONBOARDING.md §2.6. |
| FortiGate Overview (center, `center_overlay=True`) | `ui.Stats`(children=[Stat(Firewall Policies), Stat(Address Objects), Stat(Interfaces)]) + `ui.Tabs`(Policies / Address Objects / Services / Interfaces / VPN) | Быстрый статус устройства. |
| FortiManager Overview (center) | `ui.Stats`(children=[Stat(ADOMs), Stat(Managed Devices), Stat(Policy Packages)]) + `ui.Tabs`(ADOMs / Devices / Policy Packages / Global Objects) | Быстрый статус парка. |
| FortiSASE Overview (center) | `ui.Stats`(children=[Stat(Endpoints), Stat(SASE Policies), Stat(SD-WAN Sites)]) + `ui.Tabs`(Endpoints / Policies / Sites / Security Events) | Быстрый статус облачного ZTNA. |
| Списки (Policies/Devices/Endpoints/etc.) | `ui.DataTable`(name, status Badge, key detail column) | Табличное представление, консистентно с остальным портфелем. |
| App settings (center) | `ui.Stack`(direction="v") + список подключений с `ui.Button`("Disconnect", variant="danger") на каждой строке | Disconnect живёт только здесь, не в сайдбаре. |

## 2. User flow

Empty → (одна из трёх Connect-форм) → успех → соответствующая Overview
панель (Stats+Tabs) → выбор таба → DataTable списка → детальные
get_*-действия через чат. App settings отдельно, доступен из сайдбара
(последняя кнопка).

## 3. Ошибки на UI

- Неверные credentials → toast с точным текстом (какая из трёх поверхностей,
  401 vs прочее).
- FortiManager session expiry → прозрачный re-login, не показываем
  пользователю как ошибку, если re-login успешен.
- Частично подключено → см. Empty-состояние выше, не пустой список.
