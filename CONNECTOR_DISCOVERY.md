# Fortinet Connector — Connector Discovery

**Дата discovery:** 2026-08-24. SIEM/SOAR-серия — "максимальный функционал,
полный максимум" заявлен для всей серии заранее (тот же прецедент, что
Zscaler/CircleCI/MuleSoft), повторный вопрос не требуется.

## 1. Три независимые BYOK-поверхности под одним продуктовым зонтиком

Fortinet Security Fabric состоит из архитектурно несовместимых API,
покрывающих разные уровни управления:

- **FortiGate REST API** (`https://{host}/api/v2/`) — device-level, прямое
  управление ОДНИМ firewall-устройством: firewall policy, address/service
  objects, interfaces, VPN. Авторизация: локальный REST API Admin токен
  (System > Administrators > Create New > REST API Admin), передаётся как
  Bearer.
- **FortiManager JSON-RPC API** (`https://{host}/jsonrpc`) —
  централизованное управление парком FortiGate-устройств через
  Administrative Domains (ADOM), Policy Packages. Авторизация:
  session-based login (`exec` на `/sys/login/user` с username/password
  возвращает `session` токен), передаваемый в теле КАЖДОГО JSON-RPC запроса
  (не HTTP header) — принципиально другая модель, чем везде в портфеле.
- **FortiSASE REST API** — облачный SASE-тенант (ZTNA-эндпоинты, SD-WAN
  sites, Secure Web Gateway policy, security events). Авторизация:
  отдельный FortiCloud IAM API-токен, НЕ связан с FortiGate/FortiManager
  credentials.

## 2. WHY три раздельные формы подключения, а не одна объединённая

Клиент использует любую одну поверхность, любые две, или все три сразу —
типичная крупная организация: FortiManager управляет парком железа,
FortiSASE покрывает облачный ZTNA-периметр, отдельные небольшие офисы
подключены напрямую по FortiGate REST. Принуждение вводить все три набора
credentials сразу было бы избыточным трением. Тот же паттерн раздельных
`connect_*` инструментов, что Cisco Secure Access Connector реализует для
Umbrella/Meraki.

## 3. WHY FortiManager session — непрозрачный токен в теле запроса, не header

JSON-RPC 2.0 у FortiManager не следует привычной REST-семантике заголовков
авторизации: `session` — это поле верхнего уровня JSON-тела каждого
запроса, возвращаемое методом login и требующее явной передачи в каждом
последующем вызове. Сессия истекает по таймауту неактивности и требует
re-login (не token refresh) при коде ошибки `-11` (No permission for the
resource) — клиент делает один прозрачный re-login перед тем как сдаться и
вернуть ошибку пользователю.

## 4. Ключевые домены API по поверхности

- **FortiGate:** `/api/v2/cmdb/firewall/policy` (правила),
  `/api/v2/cmdb/firewall/address` (address objects),
  `/api/v2/cmdb/firewall/service/custom` (service objects),
  `/api/v2/cmdb/system/interface` (interfaces, read),
  `/api/v2/monitor/vpn/ipsec` (VPN tunnels, read),
  `/api/v2/monitor/system/status` (health).
- **FortiManager:** JSON-RPC методы `get`/`add`/`set`/`delete`/`exec` на
  `/dvmdb/adom/{adom}/device` (managed devices), `/pm/pkg/adom/{adom}`
  (policy packages), `/dvmdb/adom` (ADOM list).
- **FortiSASE:** endpoints/SASE policy/SD-WAN sites/security events REST
  под облачным FortiCloud IAM токеном.

## 5. Разграничение с остальными приложениями SIEM/SOAR-серии

Fortinet — единственный в этой серии, кто РЕАЛЬНО меняет сетевую
инфраструктуру на уровне firewall policy (не только читает/управляет
инцидентами/endpoint-ами, как Sentinel/CrowdStrike/Cortex XDR/Defender).
Изменение firewall policy на FortiGate/FortiManager несёт больший blast
radius, чем isolate_endpoint — ошибка в address object может оборвать
трафик целой подсети, а не одного хоста.

## 6. Явно вне объёма первого релиза

FortiAnalyzer (централизованный лог-менеджмент/SIEM-слой) и FortiEDR/
FortiClient EMS — отдельные продукты Fortinet с собственными API, не
покрыты этим коннектором в первом релизе (описание приложения явно
называет это ограничение, а не скрывает).
