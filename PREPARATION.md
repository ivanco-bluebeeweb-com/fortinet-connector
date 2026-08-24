# Fortinet Connector — Preparation (Фаза 2.5, до кода)

**Дата:** 2026-08-24. Основано на `CONNECTOR_DISCOVERY.md`. SIEM/SOAR-серия —
"максимальный функционал, полный максимум" заявлен заранее, повторный вопрос
не требуется.

## 1. WHY BYOK

FortiGate/FortiManager/FortiSASE живут в облаке или инфраструктуре клиента —
Imperal не брокерит доступ централизованно, тот же принцип, что Zscaler/
Cisco Secure Access/MuleSoft Connector.

## 2. WHY три раздельные поверхности внутри одного коннектора

Fortinet Security Fabric состоит из архитектурно несовместимых API (см.
CONNECTOR_DISCOVERY.md §1). Объединение под одним "Fortinet Connector"
отражает реальную покупательскую единицу (один вендор, одна лицензия
Security Fabric), но каждая поверхность подключается и работает независимо
— клиент использует одну, две или все три.

## 3. WHY FortiManager session хранится как session-token в теле запроса, не header

JSON-RPC login (`exec` на `/sys/login/user`) — дорогая операция,
возвращающая `session` строку, которая ОБЯЗАНА передаваться как поле
`session` в теле каждого последующего JSON-RPC запроса (FortiManager API
design, не выбор коннектора). Сессия кешируется и переиспользуется до
явного кода ошибки сессии в JSON-ответе, затем re-login прозрачно — тот же
ленивый-refresh принцип, что у OAuth2 client_credentials коннекторов
(Zscaler/Sentinel/Defender), но триггер обнаруживается в теле ответа, а не
по HTTP-статусу.

## 4. WHY FortiGate/FortiSASE используют статичный Bearer-токен, FortiManager — нет

FortiGate REST API Admin токен и FortiSASE FortiCloud IAM токен — оба
статичные API-ключи без expiry-цикла, управляемого коннектором (revoke
делается вручную в GUI/IAM). FortiManager, напротив, требует активную
сессию с ограниченным временем жизни — разные модели авторизации у разных
продуктов одного вендора, коннектор не может унифицировать их искусственно
без потери реального поведения API.

## 5. WHY update firewall policy / VPN / SASE policy требуют явного
подтверждения и явного указания затронутого диапазона

Ошибочное правило firewall policy на FortiGate или SASE policy на FortiSASE
способно оборвать связь для целой подсети или заблокировать легитимный
трафик — тот же класс риска, что isolate_endpoint у EDR-коннекторов.
Инструмент явно называет затрагиваемый IP/CIDR/policy id перед применением.

## 6. WHY FortiManager требует adom как явный параметр с дефолтом "root"

FortiManager группирует управляемые устройства по Administrative Domains
(ADOM) — без явного ADOM большинство операций (Policy Package edit, device
add) обращаются не туда, куда ожидает пользователь с несколькими ADOM.
Дефолт `root` покрывает единственный распространённый случай (нет
multi-ADOM настройки), но параметр остаётся явным и переопределяемым.

## 7. Scope (Ярус 1+2+3, максимум по заявленному объёму)

**Я1 (must):** connect/disconnect (все три поверхности), list connections,
FortiGate: list/create/update/delete firewall policy, list address/service
objects, list interfaces. FortiManager: login/session, list managed
devices, list policy packages, list ADOMs. FortiSASE: list ZTNA endpoints,
list SD-WAN sites, list security events.

**Я2 (should):** FortiGate VPN tunnel status, address group CRUD.
FortiManager: install policy package to device, device add/remove.
FortiSASE: SASE policy CRUD, endpoint quarantine.

**Я3 (nice):** bulk operations (bulk policy enable/disable across devices),
estate-wide health audit (`audit_fortinet_estate`) aggregating FortiGate
device health + FortiManager device sync status + FortiSASE endpoint
posture in one report — same "audit_*" value-add pattern as every other
connector in the portfolio.

## 8. Explicitly out of scope this release

FortiAnalyzer (dedicated SIEM/log-analytics product, separate API/host) and
FortiEDR/FortiClient EMS (separate endpoint products) are NOT covered by
this connector — different products with their own onboarding surface,
would need their own connect_* flow and are candidates for a future
separate app, not scope creep into this one.
