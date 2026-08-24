# Fortinet Connector — идеальный первый запуск

Источник: `ONBOARDING_FIRST_LAUNCH_STANDARD.md`. Целевой пользователь: network/
security admin, управляющий парком FortiGate (напрямую или через
FortiManager) и/или облачным FortiSASE-тенантом.

## 1. Credential type

Три независимые формы, ни одна не обязательна для другой:

- **FortiGate:** `host` (напр. `https://fw01.company.com:443`) + `api_token`
  (REST API Admin токен).
- **FortiManager:** `host` + `username` + `password` (session-based login) +
  опциональный `adom` (по умолчанию `root`).
- **FortiSASE:** `api_token` (FortiCloud IAM) + опциональный `region`.

## 2. Идеальный флоу

1. **Первое открытие** — `Empty` с тремя равнозначными путями: "Подключить
   FortiGate", "Подключить FortiManager", "Подключить FortiSASE" — не
   визард, три независимых входа (клиент использует одну, две или все три
   поверхности).
2. **Форма FortiGate** — `host` + `api_token` (password). Подсказка (в
   help-модалке): как создать REST API Admin в самом FortiGate (System >
   Administrators > Create New > REST API Admin > привязать к Trusted Host).
3. **Форма FortiManager** — `host` + `username` + `password` (password) +
   `adom` (опционально, по умолчанию root). Подсказка: сессионный логин
   истекает — коннектор re-login'ится прозрачно при следующем вызове, не
   требуя от пользователя переподключаться вручную.
4. **Форма FortiSASE** — `api_token` (password) + `region`. Подсказка: где
   в FortiCloud создаётся API-токен (Identity & Access Management > API
   tokens).
5. **После успеха (каждая форма)** — сводка, специфичная для поверхности:
   FortiGate → версия/модель/serial устройства; FortiManager → сколько
   managed devices и ADOM видно; FortiSASE → сколько endpoints и активных
   SASE policies.
6. **Частичное подключение** — если подключена только одна поверхность,
   вкладки других показывают `Empty` с точным объяснением "FortiManager не
   подключен" — не пустой список без причины.
7. **Ошибка неверных credentials** — FortiGate/FortiManager/FortiSASE каждый
   возвращают разный формат ошибки авторизации; коннектор обязан различать
   401 (неверные credentials) от прочих кодов и не путать их с общими
   сетевыми сбоями.
8. **Session expiry (FortiManager specifically)** — JSON-RPC сессия имеет TTL;
   коннектор ловит `-11` (No permission)/session invalid код и делает один
   прозрачный re-login перед тем как сдаться и показать ошибку пользователю.
