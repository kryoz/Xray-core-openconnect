# Запрос: per-user split routing (`routes` на пользователе, а не только на inbound)

**Дата:** 2026-09-26
**Тип:** feature request (не блокер тестового инстанса; блокер паритетного cutover прод-сервера)
**База:** dist sha256 `af24b8f1…` (коммиты `8c2f0f3a` split-routing, `1f769e97` camouflage)

---

## 1. Зачем

Прод-сервер (миграция ocserv 1.4.0 → Xray-openconnect, один inbound на :443)
имеет 20 пользователей в двух группах ocserv:

* `fullroute` (14) — весь трафик через туннель;
* `splitroute` (6, роутеры) — `no-route = 0.0.0.0/0`: клиент **не** тянет
  default route, в туннель идёт только назначенная подсеть и серверные сети.

Сейчас `routes` задан на inbound → на :443 одна политика для всех. Либо все
full (роутеры начнут гнать весь трафик через out-ноду — чужая география и
нагрузка), либо все split (ломает fullroute-пользователей). Нужен per-user
выбор. Именованные группы не обязательны — «группа» у нас остаётся
конвенцией конфига; достаточно переопределения на пользователе.

## 2. Что просим

Поле `routes` у пользователя, переопределяющее inbound-политику:

```proto
message User {
  string name = 1;
  string password = 2;
  string ip = 3;
  // Split-routing override: when non-empty, used instead of the
  // inbound-level routes for this user's sessions.
  repeated string routes = 4;
}
```

JSON (infra/conf): `OpenConnectUserConfig.Routes []string` с тегом
`json:"routes,omitempty"`.

### Семантика (важно зафиксировать)

1. **Разрешение:** `user.routes` (если не пуст) → иначе `inbound.routes`
   (если не пуст) → иначе full tunnel (заголовки `X-CSTP-Split-Include`
   не отправляются).
2. **«Пусто = наследовать»** — сознательно: в proto3/JSON пустой список
   неотличим от отсутствующего, отдельных состояний «пусто» и «не задано»
   не вводим. Пользователь с пустым `routes` на split-inbound наследует
   split инстанса — нас это устраивает.
3. Валидация — та же, что для inbound `routes` (IPv4 CIDR; статический IP
   пользователя, как и сейчас, обязан попадать в `subnet` — с `routes`
   это не связано).
4. Эмиссия — без изменений: каждая сеть отдельной строкой
   `X-CSTP-Split-Include` (client собирает маршруты по строкам).
5. Cookie/resume — ничего специального: политика выводится из пользователя,
   resume восстанавливает ту же сессию.
6. Камуфляж/лимиты/прочее — не затрагивается.

### Точки в коде (оценка — всё уже на месте)

* `config.proto` — `User.routes = 4` (+ регенерация `config.pb.go`).
* `infra/conf/openconnect.go` — `OpenConnectUserConfig.Routes`, прокинуть в
  `config.Users[i].Routes`.
* `control.go` `connectHeaders()` (сейчас: `hdrs["X-CSTP-Split-Include"] =
  append(..., s.conf.Routes...)`) — использовать `sess.user.Routes` с
  фолбэком на `s.conf.Routes`; `ocSession.user *User` уже хранится
  (session.go:22).
* `config.go` `validate()` — проверить пользовательские CIDR там же, где
  валидируются inbound.

## 3. Пример конфига после реализации

```json
"users": [
  { "name": "alex",        "password": "…" },
  { "name": "home-router", "password": "…", "ip": "172.16.10.115",
    "routes": ["172.16.10.0/24"] }
]
```

`alex` — полный туннель; `home-router` — только `172.16.10.0/24`
(адрес клиента в этой же подсети, так что и DNS `172.16.10.1`, и другие
клиенты пула достижимы; default route клиент оставляет себе).

## 4. Что в этом запросе НЕ требуется

* Именованные группы (`group:` + справочник) — не нужно, per-user достаточно.
* `X-CSTP-Split-Exclude` — пока не нужен (у ocserv использовался вариант
  «исключить всё», что эквивалентно split-include нужных сетей).
* Per-user/per-group лимиты скорости, `max-same-clients` — отдельные будущие
  запросы (см. `REQUEST-20260925-openconnect-camouflage-path.md`, раздел 4).
* IPv6 (`X-CSTP-IPv6-*`) — вне скоупа.

## 5. Приёмка

На одном inbound'е (любой порт) два пользователя: один с `routes`, другой
без. Ожидание: у первого в CONNECT-ответе есть `X-CSTP-Split-Include` с
заданными сетями и клиент **не** тянет default route; у второго заголовков
нет (полный туннель); cookie-resume сохраняет политику первого. Проверим
на тестовом инстансе gate (8443/8444) реальным openconnect 9.12 — доступ
есть, отчет пришлём.
