# Запрос: камуфляжный путь ocserv (`camouflage_secret`) в OpenConnect-inbound

**Дата:** 2026-09-25
**Статус:** БЛОКЕР для миграции прод-сервера networp gate (ocserv 1.4.0 → Xray-openconnect).
**Сборка, на которой воспроизведено:** `dist/Xray-openconnect-linux-amd64.zip`,
sha256 `d928c677d90c8ff376b1975425d900dc5652a7b63b196aaf90ef76ce4c0b9931`,
Xray 26.9.9 (go1.27.0 linux/amd64), inbound — коммит `b3c7d95e`.

---

## 1. Суть

Все клиенты прод-сервера ходят на URL с камуфляжным секретом:

```
https://gate.n3tw0rp.ru/?forzarussia
```

(ocserv: `camouflage = true`, `camouflage_secret = "forzarussia"`,
`camouflage_realm = "Restricted area"`; способ подключения задокументирован —
wiki `ocserv-camouflage-secret-forzarussia`). Это 20 клиентов: телефоны,
ноутбуки и 6 роутеров; URL зашит в их конфиги, менять вручную — дорого
и именно то, чего мы избегаем.

Inbound такой URL не принимает:

* `http.go:69` — `path` = `f[1]` из request-line, **целиком, включая query**
  (`/?forzarussia`);
* `control.go:114` — `dispatch()` сравнивает `req.path == "/"` или
  `"/index.html"`;

→ первый же запрос клиента (`POST /?forzarussia`) получает **404**,
аутентификация не начинается.

## 2. Воспроизведение (gate, loopback, prod не затронут)

```bash
# инстанс: inbound openconnect 127.0.0.1:1443, LE-сертификат gate.n3tw0rp.ru,
# тестовый пользователь (salt$sha256)
printf 'testpw' | openconnect "https://127.0.0.1:1443/?forzarussia" \
  --user=testuser --passwd-on-stdin --servercert=pin-sha256:jJjztZbtaur0JGzMm5svdBtkHq/i2kx0rbIJ1OQ/soc= \
  --script-tun --script=/bin/true
```

Результат:

```
POST https://127.0.0.1:1443/?forzarussia
Got HTTP response: HTTP/1.1 404 Not Found
Unexpected 404 result from server
GET https://127.0.0.1:1443/?forzarussia
Got HTTP response: HTTP/1.1 404 Not Found
Failed to complete authentication
```

**Контроль** — тот же тест без query-строки проходит весь путь:

```
POST https://127.0.0.1:1443/
CSTP connected. DPD 30, Keepalive 10
DTLS MTU reduced to 1342
Established DTLS connection (using GnuTLS). Ciphersuite (DTLS1.2)-(PSK)-(CHACHA20-POLY1305).
Configured as 10.66.0.1, with SSL connected and DTLS connected
```

Серверный лог: `auth OK user=testuser ip=10.66.0.1` → `CONNECT tunnel` →
`DTLS established` (то есть сам inbound рабочий, проблема только в пути).

## 3. Что просим

Поддержку семантики ocserv-камуфляжа в inbound'е:

1. Новая опция в `settings` (имя на ваше усмотрение, например `pathSecret`
   или `camouflageSecret`).
2. При заданной опции: первый запрос клиента должен содержать секрет
   (для совместимости с ocserv — в query: `GET|POST /?<secret>`); при
   отсутствии/неверном секрете отдавать заглушку (аналог «Restricted area»),
   а **не 404**; после успешного «рукопожатия» — обычный флоу
   (`/auth`, `CONNECT /CSCOSSLC/tunnel`), который клиент и так использует.
3. При незаданной опции поведение не менять (оставить текущее `/` и
   `/index.html`) — чтобы не ослаблять конфигурации, которым камуфляж не нужен.
4. Разбор request-target: сейчас query-строка входит в `path` и ломает
   сравнение — срезать query перед сравнением пути (нужно в любом случае).

Если решите сделать иначе — нам важнее **отсутствие ручной перенастройки
20 клиентов**, чем сам камуфляж; приемлемый минимум — принимать первый запрос
с любым путём (query игнорировать). Но ocserv-совместимая опция предпочтительнее:
камуфляж — часть защиты от сканеров, и inbound позиционируется как замена ocserv.

## 4. Что в этом релизе НЕ требуется (принятые потери, только к сведению)

Мигрируем «минимумом», эти расхождения осознанно принимаются на первый релиз
(перечислено, чтобы вы знали контекст и не считали это забытыми багами):

| # | Расхождение с ocserv | Влияние |
|---|---|---|
| 1 | Нет `X-CSTP-Split-Include/Exclude` | 6 роутеров группы `splitroute` (`no-route = 0.0.0.0/0` — весь трафик мимо туннеля) временно начнут гнать весь трафик через out-ноду. Кандидат в следующий релиз (`splitExclude` per user/group) |
| 2 | Нет per-user/group лимитов скорости (`tx/rx-data-per-sec`: 4 / 9.5 МБ/с) | Канал клиента ничем не ограничен |
| 3 | Нет `max-same-clients` на пользователя | Только общий `maxClients` |
| 4 | Нет rekey (`X-CSTP-Rekey-Time: 0`) | Долгоживущие сессии без rekey (у ocserv 48 ч) |
| 5 | IP-пул последовательный, не per-user | Адреса клиентов нестабильны; для роутеров зафиксируем через `User.ip` |
| 6 | Трафик клиент↔клиент внутри пула | `ocDevice.WritePacket` доставляет по dst в туннель (обратное направление), но исходящий флоу клиента A к IP клиента B уходит в `routing.Dispatcher` → не проверено, вероятно не работает. Использовалось для имён `*.vpn` в unbound |
| 7 | Мониторинг `occtl` | Заменим на стороне эксплуатации (stats API/ss) |

## 5. Приложение: окружение

* gate: Debian 13 (trixie), 1 vCPU, 962 МБ RAM, КВМ; ocserv 1.4.0 (пакет 1.3.0-2)
  слушает 443/tcp+udp, `ipv4-network = 172.16.10.0/24`, `dns = 172.16.10.1`
  (unbound на gate, адрес держит `lo-vpn-gw-addr.service` на lo),
  LE-сертификат `/etc/letsencrypt/live/gate.n3tw0rp.ru/{fullchain,privkey}.pem`.
* Выход клиентского трафика: gate → AmneziaWG (`wg-gate`, MTU 1420) → out-нода
  (38.135.53.115, MASQUERADE). В конфиге inbound'а выход планируется привязать
  через `streamSettings.sockopt.interface = "wg-gate"` (иначе трафик уйдёт
  с IP gate напрямую, минуя out-ноду).
* Тестовый инстанс для проверок: `/opt/xray-oc-test` на gate
  (`127.0.0.1:1443` tcp+udp, лог `/tmp/xray-oc-test.log`), клиент —
  `openconnect 9.12` (пакет, `/usr/sbin/openconnect`).
