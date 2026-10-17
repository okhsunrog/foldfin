# Архитектура Foldfin

Актуальное состояние: 2026-10-17. История реализации и проверок находится в
[IMPLEMENTATION.md](IMPLEMENTATION.md); серверные пробелы и порядок завершения —
в [SERVER-REVIEW.md](SERVER-REVIEW.md).

## Режим и транспорт

| Режим | Вход | H2 | H3 | Выход сервера |
| --- | --- | --- | --- | --- |
| TCP proxy | SOCKS5 или library API | CONNECT/DATA | CONNECT/QUIC stream | TCP socket |
| IP VPN | PacketDevice, TUN | CONNECT-IP capsules | CONNECT-IP datagrams + control stream | Общий TUN/router |

IP VPN переносит IPv4/IPv6, включая TCP, UDP и ICMP. CONNECT-UDP для отдельного
UDP proxy пока не реализован. H2 сохраняет TCP head-of-line blocking и эффекты
TCP-over-TCP. H3 datagrams могут теряться и требуют достаточного path MTU.

TLS завершается на сервере Foldfin. Используются rustls и стандартные механизмы
HTTP; собственного mux, Noise и фрагментации нет. Chromium/BoringSSL удалён.
Наблюдавшееся совпадение старых ClientHello не относится к нынешнему wire profile
и не доказывает неотличимость от браузера.

## Владение ресурсами

- `client` / `h3_client`: один carrier, TCP flows и CONNECT-IP negotiation.
- `session`: PacketDevice живёт дольше carrier; host явно запускает recovery.
- `server`: один общий authorizer, admission registry и лимиты на H2/H3 listeners.
- `authorization`: lease устройства; expiry/revoke закрывает его активные потоки.
- `admission`: подготовка и commit поколения VPN-сессии одного peer.
- `router`: единственный владелец серверного PacketDevice, отдельные ограниченные
  очереди peer, проверка source prefixes и маршрутизация ответных пакетов.
- `vpn` / `vpn::control`: IP policy, capsules, assignments и route advertisements.
- `adapters`: SOCKS и TUN/owned FD. `cli`: runtime, env, файлы и process signals.

Host готовит TLS, listeners, устройства, маршруты и firewall. Перед освобождением
платформенных ресурсов он дожидается остановки listeners и router. Сбой общего
TUN должен завершать node, а не оставлять работающий порт с неработающим VPN.

## Граница с Floppa

API Floppa проверяет аккаунт, подписку, устройство, quota и регион; сохраняет digest
отдельного VPN token и версию прав. Серверный host синхронизирует эти права,
обновляет leases и сертификат. Database queries не находятся в пути IP-пакетов.
Эта серверная цепочка пока не завершена; существующий DeviceRegistry проверен
в интеграционных тестах.

Клиент Floppa владеет actor lifecycle, route/DNS rollback и underlay. На Linux
outer sockets используют общий SO_MARK, без ручного endpoint host route.
На Android protect/bind привязаны к конкретному VpnService; системный lockdown
принадлежит Android. Смена сети не даёт протоколу права менять default route.

## Ограничения доверия

Source-prefix validation не заменяет firewall: default destination route включает
private ranges и других клиентов. Internet exit, приватные сети и site-to-site
требуют явных разрешений, forwarding и обратных маршрутов/NAT.

Carrier probe подтверждает только связь с сервером. Он не доказывает forwarding,
DNS или доступность интернета. Восстановление carrier не обещает сохранение всех
ранее открытых внутренних TCP-потоков.
