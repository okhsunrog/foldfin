# Архитектура

## Целевые режимы

У Foldfin два пользовательских режима: локальный SOCKS5 TCP-прокси и device-level VPN через TUN. Есть рабочий proxy и первый Linux IP prototype между статическими endpoints. Режим и транспорт независимы: оба используют TLS/H2, сохраняя разные адаптеры трафика.

Linux prototype использует подготовленные TUN и CONNECT-IP поверх H2: DATAGRAM capsules переносят полные IP-пакеты, включая TCP/UDP/ICMP. Разрешены настроенные endpoint addresses и явные routed prefixes; address/route capsules проверяются по local configuration. Kernel forwarding проверен в обе стороны. Нужны последующие маршруты/DNS/MTU и полный lifecycle. H2 несёт TCP-over-TCP деградацию и head-of-line blocking: измерять их, затем оценивать H3/datagrams. Проектное решение и этапы проверки — [VPN-DESIGN.md](VPN-DESIGN.md).

Доступ в домашнюю или офисную LAN требует gateway/peer внутри этой сети или отдельного маршрута до неё, обратного маршрута/NAT и firewall policy. Франкфуртский exit сам по себе не даёт маршрута в сеть пользователя. Частные адреса на сервере сейчас запрещены по умолчанию; LAN-доступ следует ограничивать явно заданными подсетями.

## Реализованный proxy data plane

Один crate, общая библиотека и бинарники client/server. Один постоянный TLS/H2 carrier клиента, один стандартный HTTP/2 CONNECT на SOCKS TCP flow. Адрес в :authority, token в Authorization. TCP payload идёт в H2 DATA. H2 stream ID уже является flow ID: собственный mux сейчас лишний.

TLS завершается прямо на сервере. Внутреннего Noise нет. При добавлении внешнего TLS-терминатора меняется граница доверия и нужно отдельно решить необходимость E2E. Не предполагать, что любой reverse proxy/CDN поддерживает произвольный CONNECT.

| Файл | Роль |
| --- | --- |
| src/lib.rs | Shared helpers, public modules/features |
| src/client.rs | Client/TcpFlow/PreparedVpn/VpnTunnel, TLS/H2 lifecycle |
| src/adapters/socks.rs | SOCKS5 adapter over Client::open_tcp |
| src/server.rs | Server TLS/H2, static auth, CONNECT dispatch and task ownership |
| src/cli.rs, src/bin/*.rs | Process-only CLI, files/env/signals |
| tests/smoke.py | Local E2E, concurrent flows, FIN, bad token |
| src/vpn.rs | Platform-independent static peer and DATAGRAM/control capsules |
| src/packet.rs, src/adapters/tun.rs | Packet IO and Linux/Android owned FD adapters |
| tests/vpn_netns.py | Real dual-stack TUN acceptance in disposable namespaces |

Чтение TCP блоками 16 KiB; перед send_data резервируется H2 capacity. Receive window освобождается после write_all в TCP. EOF TCP превращается в END_STREAM, EOF H2 в shutdown TCP write-half. Направления работают независимо. Отдельные H2 streams не устраняют outer TCP head-of-line blocking.

Сервер: 128 соединений, 256 обработчиков, до 64 streams на H2 connection; клиент: 64 потока. Setup/DNS deadline 15 s. Входящий token проверяется до connect. Private/loopback адреса запрещены по умолчанию, DNS проверяется один раз и connect использует те же IP. Policy не является полной базой IANA специальных диапазонов. Idle timeout отсутствует.

## План модулей

Оставить один crate: отдельные модули TCP flows, IP session, CONNECT-IP codec,
H2 carrier, TUN adapter и platform setup. Выделять crates при реальной потребности.
Будущий carrier должен поддерживать TCP flows и packet tunnels с явными
свойствами доставки, а не только `open_tcp`. H2 capsules надёжны и упорядочены;
H3 datagrams могут теряться. Не обещать QUIC-like UDP semantics поверх TCP.
Конкретный общий trait определить после рабочего H2 prototype и второго carrier.
Session-crypto нужен только при подтверждённой E2E задаче.

## Мимикрия: измеренный ClientHello

По умолчанию используется rustls. Feature `chrome-tls` и флаг `--chrome-tls` включают BoringSSL с профилем установленного Chrome 154.0.8037.92. Сравнение 30 Chrome и 5 Foldfin ClientHello показало совпадение нормализованных полей; captures и comparison.json лежат в `captures/chrome-154`. Проверка сертификата и имени включена. Идентификаторы trust anchors — снимок рекламы Chrome, не замена системного root store.

Для профиля Chrome 154 измеренные SETTINGS (header table 65536, push off, stream window 6291456, header list 262144) и connection WINDOW_UPDATE (15663105) совпадают с Chrome. Снимки находятся в `captures/http2-chrome-154`; запуск локального сравнения — `uv run python tests/http2_capture.py`. Запросы различаются по назначению: Chrome делает GET с `:scheme`/`:path`, Foldfin — CONNECT с `:authority` и bearer Authorization; Foldfin оставляет поток открытым. У Chrome HEADERS содержит priority metadata, у h2 crate такой публичной настройки нет. H2-only сервер и HTML-заглушка не заменяют настоящий website frontend. HTTP headers/settings зашифрованы внутри TLS; дальнейшие измерения должны учитывать наблюдателя и traffic statistics. Новый VPN wire profile требует повторной проверки. Авторизация и защитные лимиты отложены. Signed profiles возможны позже, со строгой схемой, anti-rollback и без удалённого executable code.
