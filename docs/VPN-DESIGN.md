# VPN: рекомендуемая архитектура

Статус: архитектура целевого VPN; первая часть реализована как Linux static-peer
prototype с DATAGRAM/configuration capsules и routed prefixes. OS addresses/routes пока готовятся отдельно.
Рабочий SOCKS5 TCP-прокси сохранён. Этот документ заменяет прежнее
предположение, что VPN обязательно требует другого транспорта или tun2socks.

## Режим и транспорт — независимые настройки

Один клиент и сервер, два режима работы:

| Режим | Вход клиента | Передача | Выход сервера |
| --- | --- | --- | --- |
| Proxy | SOCKS5 | HTTP CONNECT, поток на TCP-соединение | TCP socket |
| VPN | TUN / Android VpnService | CONNECT-IP, полные IP-пакеты | TUN и маршрутизация ядра |

Первый транспорт обоих режимов — существующий TLS/HTTP2. Клиент сохраняет
выбор rustls / Chrome TLS profile. Позже HTTP/3 может предоставлять TCP-потоки
и IP-туннели через тот же продуктовый интерфейс. Выбор VPN не должен автоматически
означать выбор QUIC. Возможность одновременного SOCKS и TUN оставить в архитектуре;
в прототипе достаточно отдельного запуска каждого режима.

Full tunnel, split tunnel, internet exit, доступ к LAN, связь между клиентами
и site-to-site — конфигурации маршрутизации. Не нужны отдельные протоколы для
каждой топологии. В первой реализации проверить простую remote-access топологию,
сохранив модель адресов и подсетей для остальных.

## Настоящий L3 data plane

```text
приложения → IP stack ядра → client TUN → CONNECT-IP → server TUN
                                                        ↓
                                               forwarding / routing
                                                        ↓
                                           интернет / LAN / другой peer
```

VPN переносит IP-пакеты; TCP остаётся между исходными конечными узлами.
UDP и ICMP не требуют реализации отдельных прокси. Не вводить userspace TCP/IP
stack как обязательную основу: tun2socks превращает TCP в новые серверные
соединения и усложняет обратные подключения, UDP и ICMP. Отдельный такой адаптер
можно рассмотреть позже при конкретной потребности.

TUN — L3 интерфейс. Ethernet bridging, broadcast discovery и автоматическое
обнаружение устройств через mDNS не появляются просто от подключения VPN.
Для удалённой LAN нужен подключённый gateway с маршрутом в неё и обратный
маршрут; NAT допустим как явный обход отсутствующего обратного маршрута.
Обычный internet exit может использовать NAT. Между VPN-подсетями предпочитать
маршрутизацию с сохранением адресов.

## Стандартный wire protocol

Использовать [CONNECT-IP / RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html)
и [HTTP Datagrams / Capsule Protocol, RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297).
Не изобретать собственный packet mux или упаковку TCP/UDP отдельно.

Для H2 нужны Extended CONNECT (`:protocol=connect-ip`), абсолютный URL
туннеля с `:scheme`, `:authority`, `:path`, согласование Capsule Protocol
и проверка поддержки Extended CONNECT сервером. Используемый h2 crate уже
предоставляет `h2::ext::Protocol`, `enable_connect_protocol()` и
`is_extended_connect_protocol_enabled()`; DATAGRAM codec реализован в `src/vpn.rs`.
Сервер должен отдельно распознавать VPN-запрос, до proxy destination lookup.

IP-пакеты идут в DATAGRAM capsules с context ID 0. Адреса и доступные маршруты
передаются стандартными ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT.
OS addresses/routes пока настроены out-of-band. Assignments проверяются по подготовленным
адресам, peer advertisements — по административному списку допустимых prefixes.
Повторные advertisements заменяют список; protocol-scoped routes пока не поддержаны.
DNS и локальная route policy задаются конфигурацией клиента: эти capsules
не заменяют DNS provisioning и не должны произвольно менять настройки хоста.

В H2 capsules передаются внутри надёжного упорядоченного DATA stream.
Один IP-туннель — один bidirectional HTTP stream; пакет не равен H2 DATA frame.
Нужен incremental parser: частичные varints, разбиение и объединение capsules,
неизвестные типы, некорректные длины, END_STREAM/reset. Размеры и очереди ограничены;
не выделять память по непроверенной длине из сети. Это корректность codec и
backpressure, а не новые лимиты соединений по публичному IP.

HTTP/3 сможет передавать пакеты через QUIC datagrams, оставляя управление
в надёжном HTTP stream. Интерфейс packet tunnel должен явно сообщать свойства
доставки: H2 reliable/ordered, H3 datagrams могут теряться. Не обещать
ненадёжную доставку поверх H2 или безусловную надёжность datagrams.

Для соответствия RFC отдельно проверить адресную ownership, маршруты,
TTL/Hop Limit, ICMP errors и MTU, включая IPv6. Учесть действия ядра, чтобы
не получить двойное уменьшение TTL. Частичный prototype не объявлять
полностью MASQUE-совместимым до protocol/interoperability проверки.

## Компромисс H2

H2/TCP подходит для первого рабочего VPN и сохраняет существующую HTTPS основу.
TCP-over-TCP и общий head-of-line blocking остаются: потеря внешнего пакета
задерживает и внутренний TCP, и UDP. Это ограничение производительности,
а не отсутствие полноценной IP-связности. Как практический пример,
[OpenConnect](https://www.infradead.org/openconnect/technical.html) использует
TCP/TLS канал и предпочитает дополнительный UDP/DTLS канал, когда он доступен.

Измерять throughput и latency при потерях/задержке внешнего канала, смешанном
TCP/UDP и нескольких flows. Результат определит приоритет H3; не обещать
производительность WireGuard. H3 меняет TLS/QUIC fingerprint и требует отдельных
Chrome captures. Измеренный TLS/H2 профиль не переносится на него автоматически.

HTTP-запросы и H2 SETTINGS внутри TLS зашифрованы для пассивного наблюдателя.
CONNECT-IP является настоящим HTTP, но не обычной браузерной загрузкой страниц.
Не считать добавление User-Agent доказательством скрытности; отдельно оценивать
ClientHello, сервер, размеры и временные характеристики трафика.

## Сессия и жизненный цикл

Логический peer владеет виртуальными IPv4/IPv6 адресами и разрешёнными префиксами,
независимо от домашнего или мобильного публичного IP. Транспортное соединение
может пересоздаваться. При сохранении адресов/маршрутов краткий обрыв иногда
переживают внутренние TCP-соединения; это зависит от их deadlines и состояния
NAT. Гарантированное восстановление не обещать. Proxy TCP sockets при обрыве
carrier теряются, как сейчас.

Текущий общий bearer token не является уникальной идентичностью устройства.
Авторизацию сейчас не переделывать. Для локального прототипа — один явно
настроенный peer со статическими адресами; перед поддержкой нескольких peers
отдельно определить binding credential → peer → адреса/префиксы и их конфликты.
Адрес пакета обязан принадлежать его сессии. Не привязывать peer к публичному IP.

Серверу достаточно shared TUN и таблицы destination prefix → peer session,
с запретом конфликтующих назначений. Начать с одного peer; сохранять такой
путь расширения. Ядро выполняет forwarding, routing и при необходимости NAT.

Настройка клиента включает TUN, MTU, routes, DNS и исключающий маршрут до VPN
endpoint через исходное соединение. Хранить предыдущие настройки и владение
изменениями; очищать только собственные routes/DNS. При смене сети обновлять
endpoint route. Отдельно определить fail-open/fail-closed поведение и DNS/IPv6
утечки до включения full tunnel по умолчанию. Android adapter передаёт TUN FD
из VpnService тому же packet core; control socket требует bypass через protect().

Оставить один crate с модулями packet codec, IP session, H2 carrier, TUN adapter
и platform network setup. Shared config/TLS не означает одинаковую обработку
TCP flows и IP packets. Не строить большой trait/workspace до второго carrier.

## Интеграция с playbooks

Proxy-only systemd service запрещает устройства и capabilities, разрешает
AF_INET и AF_UNIX. Во Франкфурте opt-in VPN уже использует root setup oneshot,
user-owned persistent TUN и DeviceAllow=/dev/net/tun; data-plane процесс без
capabilities. Managed forwarding пока IPv4. Для дальнейшей поддержки предпочитать подготовку интерфейса,
routes и forwarding отдельным setup helper / playbook, с минимальными правами
data-plane процесса; явно выбрать передачу FD или доступ к подготовленному TUN.
Не запускать весь сервер от root ради сетевой настройки.

Текущая OUTPUT policy по UID обслуживает proxy sockets. VPN forwarding проходит
через FORWARD: нужны отдельные VPN chains, allowed prefixes и NAT. Proxy private
destination policy и VPN route policy различаются; глобальный allow-private
не заменяет конфигурацию LAN. Изменения в инфраструктуре делать opt-in для VPN.

## Этапы и состояние

1. Локальные network namespaces: client/server TUN, один static peer,
   H2 CONNECT-IP и только тестовые IPv4/IPv6 подсети — реализовано и проверено.
   Не менять default route хоста.
2. Проверить TCP, UDP/DNS, ICMP и соединение, инициированное с удалённой стороны,
   подтверждая packet routing. Добавить проверки capsule parser, MTU/errors,
   backpressure, carrier loss и очистки interfaces/routes. Проверены также
   routed LAN, обратные подключения и ICMP MTU errors; полный TTL/interop audit впереди.
3. Измерить канал под loss/delay с netem; сопоставить IP routing и proxy baseline.
4. Франкфурт (`europe`): opt-in VPN рядом с proxy, отдельные тестовые префиксы,
   forwarding и acceptance script — реализовано и проверено по IPv4 без NAT.
   NAT для internet exit ещё предстоит. Другие VPS не трогать.
5. Затем full/split routes и DNS lifecycle, reconnect, несколько peers и LAN gateway;
   Android adapter и H3 — последующие отдельные этапы. Работоспособный Linux
   prototype ещё не означает завершённый general-purpose VPN.
