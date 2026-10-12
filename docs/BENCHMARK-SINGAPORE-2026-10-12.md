# Foldfin: физический Сингапур — 2026-10-12

Новая реализация развёрнута на Сингапуре. Оба VPN-профиля прошли routed IPv4
acceptance через физический Ethernet. В двух замерах download получился
**98–99 Мбит/с у Rustls, 102–104 у Chrome, 108–109 у прямого TCP**.
Upload существенно колеблется, в том числе у прямого TCP. Локальные 700 Мбит/с
на текущем WAN не воспроизведены.

Продолжать проект имеет смысл ради готового VPN с корректными routes, DNS,
setup/rollback и обработкой обрывов. Дальнейшее увеличение H2 windows само
по себе не выглядит главным приоритетом. Текущий download overhead относительно
прямого TCP составляет около 9% у Rustls и 5% у Chrome; небольшую разницу
профилей нельзя считать устойчивым преимуществом по двум последовательным runs.
Необнаружимость ТСПУ и полная эквивалентность браузеру здесь не проверялись.

## Что реализовано и развёрнуто

- `scripts/network_policy.py`: временная настройка TUN queue и TCP send
  autotuning только в явно названном isolated namespace. Host namespace
  запрещён. Старые значения восстанавливаются после выхода, ошибки и SIGTERM;
  чужие изменения или подмена namespace/device вызывают ошибку rollback,
  а не перезаписываются.
- Client test policy: queue 10000 вместо 500, TCP send-autotune max 32 МиБ
  вместо 4 МиБ. Сохраняются исходные minimum/default TCP значения.
  Socket fixed-buffer flags, default routes и DNS helper не меняет.
- Singapore opt-in static-peer CONNECT-IP: сервер `198.18.78.1`, peer
  `198.18.78.2`, allowed routed LAN `198.19.78.0/30`. Нет full tunnel или internet
  NAT. Proxy продолжает работать на прежнем TLS/H2 listener TCP/8445.
- Managed server TUN queue 10000. Root setup helper помечает свой интерфейс
  ifindex/alias и отказывается переиспользовать или удалять чужой TUN.
  Data-plane процесс остаётся непривилегированным.
- Исправлена адресация quick-update в cloud-forge: playbook и guard теперь
  выбирают Singapore. До правки Foldfin wrapper ограничивал Singapore, но
  infrastructure playbook всё ещё выбирал Frankfurt.
- `tests/vpn_physical.py` и remote helper выполняют routed acceptance,
  transfer-integrity benchmark, captures и очистку. Wrapper `test-vpn.sh`
  снова доступен; старые Frankfurt/relay/Floppa remote команды остаются disabled.

Серверные global TCP sysctls не менялись: максимум `tcp_wmem` остаётся 4 МиБ.
Поэтому этот опыт не повторяет полностью tuned local стенд, где по 32 МиБ
задавалось обоим namespaces. Policy helper уже применим к отдельному server
namespace, но production service пока использует host network namespace.
Перенос сервиса в отдельную сеть или отдельная политика socket buffers требует
своего проверяемого этапа, с сохранением proxy firewall и маршрутизации.

## Метод и путь

```text
Foldfin CLI / TCP workload
  → disposable namespace, TUN MTU 1280
  → veth + exact source routing/NAT
  → enp0s13f0u1u5, 10.77.77.230
  → gateway 10.77.77.1
  → Singapore 66.179.31.173:8445
```

Ethernet по-прежнему negotiated 1000 Mb/s full duplex. VPS capture на `eth0`
видит внешний source `128.0.128.51`; source-port marker сопоставлен с удерживаемым
сокетом namespace. Изолированный source rule использовал table 42810 в итоговом
прогоне; значение хранится в summary.
Физический и server captures содержат соответствующие SYN/SYN-ACK.
Administration SSH имеет свой обычный маршрут и не переносит тестовый carrier.

Один общий TCP workload: 64 КиБ generated blocks, SHA-256/count verification,
TCP_NODELAY на endpoint-сокетах, independent half-close. Sender работает
12 секунд плюс 2 секунды прогрева; receiver goodput считается после прогрева
до последнего блока, включая возможное дренирование накопленной очереди.
По два повтора upload/download, один inner flow за раз. Direct использует
свежий TCP socket для каждого transfer; VPN повторно использует H2 carrier
внутри профиля. Режимы идут последовательными блоками, поэтому изменение
условий канала и startup способны влиять на сравнение.

Endpoint на самом VPS, без дополнительного TCP relay. Временно открытый
TCP/31992 ограничен observed physical source, а для TUN — точным peer/interface.
Private/public-local destination protection proxy не ослаблялась.
Функциональный LAN responder находится в отдельном VPS namespace и проверяет
исходные source addresses в обе стороны.

TCP samples снимаются локально и через SSH: между завершёнными samples
выдерживаются 2 секунды; сами команды добавляют время и некоторую нагрузку.
Это короткий path/workload benchmark, не CPU ceiling, не длительный stress test
и не точная WAN packet-loss модель. Local Floppa actor не участвует.

## Результаты

Мбит/с десятичные. Все 12 transfers завершились с совпадающим SHA-256 и числом байт.

| Режим | Upload 1 | Upload 2 | Download 1 | Download 2 |
|---|---:|---:|---:|---:|
| Direct TCP | 110,39 | 37,93 | 108,19 | 108,79 |
| Foldfin Rustls/TUN | 41,48 | 33,59 | 98,67 | 98,35 |
| Foldfin Chrome/TUN | 27,53 | 47,06 | 101,54 | 103,76 |

Средний download: native 108,49, Rustls 98,51, Chrome 102,65 Мбит/с.
Upload ranges показывать полезнее среднего: native менялся почти втрое.
Ранний неполный прогон дал native 33–44 upload / 104 download, также
подтверждая изменчивость. По таким runs нельзя доказать предел маршрута,
вину конкретного провайдера или преимущество одного TLS backend.

## TCP и локальные потери

В итоговых link snapshots у client и server TUN **нулевые TX/RX drops**.
Прежнее переполнение маленькой TUN queue в этом run не воспроизвелось.
Outer RTT преимущественно около 202–206 мс.

Во время Rustls upload клиентский CUBIC показывает cwnd порядка 763–836 segments,
delivery rate около 43–47 Мбит/с, retransmissions и reordering. Поэтому нельзя
объяснить этот upload исключительно лимитом серверного CPU или фиксированной
скоростью кодирования протокола. При этом точное место появления reordering
и причина изменения congestion window данным стендом не установлены.

Во время download сервер использует BBR, send-memory limit 4 МиБ. Samples
показывают заполнение send queue примерно до 2,8–3,0 МБ и `sndbuf_limited`
примерно 10–15% accumulated busy time. Socket-buffer ограничение вносит вклад;
это не доказательство, что одно его увеличение гарантирует 700 Мбит/с по WAN.
Полученные data rates, direct baseline и локальный стенд описывают разные условия.
Точные CPU percentages на WAN здесь не измерялись.

## Acceptance и неуспешные подготовительные runs

Оба профиля прошли IPv4 ICMP к server peer и routed LAN, четыре параллельных
TCP/FIN transfer, UDP и тестовый DNS; затем такой же probe инициирован с VPS LAN
к клиенту. Source addresses сохранены. Managed remote IPv6 не настроен;
предыдущая local routed dual-stack acceptance остаётся отдельным подтверждением.
Оба proxy-профиля также прошли внешние HTTPS, DNS, auth/private-destination checks
через Ethernet: `captures/proxy-deployed-20261012/`.

Подготовительные failures не замаскированы successful run:

- `vpn-physical-20261012-accept`: неоднозначное сравнение изменяемых строк `ss`
  при параллельном proxy тесте. Исправлено сопоставлением marker source port.
- `accept2`/`accept3`: remote reverse probe не запускался из-за попытки `uv`
  от непривилегированного пользователя открыть `/root/uv.toml`. Исправлены
  рабочий каталог и отключено чтение user config; это не protocol failure.
- `vpn-physical-20261012-wan`: native transfers завершились, но proxy transfer
  к собственному public IP VPS был корректно отвергнут LOCAL guard. Proxy
  throughput к этому endpoint исключён; исключение в policy не добавлялось.

Эти runs сохраняются как неполные; итоговая таблица относится только к `wan2`.

## Проверки, artifacts и очистка

Пять network-policy acceptance tests прошли: rollback при ошибке дочерней работы,
частично неуспешный setup, сохранение чужого изменения, отказ host namespace,
SIGTERM с остановкой child и восстановлением значений.
TUN setup helper прошёл isolated up/reentry/down и отказ трогать чужой TUN.
Musl server и native Chrome-enabled CLI release собраны; Rust source в этом
этапе не менялся, результаты предыдущих default/Chrome checks/tests сохраняются.

Raw итогового run: `captures/vpn-physical-20261012-wan2/`, включая summary,
per-transfer JSON/TCP samples, local/server packet metadata и acceptance logs.
Deploy logs: `benchmarks/2026-10-12-wan/deploy.log`.
Quick-update также проверен: Singapore `ok=8 changed=0 failed=0`,
`benchmarks/2026-10-12-wan/quick-update.log`; неизменный сервер не перезапускался.
Client SHA-256:
`1b95e9efaa96451b086f2b01dc5d21a50bf6ad17927ed77a3fbd0b4dc24dcfc3`.
Deployed musl server SHA-256:
`2d8610bc00cab6fac76a7dce9e964e3dafbcefe3e46c35c5dc3a6049bb92621e`.

Итоговый cleanup прошёл: временные firewall rules, routing rule/table, namespaces,
veths, responder/capture units, benchmark listener и remote script directory
удалены. Namespace policy восстановлена до удаления client namespace.
Host default routes и TCP sysctls до/после совпадают; server TCP globals тоже.
Служба Foldfin остаётся active, managed server TUN и его явный peer route сохранены.

Далее приоритет — usable VPN lifecycle и диагностика стабильности upload.
Повторное изменение H2 windows без новых причин и измерений не требуется.
См. [локальную диагностику](BENCHMARK-TCP-2026-10-12.md) и
[план](PERFORMANCE-PLAN.md).
