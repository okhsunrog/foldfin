# Foldfin: диагностика TCP/TUN — 2026-10-12

При локальном моделировании RTT 200 мс Foldfin Rustls/TUN передал около
**700 Мбит/с в обе стороны** в общем TCP workload. Без добавленной задержки
реальный CLI/TUN дал около **3,6 Гбит/с**. Это результаты локального стенда:
скорость до Сингапура новой реализацией здесь не измерялась.

Предыдущие 33–64 Мбит/с нельзя считать пределом протокола или доказательством
плохого внешнего маршрута. Диагностика нашла потери в локальном TUN driver и
ограничение TCP send autotuning. Значительная часть прироста получена настройкой
тестовой сети; вклад изменений Rust-кода отдельно от неё существенно меньше
и зависит от workload. [Первый этап с окнами H2](BENCHMARK-2026-10-12.md)
сохраняет исходные результаты.

## Метод и границы

Два полностью изолированных network namespaces, veth, настоящий TUN MTU 1280,
Foldfin release CLI, TLS/H2 и Core Ultra 5 125H. Нет host-facing veth, выхода
в интернет, существующего VPN хоста или дополнительного TCP relay.
Upload означает client → server, download — server → client. Мбит/с десятичные.

`tests/bench_local.py --telemetry` записывает каждые 0,5 с `ss -tinm`, TCP packet
metadata без payload, статистику links/qdiscs и `nstat`. Счётчики после прогона
накопительные: для отдельных направлений нужно брать разницу снимков.
Первичные эксперименты сохраняют sender-egress netem старого стенда.
Последующие используют IFB и receiver-ingress netem, по 100 мс на каждом конце.
Это соответствует [рекомендации tc-netem для TCP](https://man7.org/linux/man-pages/man8/tc-netem.8.html):
sender-side задержка может взаимодействовать с TCP Small Queues.
Смена placement сама по себе не устранила ограничение direct TCP.

Контрольные iperf-прогоны: 20 измеряемых секунд после 2 секунд прогрева,
по одному повтору в каждом каталоге. Общий direct/proxy/TUN workload:
12 секунд после 2 секунд прогрева, блоки 64 КиБ с SHA-256 и проверкой полного
получения, одинаковый TCP_NODELAY на endpoint-сокетах. Его Python/checksum
расходы не позволяют считать скорость пределом CPU. Режимы идут блоками,
а не в случайном порядке. Отдельные результаты не заменяют длительный stress test.

## Подтверждённые локальные причины

**1. Переполнение TUN driver.** При `txqueuelen=500` исходная реализация
показала 36,3/42,5 Мбит/с. После upload счётчик TX dropped клиентского TUN
составил 5346, серверного — 223, при нулевых qdisc drops. Повторные передачи
внутреннего TCP происходили при стабильном внешнем RTT около 200 мс и без
внешних retransmissions в первичном capture. Поэтому отсутствие qdisc drops
в отчёте первого этапа не означало отсутствия потерь в TUN driver.

На том же бинарнике увеличение только тестового TUN queue до 5000 дало
107,1/136,5 Мбит/с. Это сильное свидетельство локального ограничения.
Очередь 10000 вместе с tuned TCP позволила убрать TUN drops и внутренние
retransmissions в выбранных прогонах. Значение не стало настройкой хоста или
новым обязательным production default: platform setup/rollback ещё предстоит.

**2. TCP send autotuning.** При максимуме `tcp_wmem` 4 МиБ native TCP
упирался примерно в 164–165 Мбит/с. После изменения максимума до 32 МиБ
**только в двух тестовых namespaces** native достиг 959–996 Мбит/с.
Телеметрия показывает соответствующие socket send-memory limits.
Для 1 Гбит/с при 200 мс требуется примерно 25 МБ данных в полёте;
реальные socket-memory расходы и congestion window учитываются отдельно.
Глобальные `tcp_wmem`, `core.wmem_max`, routes и DNS хоста не менялись.

**3. Очерёдность polling в packet engine.** Обработка большого входящего
burst могла надолго оставлять противоположное направление без чтения TUN.
Это усиливало локальные потери и задержку ACK. Добавлены ограниченная очередь
исходящих пакетов и добровольная передача исполнения после 32 записанных
пакетов либо четырёх H2 DATA frames. Изменение не устраняет TCP-over-TCP/HOL.
На малой TUN queue потери всё ещё возможны: Rust-код не создаёт backpressure
в kernel TUN, который этой возможности не поддерживает.

В текущем upstream Linux есть опциональный `IFF_BACKPRESSURE`:
[флаг](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/if_tun.h)
и [обработка в tun_net_xmit](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/tun.c).
Он останавливает transmit queue при заполнении ring, позволяя qdisc удерживать
пакеты. На установленном ядре `7.2.8-5-okhsunrog` read-only `TUNGETFEATURES`
вернул `0x7173`, без бита `0x80`. Эта возможность не применялась и не проверена
на данном хосте; смена ядра не выполнялась. Upstream master не является
доказательством реализации установленного бинарного ядра.

## Изменения packet engine

- 64 исходящих batches, каждый до 32 IP packets и менее `CHUNK + MTU + 8`
  байт. Queued payload ограничен примерно 1,1 МиБ на VPN session; metadata,
  рабочие buffers, H2/TLS/socket память учитываются отдельно.
- Чтение packet device и отправка H2 выполняются двумя borrowed futures
  внутри одной session, без detached task. Заполнение очереди останавливает
  дальнейшее чтение; отмена session уничтожает оба futures и endpoints.
- Перед сериализацией batch повторно проверяются текущие assignments/routes.
  Пакеты, ставшие недопустимыми после route withdrawal, отбрасываются.
  Control replies имеют приоритет перед следующим queued batch.
- Capsule framing не менялся. Сериализация batch не требует отдельного
  временного serialized buffer для каждого пакета.

Эксперимент с 512 batches увеличивал queued payload примерно до 8,7 МиБ,
но не дал устойчивого преимущества. Размер 64 выбран для меньшего ограниченного
расхода памяти. Public API, proxy path, authorization и measured Chrome
initial SETTINGS не менялись.

## Контрольные iperf сравнения, RTT 200 мс

Все значения upload/download, Мбит/с. Потери netem не заданы.

| Бинарник и параметры | Native TCP | Rustls/TUN | Raw каталог |
|---|---:|---:|---|
| Исходный, TUN 500, wmem 4 МиБ, egress | 163,2 / 164,5 | 36,3 / 42,5 | `queue500` |
| Исходный, TUN 5000, wmem 4 МиБ, egress | 163,3 / 164,3 | 107,1 / 136,5 | `queue5000` |
| Исходный, TUN 500, wmem 4 МиБ, ingress | 164,6 / 164,3 | 48,4 / 48,1 | `before-ingress` |
| Pump 512 + fairness, TUN 500, wmem 4 МиБ, ingress | 165,6 / 164,6 | 94,8 / 100,1 | `fair32-ingress` |
| Исходный, TUN 10000, wmem 32 МиБ, ingress | 978,7 / 975,5 | 551,4 / 705,3 | `before-wmem32` |
| Pump 512 + fairness, те же параметры | 985,0 / 980,3 | 701,8 / 708,2 | `fair32-wmem32` |
| Повтор Pump 512, те же параметры | 979,0 / 959,2 | 346,0 / 705,9 | `pump512-repeat` |
| Финальный Pump 64 + fairness, те же параметры | 972,4 / 995,7 | 700,8 / 530,0 | `pump64-wmem32` |
| Повтор финального Pump 64 | 973,7 / 985,6 | 673,1 / 530,0 | `pump64-repeat` |

Нельзя приписать рост 36 → 700 Мбит/с одной правке кода: менялись и настройки
тестовой сети. Даже на исходном коде tuned сеть дала 551/705 Мбит/с.
Большая очередь не обеспечивает стабильно более высокую скорость.
При некоторых прогонах телеметрия outer TCP показывает reordering и меньший
congestion window; это возможное объяснение разброса, а не установленная
единственная причина. В финальных двух loss-free iperf runs TUN driver drops
и retransmissions внутреннего TCP равны нулю.

## Один workload для proxy и VPN

Финальная реализация с 64 batches, receiver-ingress RTT 200 мс,
TUN queue 10000, namespace-only tcp_wmem max 32 МиБ, без заданных потерь.
Каждый transfer прошёл SHA-256 и проверку числа байт.

| Режим | Upload, Мбит/с | Download, Мбит/с |
|---|---:|---:|
| Direct TCP | 835,1 | 838,9 |
| SOCKS Rustls | 645,7 | 849,3 |
| SOCKS Chrome | 667,3 | 176,3 |
| TUN Rustls | 696,4 | 699,8 |
| TUN Chrome | 666,3 | 174,5 |

Chrome download ограничивается сохранённым клиентским H2 receive profile:
6 МиБ stream window, 15 МиБ connection window. Это согласуется с близкими
download результатами proxy и TUN. Формула window/RTT — только оценка масштаба,
а не точный прогноз goodput. Upload использует увеличенные окна сервера.
Profile не изменялся ради скорости. Чуть более высокий SOCKS download, чем
direct, в одном последовательном запуске не доказывает ускорение сети туннелем.

Raw: `benchmarks/2026-10-12-tcp/stream-final/`.
Ранний каталог `streams/` относится к exploratory workload до согласованного
TCP_NODELAY и не используется для этой таблицы.

## Малая задержка

Финальный Pump 64, default TUN queue 500 и wmem 4 МиБ, без netem,
8 измеряемых секунд после 2 секунд прогрева:

| Профиль | Upload, Гбит/с | Download, Гбит/с |
|---|---:|---:|
| Rustls/TUN | 3,609 | 3,593 |
| Chrome/TUN | 3,643 | 3,600 |

Native veth дал 60–77 Гбит/с. На таком burst load внутренний TCP всё ещё делает
retransmissions. Это короткая проверка локальной обработки, не длительный
без потерь stress test и не предел CPU VPS. Raw: `zero-final/`.

## Проверка под потерями

Финальный бинарник, receiver-ingress RTT 200 мс, netem loss 1% на каждом
внешнем направлении, TUN queue 10000 и wmem 32 МиБ, 12 секунд после прогрева.
Native TCP дал всего 1,55/2,01 Мбит/с. Rustls/TUN upload завершился ошибкой
iperf `unable to receive results`, до сопоставимого receiver result;
download не запускался. Это **неуспешный benchmark**, а не нулевая измеренная
скорость и не доказательство превосходства или регрессии относительно native.
Такой же класс iperf-control ошибки встречался в первом этапе. Точная причина
этого повторения не установлена; timestamps и packet/TCP metadata сохранены
в `loss-final/`, cleanup прошёл.

Внешний TLS/TCP carrier оставался ESTABLISHED, без ошибок процесса, с
congestion window примерно 16–20 segments в поздних samples и retransmissions.
При заполнении TCP send queue примерно до 1,6 МБ передача продолжалась медленно;
TUN driver drops оставались нулевыми. Это отличает данный failure от прежнего
переполнения TUN, но не объясняет окончательно сбой iperf control exchange.

Loss применяется к queued SKBs при обычных veth offloads, поэтому это не точная
модель 1% Ethernet-frame loss на WAN. Увеличение buffers не исправляет TCP при
потерях. Routed acceptance с меньшей задержкой и loss проверяет функциональную
корректность, но не заменяет этот неуспешный high-RTT performance test.
Стабильная скорость нового варианта на плохом маршруте не подтверждена.

## Воспроизведение

```sh
cargo build --locked --release --bins --features chrome-tls
uv run --no-project tests/bench_local.py --output /tmp/foldfin-tcp \
  --rtt-ms 200 --seconds 20 --repeats 2 --telemetry \
  --netem-placement ingress --tun-queue 10000 --tcp-wmem-max 33554432
uv run --no-project tests/bench_local.py --output /tmp/foldfin-modes \
  --rtt-ms 200 --seconds 12 --repeats 1 --workload stream --modes proxy tun \
  --telemetry --netem-placement ingress --tun-queue 10000 --tcp-wmem-max 33554432
```

Замороженные binaries и исходный `vpn.rs` сохранены в
`benchmarks/2026-10-12-tcp/`. Summary каждого прогона содержит условия,
hash бинарника, результаты и cleanup. Исходный после первого этапа:
`32a56ea3096a426e00a0cae6119e67d5b7a5c1a653448fc0870a9778759cd1a9`.
Эксперимент Pump 512 + fairness:
`a537b27845fb1073592c66432314a938c05d146060305f8aaa7a7d335c913f77`.
Финальный Pump 64 + fairness:
`1b95e9efaa96451b086f2b01dc5d21a50bf6ad17927ed77a3fbd0b4dc24dcfc3`.

## Проверки и дальнейшая работа

Прошли default/chrome fmt, all-target check/test/clippy с warnings denied,
core/client/server feature checks, SOCKS smoke и routed dual-stack acceptance:
TCP/FIN, UDP/DNS/ICMP, reverse connections, PMTU, carrier loss/delay, cleanup.
15 unit tests, 4 default / 7 Chrome library tests. Новые unit tests проверяют
границу исходящей очереди, FIFO, продолжение после освобождения slot, отмену
collector и повторную проверку route withdrawal.
`captures/http2-tcp-final-20261012/summary.json` подтверждает совпадение Chrome
initial H2 SETTINGS и connection WINDOW_UPDATE. TLS profile против новой
версии браузера в этом этапе не измерялся; скрытность не подтверждается.

Следующий platform этап должен определить явную политику TUN queues и TCP
buffers с setup/rollback, затем full/split routes и DNS. Нельзя просто переносить
namespace sysctls в глобальную конфигурацию пользователя. Пакетный core сам
маршруты, DNS и network sysctls не настраивает.
Далее нужна реальная WAN проверка после настройки CONNECT-IP на Сингапуре,
строго через физический интерфейс по [методу](LOCAL-VPN-TESTING.md).
Новый server на VPS в этом этапе не развёрнут; удалённые тесты не запускались.
Ни локальные 700 Мбит/с, ни 3,6 Гбит/с не являются обещанием WAN скорости или
необнаружимости ТСПУ. Общий TCP carrier по-прежнему имеет HOL и зависит от потерь.

После последней правки telemetry helper прошёл короткую direct/proxy/TUN
проверку с SHA-256; `harness-final/` не используется для оценки скорости.
Все 20 retained benchmark summaries, включая неуспешный loss run, подтверждают
cleanup. Итоговый `ip netns list` пуст; host `tcp_wmem` остаётся
`4096 16384 4194304`, `core.wmem_max` — `4194304`. Ethernet/Wi-Fi default routes
сохранены, release hash совпадает с замороженным Pump 64.
