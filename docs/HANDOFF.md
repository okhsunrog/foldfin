# Передача на ноут

> Исторический bootstrap snapshot. Его исходный промпт ошибочно сужал цель до TCP-прокси и запрещал TUN. Для текущей продуктовой цели и согласованных приоритетов см. `GOALS.md` и `AGENTS.md`; этот старый промпт не является действующим ТЗ.

## Промпт для Codex

> Прочитай AGENTS.md, README.md и docs. Доведи этот Rust TCP-over-TLS/H2 прототип до компилируемого и проверенного состояния. Выполни fmt/check/test и tests/smoke.py, исправь ошибки и добавь Cargo.lock. Проверь backpressure, half-close, reset/cancellation и утечки upstream connections при обрыве H2. Добавь idle timeout и reconnect для новых flows. Пока не делай TUN, QUIC и browser impersonation. Покажи выполненные проверки и ограничения. Потом обсудим тесты в моей сети.

## Проверки при подготовке

Python smoke test прошёл только синтаксическую проверку py_compile. Rust код не компилировался: toolchain отсутствует, загрузка недоступна. E2E и работа с ТСПУ не проверены.

Smoke test генерирует localhost TLS cert, запускает сервер/клиент и TCP endpoint. Восемь параллельных потоков по 512 KiB, ответ только после клиентского FIN: проверка multiplexing, flow control и half-close. Затем неверный token должен дать SOCKS error.

## Открытые задачи

Тесты wrong CA/server name, private address policy, H2 resets, bounded memory. Idle cleanup и reconnect. Настоящий сайт/H1 fallback перед probing исследованиями. Прототип — TCP proxy, не IP VPN. Используй curl --socks5-hostname для серверного DNS; обычный --socks5 может резолвить локально.
