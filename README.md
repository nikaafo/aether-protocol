# Aether Protocol v0.1

**Aether** — транспортный протокол четвёртого уровня (L4), спроектированный для замены TCP и UDP в сценариях, требующих мультиплексирования, шифрования, multi-path соединений и self-sovereign identity.

## Возможности

- **Wire format** — 16-байтовый short header / 24-байтовый long header, TLV extension chain
- **Handshake** — ClientHello → ServerHello → Finished, X25519 key exchange, Ed25519 identity proof
- **Шифрование** — AES-256-GCM / ChaCha20-Poly1305, HKDF key derivation
- **Self-sovereign identity** — Ed25519 ключи, проверка подлинности пиров
- **Stream multiplexing** — до 262143 потоков на соединение, flow control
- **Congestion control** — Aether-CC (гибрид BBRv3 + NewReno для шумных каналов)
- **Multi-path** — миграция соединения, проверка путей
- **Discovery** — mDNS/DHT обнаружение пиров

## Структура проекта

```
aether-protocol/
├── aether-core/       # Основная библиотека протокола (Rust)
│   ├── src/
│   │   ├── lib.rs           # Публичный API, реэкспорты
│   │   ├── framing.rs       # Wire format (encode/decode пакетов)
│   │   ├── handshake.rs     # ClientHello, ServerHello, key derivation
│   │   ├── crypto.rs        # AEAD шифрование, HKDF
│   │   ├── connection.rs    # Управление соединением
│   │   ├── stream.rs        # Управление потоками
│   │   ├── congestion.rs    # Контроль перегрузки
│   │   ├── multipath.rs     # Multi-path логика
│   │   ├── identity.rs      # Ed25519 identity
│   │   ├── discovery.rs     # mDNS/DHT
│   │   └── error.rs         # Типы ошибок
│   └── benches/             # Бенчмарки
├── aether-sdk/        # SDK для интеграции
├── demo/              # Демо-приложение
├── spec/              # Спецификация протокола
└── tests/             # Интеграционные тесты
```

## Быстрый старт

```rust
use aether_core::{Connection, Config, Identity};

let identity = Identity::generate();
let config = Config::default();

// Сервер
let mut listener = Connection::bind("0.0.0.0:9000", identity, config.clone()).await?;

// Клиент
let mut conn = Connection::connect("127.0.0.1:9000", config).await?;
let mut stream = conn.open_stream().await?;
stream.write(b"Hello, Aether!").await?;
let data = stream.read(1024).await?;
stream.close().await?;
```

## Сборка

```bash
cd aether-core
cargo build --release
cargo test --lib   # 62 тестов
```

## Лицензия

MIT License — см. [LICENSE](LICENSE).