//! # Aether Protocol — Core Library
//!
//! Aether — это транспортный протокол четвёртого уровня (L4), спроектированный
//! для замены TCP и UDP в сценариях, требующих мультиплексирования,
//! шифрования, multi-path соединений и self-sovereign identity.
//!
//! ## Основные модули
//!
//! - `framing` — wire format, encode/decode пакетов (16-байтовый заголовок)
//! - `handshake` — ClientHello, ServerHello, key derivation (Kyber + X25519)
//! - `stream` — управление потоками, flow control, мультиплексирование
//! - `connection` — управление соединением, таймеры, keep-alive
//! - `congestion` — Aether-CC (гибрид BBRv3 + NewReno для шумных каналов)
//! - `multipath` — multi-path логика, миграция соединения
//! - `identity` — Ed25519 self-sovereign identity
//! - `crypto` — AEAD шифрование, HKDF, key schedule
//! - `discovery` — mDNS/DHT обнаружение пиров
//!
//! ## Быстрый старт
//!
//! ```rust,no_run
//! use aether_core::{Connection, Config, Identity};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = Identity::generate();
//! let config = Config::default();
//!
//! // Сервер
//! let mut listener = Connection::bind("0.0.0.0:9000", identity, config.clone()).await?;
//!
//! // Клиент
//! let mut conn = Connection::connect("127.0.0.1:9000", config).await?;
//! let mut stream = conn.open_stream().await?;
//! stream.write(b"Hello, Aether!").await?;
//! let data = stream.read(1024).await?;
//! stream.close().await?;
//! # Ok(())
//! # }
//! ```

pub mod congestion;
pub mod connection;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod multipath;
pub mod stream;

// Реэкспорт основных типов для удобного API
pub use connection::{Config, Connection, Listener};
pub use error::{Error, Result};
pub use framing::{
    ExtType, Extension, Frame, FrameType, LongHeader, Packet, ShortHeader, MAX_PACKET_SIZE,
};
pub use identity::Identity;
pub use stream::{Stream, StreamId, StreamState};

/// Версия протокола Aether
pub const AETHER_VERSION: u8 = 0;

/// Порт по умолчанию для Aether
pub const AETHER_DEFAULT_PORT: u16 = 9000;

/// Максимальный размер пакета (payload + заголовки)
/// 1400 байт — с запасом под Ethernet MTU (1500 - IP header - UDP header)
pub const MAX_PAYLOAD_SIZE: usize = 1376; // 1400 - 24 (long header max)

/// Начальное congestion window (10 * MSS)
pub const INITIAL_CWND: u64 = 10 * MAX_PACKET_SIZE as u64;

/// Таймаут бездействия соединения по умолчанию (миллисекунды)
pub const IDLE_TIMEOUT_MS: u64 = 30_000;

/// Базовый Probe Timeout (миллисекунды)
pub const PTO_BASE_MS: u64 = 100;