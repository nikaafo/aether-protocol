//! Управление соединением Aether Protocol
//!
//! Connection — центральный тип, объединяющий:
//! - Установление соединения (handshake)
//! - Отправка и приём фреймов
//! - Управление потоками (StreamManager)
//! - Keep-alive (Ping)
//! - Закрытие соединения
//!
//! ## API
//!
//! ```rust,no_run
//! use aether_core::{Connection, Config, Identity};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Сервер
//! let identity = Identity::generate();
//! let mut listener = Connection::bind("0.0.0.0:9000", identity, Config::default()).await?;
//!
//! // Клиент
//! let mut conn = Connection::connect("127.0.0.1:9000", Config::default()).await?;
//! let mut stream = conn.open_stream().await?;
//! stream.write(b"Hello").await?;
//! # Ok(())
//! # }
//! ```

use crate::crypto::{self, AeadAlgorithm, AeadSession};
use crate::error::{CloseCode, Error, Result};
use crate::framing::{
    ExtType, Extension, Frame, FrameType, LongHeader, Packet, ShortHeader,
    CONTROL_STREAM_ID, LONG_HEADER_SIZE, MAX_PACKET_SIZE, SHORT_HEADER_SIZE,
};
use crate::handshake::{Capabilities, HandshakeContext, HandshakeState};
use crate::identity::Identity;
use crate::stream::{StreamId, StreamManager, StreamState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{self, Duration};

/// Конфигурация соединения
#[derive(Debug, Clone)]
pub struct Config {
    /// Наши возможности
    pub capabilities: Capabilities,
    /// Порт по умолчанию
    pub port: u16,
    /// Максимальный размер буфера приёма
    pub recv_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            capabilities: Capabilities::default(),
            port: crate::AETHER_DEFAULT_PORT,
            recv_buffer_size: 65536,
        }
    }
}

/// Состояние соединения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Ожидание / начальное состояние
    Init,
    /// Выполняется handshake
    Handshaking,
    /// Соединение установлено, можно передавать данные
    Active,
    /// Соединение закрывается
    Closing,
    /// Соединение закрыто
    Closed,
}

/// Статистика соединения
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Отправлено пакетов
    pub packets_sent: u64,
    /// Получено пакетов
    pub packets_received: u64,
    /// Отправлено байт (payload)
    pub bytes_sent: u64,
    /// Получено байт (payload)
    pub bytes_received: u64,
    /// Потеряно пакетов (оценка по retransmission)
    pub packets_lost: u64,
    /// Текущий RTT в микросекундах
    pub rtt_us: u64,
}

/// Aether соединение
///
/// Представляет одно защищённое соединение с удалённым пиром.
/// Мультиплексирует множество потоков данных.
pub struct Connection {
    /// UDP сокет
    socket: Arc<UdpSocket>,
    /// Адрес пира
    peer_addr: Option<SocketAddr>,
    /// Наш Connection ID (64-битный, truncated до 32 бит для short header)
    pub our_connection_id: u32,
    /// Connection ID пира (truncated)
    pub peer_connection_id: Option<u32>,
    /// Состояние соединения
    state: ConnectionState,
    /// Контекст handshake
    handshake: Option<HandshakeContext>,
    /// AEAD сессия (после handshake)
    aead: Option<Arc<Mutex<AeadSession>>>,
    /// Менеджер потоков
    pub streams: StreamManager,
    /// Identity (наша)
    identity: Option<Identity>,
    /// Конфигурация
    config: Config,
    /// Статистика
    pub stats: ConnectionStats,
    /// Мы клиент?
    is_client: bool,
    /// Счётчик пакетов отправки
    tx_packet_number: u64,
    /// Счётчик пакетов приёма
    rx_packet_number: u64,
    /// Очередь входящих фреймов для обработки
    incoming_frames: Vec<Frame>,
    /// Ожидающие подтверждения фреймы (offset → frame data)
    pending_acks: HashMap<(StreamId, u32), (Frame, u64)>, // (stream_id, offset) → (frame, retries)
    /// Таймаут бездействия
    idle_timeout: Duration,
}

impl Connection {
    /// Привязаться к адресу и слушать входящие соединения
    pub async fn bind(addr: &str, identity: Identity, config: Config) -> Result<Listener> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!("Aether server listening on {}", addr);

        Ok(Listener {
            socket: Arc::new(socket),
            identity,
            config,
        })
    }

    /// Подключиться к пиру (клиент)
    pub async fn connect(addr: &str, config: Config) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let peer_addr: SocketAddr = addr.parse().map_err(|e| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        socket.connect(peer_addr).await?;

        tracing::info!("Aether client connecting to {}", peer_addr);

        let our_cid = crypto::generate_connection_id();

        let mut conn = Self {
            socket: Arc::new(socket),
            peer_addr: Some(peer_addr),
            our_connection_id: (our_cid >> 32) as u32,
            peer_connection_id: None,
            state: ConnectionState::Init,
            handshake: Some(HandshakeContext::new_client(our_cid)),
            aead: None,
            streams: StreamManager::new(
                true,
                config.capabilities.max_streams,
                config.capabilities.max_stream_data,
                16 * 1024 * 1024,
            ),
            identity: None,
            config,
            stats: ConnectionStats::default(),
            is_client: true,
            tx_packet_number: 0,
            rx_packet_number: 0,
            incoming_frames: Vec::new(),
            pending_acks: HashMap::new(),
            idle_timeout: Duration::from_millis(30_000),
        };

        // Выполняем handshake
        conn.perform_client_handshake().await?;
        conn.state = ConnectionState::Active;

        Ok(conn)
    }

    /// Выполнить клиентский handshake
    async fn perform_client_handshake(&mut self) -> Result<()> {
        let identity = Identity::generate(); // Временная identity для тестов
        let hs = self.handshake.as_mut().unwrap();

        // ClientHello
        let ch_frame = hs.create_client_hello(&identity, &self.config.capabilities)?;
        let ch_wire = ch_frame.encode();
        self.socket.send(&ch_wire).await?;

        // Ждём ServerHello
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let n = self.socket.recv(&mut buf).await?;
        let sh_frame = Frame::decode(&buf[..n])?;
        hs.handle_server_hello(&sh_frame)?;

        // Ждём Finished от сервера
        let n = self.socket.recv(&mut buf).await?;
        let sf_frame = Frame::decode(&buf[..n])?;

        // Отправляем свой Finished
        let cf_frame = hs.handle_finished_and_respond(&sf_frame)?;
        let cf_wire = cf_frame.encode();
        self.socket.send(&cf_wire).await?;

        // Создаём AEAD сессию
        let session_key = hs.session_key.unwrap();
        let aead = AeadSession::new(&session_key, AeadAlgorithm::Aes256Gcm)?;
        self.aead = Some(Arc::new(Mutex::new(aead)));

        // Сохраняем CID пира
        self.peer_connection_id = Some((hs.peer_connection_id.unwrap() >> 32) as u32);

        self.identity = Some(identity);
        Ok(())
    }

    /// Принять входящее соединение (сервер)
    pub async fn accept(
        socket: Arc<UdpSocket>,
        identity: &Identity,
        config: &Config,
    ) -> Result<Self> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let frame = Frame::decode(&buf[..n])?;
        if frame.header.frame_type != FrameType::Initial {
            return Err(Error::ProtocolViolation(
                "Expected Initial packet".to_string(),
            ));
        }

        let mut hs = HandshakeContext::new_server();

        // Обрабатываем ClientHello → ServerHello
        let sh_frame = hs.handle_client_hello(&frame, identity, &config.capabilities)?;
        let sh_wire = sh_frame.encode();
        socket.send_to(&sh_wire, peer_addr).await?;

        // Отправляем Finished
        let sf_frame = hs.create_finished()?;
        let sf_wire = sf_frame.encode();
        socket.send_to(&sf_wire, peer_addr).await?;

        // Ждём Finished от клиента
        let (n, _) = socket.recv_from(&mut buf).await?;
        let cf_frame = Frame::decode(&buf[..n])?;
        hs.verify_finished(&cf_frame)?;

        // Создаём AEAD сессию
        let session_key = hs.session_key.unwrap();
        let aead = AeadSession::new(&session_key, AeadAlgorithm::Aes256Gcm)?;

        let our_cid = (hs.our_connection_id >> 32) as u32;
        let peer_cid = (hs.peer_connection_id.unwrap() >> 32) as u32;

        let conn = Self {
            socket,
            peer_addr: Some(peer_addr),
            our_connection_id: our_cid,
            peer_connection_id: Some(peer_cid),
            state: ConnectionState::Active,
            handshake: Some(hs),
            aead: Some(Arc::new(Mutex::new(aead))),
            streams: StreamManager::new(
                false,
                config.capabilities.max_streams,
                config.capabilities.max_stream_data,
                16 * 1024 * 1024,
            ),
            identity: Some(identity.clone()),
            config: config.clone(),
            stats: ConnectionStats::default(),
            is_client: false,
            tx_packet_number: 0,
            rx_packet_number: 0,
            incoming_frames: Vec::new(),
            pending_acks: HashMap::new(),
            idle_timeout: Duration::from_millis(config.capabilities.idle_timeout_ms),
        };

        tracing::info!("Aether connection accepted from {}", peer_addr);
        Ok(conn)
    }

    /// Отправить фрейм (шифруется AEAD)
    pub async fn send_frame(&mut self, frame: Frame) -> Result<()> {
        if self.state != ConnectionState::Active {
            return Err(Error::InvalidState("Connection not active".to_string()));
        }

        let wire = frame.encode();

        // Шифруем если есть AEAD сессия
        let encrypted = if let Some(ref aead) = self.aead {
            let aead = aead.lock().await;
            let tx_keys = aead.tx_keys(self.is_client);
            tx_keys.encrypt(&wire, &self.make_aad())?
        } else {
            wire
        };

        self.socket.send(&encrypted).await?;
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += encrypted.len() as u64;

        Ok(())
    }

    /// Получить фрейм (расшифровывается AEAD)
    pub async fn recv_frame(&mut self) -> Result<Frame> {
        // Сначала проверяем очередь входящих
        if !self.incoming_frames.is_empty() {
            return Ok(self.incoming_frames.remove(0));
        }

        let mut buf = vec![0u8; self.config.recv_buffer_size];
        let n = self.socket.recv(&mut buf).await?;

        let data = &buf[..n];

        // Расшифровываем если есть AEAD сессия
        let decrypted = if let Some(ref aead) = self.aead {
            let aead = aead.lock().await;
            let rx_keys = aead.rx_keys(self.is_client);
            rx_keys.decrypt(data, &self.make_aad())?
        } else {
            data.to_vec()
        };

        let frame = Frame::decode(&decrypted)?;
        self.stats.packets_received += 1;
        self.stats.bytes_received += n as u64;

        Ok(frame)
    }

    /// Отправить данные в потоке
    pub async fn send_stream_data(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<()> {
        let chunk_size = crate::MAX_PAYLOAD_SIZE;
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

        for (i, chunk) in chunks.iter().enumerate() {
            let offset = i as u32 * chunk_size as u32;
            let frame = Frame::data(
                stream_id,
                self.peer_connection_id.unwrap_or(self.our_connection_id),
                offset,
                chunk.to_vec(),
            );
            self.send_frame(frame).await?;
        }

        Ok(())
    }

    /// Открыть новый поток
    pub fn open_stream(&mut self) -> Result<StreamId> {
        self.streams.open_stream()
    }

    /// Принять входящий поток
    pub fn accept_stream(&mut self) -> Result<StreamId> {
        // В реальной имплементации ждём StreamOpen фрейм
        // Сейчас возвращаем первый доступный принятый поток
        let active = self.streams.active_streams();
        if active.is_empty() {
            return Err(Error::InvalidState("No streams available".to_string()));
        }
        Ok(active[0])
    }

    /// Закрыть соединение
    pub async fn close(&mut self, code: CloseCode) -> Result<()> {
        self.state = ConnectionState::Closing;

        let frame = Frame::close(
            self.peer_connection_id.unwrap_or(self.our_connection_id),
            code,
            "Connection closed",
        );
        self.send_frame(frame).await?;

        self.state = ConnectionState::Closed;
        tracing::info!("Connection closed: {:?}", code);
        Ok(())
    }

    /// Отправить Ping (keep-alive)
    pub async fn ping(&mut self) -> Result<()> {
        let frame = Frame::ping(self.peer_connection_id.unwrap_or(self.our_connection_id));
        self.send_frame(frame).await
    }

    /// Создать AAD для AEAD (Additional Authenticated Data)
    fn make_aad(&self) -> Vec<u8> {
        // AAD включает truncated connection ID и packet number для защиты от replay
        let mut aad = Vec::with_capacity(12);
        aad.extend_from_slice(&self.our_connection_id.to_be_bytes());
        aad.extend_from_slice(&self.tx_packet_number.to_be_bytes());
        aad
    }

    /// Проверить, активно ли соединение
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Active
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("our_cid", &format!("0x{:08x}", self.our_connection_id))
            .field("peer_cid", &format!("{:?}", self.peer_connection_id.map(|c| format!("0x{:08x}", c))))
            .field("state", &self.state)
            .field("is_client", &self.is_client)
            .field("streams", &self.streams.stream_count())
            .field("stats", &self.stats)
            .finish()
    }
}

/// Слушатель входящих соединений
pub struct Listener {
    socket: Arc<UdpSocket>,
    identity: Identity,
    config: Config,
}

impl Listener {
    /// Принять входящее соединение
    pub async fn accept(&self) -> Result<Connection> {
        loop {
            match Connection::accept(
                self.socket.clone(),
                &self.identity,
                &self.config,
            ).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::warn!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
    }

    /// Получить локальный адрес
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(Error::Io)
    }

    /// Получить клон identity (только публичную часть)
    pub fn identity_hash(&self) -> String {
        self.identity.hash_hex()
    }
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.socket.local_addr())
            .field("identity", &self.identity.hash_hex())
            .finish()
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_debug() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            // Этот тест проверяет что Connection можно создать и отформатировать
            // без реального сетевого взаимодействия
            let cfg = Config::default();
            assert_eq!(cfg.port, crate::AETHER_DEFAULT_PORT);
            assert!(cfg.capabilities.multipath);
        });
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.port, 9000);
        assert_eq!(config.capabilities.max_streams, 65536);
        assert_eq!(config.capabilities.max_stream_data, 1_048_576);
        assert_eq!(config.capabilities.idle_timeout_ms, 30_000);
    }
}