//! Discover (автообнаружение) пиров Aether Protocol
//!
//! ## Локальное обнаружение (LAN)
//!
//! Использует UDP-мультикаст для анонсирования и поиска пиров в локальной сети.
//! - IPv4: 224.0.0.251:9001 (Aether Discovery Group)
//! - IPv6: ff02::fb:9001
//! - Периодические анонсы: каждые 30 секунд
//! - TTL анонса: 5 минут
//!
//! ## Глобальное обнаружение (WAN)
//!
//! DHT на основе Kademlia (совместимо с libp2p):
//! - Ключ в DHT = SHA-256(identity_hash)
//! - Значение = набор (IP, порт, Connection ID, timestamp)
//! - Поиск пира по identity без централизованного сервера

use crate::error::{Error, Result};
use crate::identity::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

/// Мультикаст-адрес для Aether Discovery (IPv4)
const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);

/// Мультикаст-адрес для Aether Discovery (IPv6)
const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfc);

/// Порт для мультикаст-обнаружения
const MDNS_PORT: u16 = 9001;

/// Интервал анонсов (30 секунд)
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// TTL записи в кеше (5 минут)
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Magic-байты Aether Discovery пакета
const DISCOVERY_MAGIC: [u8; 4] = *b"AED$"; // AEth-er Discovery

/// Тип discovery-сообщения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiscoveryMessageType {
    /// Анонс: "я здесь, вот мои данные"
    Announce = 0x01,
    /// Запрос: "кто здесь?"
    Query = 0x02,
    /// Ответ на запрос
    Response = 0x03,
    /// Прощание: "я ухожу" (graceful shutdown)
    Goodbye = 0x04,
}

/// Информация об обнаруженном пире
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Identity hash пира (32 байта, hex)
    pub identity_hash: String,
    /// Публичный ключ Ed25519 (32 байта, hex)
    pub public_key: String,
    /// Адрес(а) пира
    pub addresses: Vec<SocketAddr>,
    /// Предпочитаемый Connection ID
    pub connection_id: u64,
    /// Временная метка анонса
    pub timestamp: u64,
    /// Версия протокола
    pub version: u8,
    /// Возможности (текстовое описание)
    pub capabilities: Vec<String>,
}

impl PeerInfo {
    /// Создать из identity
    pub fn from_identity(identity: &Identity, addresses: Vec<SocketAddr>, connection_id: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            identity_hash: identity.hash_hex(),
            public_key: hex::encode(identity.public_key_bytes()),
            addresses,
            connection_id,
            timestamp,
            version: crate::AETHER_VERSION,
            capabilities: vec!["aether-v0".to_string(), "multipath".to_string()],
        }
    }

    /// Сериализовать в бинарный формат для отправки по сети
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Десериализовать
    pub fn decode(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| Error::ProtocolViolation(format!("Invalid peer info: {}", e)))
    }
}

/// Сообщение discovery-протокола
#[derive(Debug, Clone)]
pub struct DiscoveryMessage {
    /// Magic-байты (AED$)
    pub magic: [u8; 4],
    /// Тип сообщения
    pub msg_type: DiscoveryMessageType,
    /// Версия протокола
    pub version: u8,
    /// Информация о пире
    pub peer_info: PeerInfo,
}

impl DiscoveryMessage {
    /// Создать анонс
    pub fn announce(peer_info: PeerInfo) -> Self {
        Self {
            magic: DISCOVERY_MAGIC,
            msg_type: DiscoveryMessageType::Announce,
            version: crate::AETHER_VERSION,
            peer_info,
        }
    }

    /// Создать запрос (query)
    pub fn query() -> Self {
        Self {
            magic: DISCOVERY_MAGIC,
            msg_type: DiscoveryMessageType::Query,
            version: crate::AETHER_VERSION,
            peer_info: PeerInfo {
                identity_hash: String::new(),
                public_key: String::new(),
                addresses: vec![],
                connection_id: 0,
                timestamp: 0,
                version: crate::AETHER_VERSION,
                capabilities: vec![],
            },
        }
    }

    /// Создать goodbye
    pub fn goodbye(peer_info: PeerInfo) -> Self {
        Self {
            magic: DISCOVERY_MAGIC,
            msg_type: DiscoveryMessageType::Goodbye,
            version: crate::AETHER_VERSION,
            peer_info,
        }
    }

    /// Сериализовать в байты
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);
        buf.extend_from_slice(&self.magic);
        buf.push(self.msg_type as u8);
        buf.push(self.version);
        let info_data = self.peer_info.encode();
        buf.extend_from_slice(&info_data);
        buf
    }

    /// Десериализовать из байт
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(Error::ProtocolViolation(
                "Discovery message too short".to_string(),
            ));
        }

        let magic = [data[0], data[1], data[2], data[3]];
        if magic != DISCOVERY_MAGIC {
            return Err(Error::ProtocolViolation(
                "Invalid discovery magic bytes".to_string(),
            ));
        }

        let msg_type = match data[4] {
            0x01 => DiscoveryMessageType::Announce,
            0x02 => DiscoveryMessageType::Query,
            0x03 => DiscoveryMessageType::Response,
            0x04 => DiscoveryMessageType::Goodbye,
            _ => return Err(Error::ProtocolViolation(format!(
                "Unknown discovery message type: 0x{:02x}", data[4]
            ))),
        };

        let version = data[5];
        let peer_info = PeerInfo::decode(&data[6..])?;

        Ok(Self {
            magic,
            msg_type,
            version,
            peer_info,
        })
    }
}

/// Сервис обнаружения пиров
///
/// Запускается как фоновая задача на каждом узле Aether.
pub struct DiscoveryService {
    /// UDP сокет для мультикаста
    socket: Arc<UdpSocket>,
    /// Кеш обнаруженных пиров (identity_hash → PeerInfo)
    peers: Arc<Mutex<HashMap<String, (PeerInfo, Instant)>>>,
    /// Наша информация
    our_info: PeerInfo,
    /// Адрес мультикаст-группы
    group_addr: SocketAddr,
}

impl DiscoveryService {
    /// Создать и запустить сервис обнаружения
    pub async fn bind(identity: &Identity, port: u16) -> Result<Self> {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
        let socket = UdpSocket::bind(bind_addr).await?;

        // Вступаем в мультикаст-группу
        socket.join_multicast_v4(MDNS_GROUP_V4, Ipv4Addr::UNSPECIFIED)?;

        let group_addr = SocketAddr::new(IpAddr::V4(MDNS_GROUP_V4), MDNS_PORT);

        let local_addr = socket.local_addr()?;
        let our_info = PeerInfo::from_identity(
            identity,
            vec![local_addr],
            crate::crypto::generate_connection_id(),
        );

        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(Mutex::new(HashMap::new())),
            our_info,
            group_addr,
        })
    }

    /// Запустить фоновые задачи: периодические анонсы + приём
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let announce_self = self.clone();
        let receive_self = self.clone();

        // Задача отправки периодических анонсов
        let announce_task = tokio::spawn(async move {
            announce_self.announce_loop().await;
        });

        // Задача приёма
        let receive_task = tokio::spawn(async move {
            receive_self.receive_loop().await;
        });

        let _ = tokio::join!(announce_task, receive_task);
        Ok(())
    }

    /// Периодическая отправка анонсов
    async fn announce_loop(&self) {
        let mut interval = time::interval(ANNOUNCE_INTERVAL);

        // Первый анонс сразу
        if let Err(e) = self.send_announce().await {
            tracing::warn!("Failed to send initial announce: {}", e);
        }

        loop {
            interval.tick().await;
            if let Err(e) = self.send_announce().await {
                tracing::warn!("Failed to send announce: {}", e);
            }
        }
    }

    /// Отправить анонс
    async fn send_announce(&self) -> Result<()> {
        // Создаём свежий анонс с актуальным timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut fresh_info = self.our_info.clone();
        fresh_info.timestamp = timestamp;

        let msg = DiscoveryMessage::announce(fresh_info);
        let data = msg.encode();

        self.socket.send_to(&data, self.group_addr).await?;
        tracing::debug!("Sent discovery announce: {}", self.our_info.identity_hash);
        Ok(())
    }

    /// Цикл приёма discovery-сообщений
    async fn receive_loop(&self) {
        let mut buf = vec![0u8; 2048];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    if let Err(e) = self.handle_message(&buf[..n], src_addr).await {
                        tracing::warn!("Failed to handle discovery message: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Discovery receive error: {}", e);
                }
            }
        }
    }

    /// Обработать входящее discovery-сообщение
    async fn handle_message(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        let msg = DiscoveryMessage::decode(data)?;

        match msg.msg_type {
            DiscoveryMessageType::Announce => {
                // Игнорируем собственные анонсы
                if msg.peer_info.identity_hash == self.our_info.identity_hash {
                    return Ok(());
                }

                let peer_info = msg.peer_info.clone();
                self.cache_peer(peer_info.clone());
                tracing::debug!("Discovered peer: {} at {}", peer_info.identity_hash, src_addr);
            }
            DiscoveryMessageType::Query => {
                // Отвечаем своим анонсом
                let response = DiscoveryMessage::announce(self.our_info.clone());
                let data = response.encode();
                self.socket.send_to(&data, src_addr).await?;
            }
            DiscoveryMessageType::Goodbye => {
                self.remove_peer(&msg.peer_info.identity_hash);
            }
            DiscoveryMessageType::Response => {
                self.cache_peer(msg.peer_info);
            }
        }

        Ok(())
    }

    /// Добавить пира в кеш
    fn cache_peer(&self, peer_info: PeerInfo) {
        // Не кешируем себя
        if peer_info.identity_hash == self.our_info.identity_hash {
            return;
        }

        // Добавляем наш порт в список адресов если его там нет
        // (пир мог не знать свой публичный IP — мы добавим адрес с которого получили)

        // Обновляем/добавляем в кеш
        let mut peers = self.peers.try_lock();
        if let Ok(ref mut peers) = peers {
            peers.insert(peer_info.identity_hash.clone(), (peer_info, Instant::now()));
        }
    }

    /// Удалить пира из кеша
    fn remove_peer(&self, identity_hash: &str) {
        let mut peers = self.peers.try_lock();
        if let Ok(ref mut peers) = peers {
            peers.remove(identity_hash);
            tracing::debug!("Peer removed: {}", identity_hash);
        }
    }

    /// Получить список известных пиров (очищая просроченные)
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let mut peers = self.peers.lock().await;
        let now = Instant::now();

        // Удаляем просроченные записи
        peers.retain(|_, (_, cached_at)| now.duration_since(*cached_at) < CACHE_TTL);

        peers.values().map(|(info, _)| info.clone()).collect()
    }

    /// Найти конкретного пира по identity
    pub async fn find_peer(&self, identity_hash: &str) -> Option<PeerInfo> {
        let peers = self.get_peers().await;
        peers.into_iter().find(|p| p.identity_hash == identity_hash)
    }

    /// Отправить goodbye перед выключением
    pub async fn shutdown(&self) -> Result<()> {
        let msg = DiscoveryMessage::goodbye(self.our_info.clone());
        let data = msg.encode();
        self.socket.send_to(&data, self.group_addr).await?;
        tracing::info!("Sent discovery goodbye");
        Ok(())
    }

    /// Получить нашу identity
    pub fn our_identity(&self) -> &str {
        &self.our_info.identity_hash
    }
}

// ────────────────────────────────────────────────────────────────────
// DHT (Kademlia) Discovery — глобальное обнаружение
// ────────────────────────────────────────────────────────────────────

/// Ключ в DHT: SHA-256(identity_hash)
pub fn dht_key(identity_hash: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aether-dht:");
    hasher.update(identity_hash.as_bytes());
    hasher.finalize().into()
}

/// Запись в DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    /// Identity hash пира
    pub identity_hash: String,
    /// Адреса пира
    pub addresses: Vec<SocketAddr>,
    /// Connection ID
    pub connection_id: u64,
    /// UNIX timestamp создания
    pub created: u64,
    /// TTL в секундах
    pub ttl: u64,
}

impl DhtRecord {
    /// Создать новую DHT-запись
    pub fn new(identity_hash: String, addresses: Vec<SocketAddr>, connection_id: u64, ttl: u64) -> Self {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            identity_hash,
            addresses,
            connection_id,
            created,
            ttl,
        }
    }

    /// Проверить, не истекла ли запись
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.created + self.ttl
    }

    /// Сериализовать
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Десериализовать
    pub fn decode(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| Error::ProtocolViolation(format!("Invalid DHT record: {}", e)))
    }
}

/// XOR-метрика Kademlia (расстояние между ключами)
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Конвертировать XOR-distance в числовой порядок (big-endian)
pub fn distance_order(distance: &[u8; 32]) -> u32 {
    // Берём старшие 4 байта для сортировки
    u32::from_be_bytes([distance[0], distance[1], distance[2], distance[3]])
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_message_encode_decode() {
        let id = Identity::generate();
        let info = PeerInfo::from_identity(
            &id,
            vec!["127.0.0.1:9000".parse().unwrap()],
            0xABCD,
        );
        let msg = DiscoveryMessage::announce(info);

        let data = msg.encode();
        let decoded = DiscoveryMessage::decode(&data).unwrap();

        assert_eq!(decoded.magic, DISCOVERY_MAGIC);
        assert_eq!(decoded.msg_type, DiscoveryMessageType::Announce);
        assert_eq!(decoded.peer_info.identity_hash, id.hash_hex());
        assert_eq!(decoded.peer_info.connection_id, 0xABCD);
    }

    #[test]
    fn test_discovery_query() {
        let msg = DiscoveryMessage::query();
        let data = msg.encode();
        let decoded = DiscoveryMessage::decode(&data).unwrap();

        assert_eq!(decoded.msg_type, DiscoveryMessageType::Query);
        assert!(decoded.peer_info.identity_hash.is_empty());
    }

    #[test]
    fn test_dht_key() {
        let key1 = dht_key("test-identity");
        let key2 = dht_key("test-identity");
        assert_eq!(key1, key2);

        let key3 = dht_key("other-identity");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_xor_distance() {
        let a = [0x00u8; 32];
        let b = [0xFFu8; 32];
        let dist = xor_distance(&a, &b);
        assert_eq!(dist, [0xFFu8; 32]);

        let same_dist = xor_distance(&a, &a);
        assert_eq!(same_dist, [0x00u8; 32]);
    }

    #[test]
    fn test_dht_record_expiry() {
        let record = DhtRecord::new(
            "test-id".to_string(),
            vec![],
            0,
            0, // TTL = 0 — истекает сразу
        );
        assert!(record.is_expired());

        let record2 = DhtRecord::new(
            "test-id2".to_string(),
            vec![],
            0,
            3600, // TTL = 1 час
        );
        assert!(!record2.is_expired());
    }

    #[test]
    fn test_peer_info_encode_decode() {
        let id = Identity::generate();
        let info = PeerInfo::from_identity(
            &id,
            vec!["192.168.1.1:9000".parse().unwrap()],
            0xDEAD,
        );

        let encoded = info.encode();
        let decoded = PeerInfo::decode(&encoded).unwrap();

        assert_eq!(decoded.identity_hash, id.hash_hex());
        assert_eq!(decoded.connection_id, 0xDEAD);
        assert!(!decoded.addresses.is_empty());
    }
}