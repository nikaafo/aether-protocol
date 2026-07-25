//! Handshake Aether Protocol v0.1
//!
//! Двухфазный handshake:
//! 1. Initial (ClientHello → ServerHello) — обмен ключами, identity, capabilities
//! 2. Handshake (Finished → Finished) — подтверждение владения ключами
//!
//! После handshake соединение зашифровано AEAD.

use crate::crypto::{
    self, compute_finished, derive_initial_key, derive_session_key,
    verify_finished, x25519_dh, x25519_generate_keypair, AeadAlgorithm, AeadSession,
    DirectionalKeys,
};
use crate::error::{CloseCode, Error, Result};
use crate::framing::{Frame, FrameType, CONTROL_STREAM_ID};
use crate::identity::Identity;
use std::fmt;
use x25519_dalek::EphemeralSecret;

/// Максимальный размер handshake-сообщения в байтах
pub const MAX_HANDSHAKE_SIZE: usize = 4096;

/// Состояние handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Начальное состояние
    Initial,
    /// ClientHello отправлен, ждём ServerHello
    HelloSent,
    /// ServerHello получен, ключи вычислены
    KeysDerived,
    /// Finished отправлен и получен — handshake завершён
    Complete,
    /// Ошибка handshake
    Failed,
}

/// Возможности, объявляемые при handshake
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Поддержка multi-path
    pub multipath: bool,
    /// Максимальное количество потоков
    pub max_streams: u32,
    /// Максимальный размер данных на поток (начальное окно)
    pub max_stream_data: u64,
    /// Частота отправки Ack (каждые N пакетов)
    pub ack_frequency: u8,
    /// Таймаут бездействия в миллисекундах
    pub idle_timeout_ms: u64,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            multipath: true,
            max_streams: 65536,
            max_stream_data: 1_048_576, // 1 MB
            ack_frequency: 2,
            idle_timeout_ms: 30_000,
        }
    }
}

/// ClientHello — первый пакет соединения
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Версия протокола
    pub version: u8,
    /// Случайный Connection ID клиента (64 бита)
    pub connection_id: u64,
    /// Поддерживаемые версии
    pub supported_versions: Vec<u8>,
    /// Выбранный AEAD алгоритм
    pub aead: AeadAlgorithm,
    /// X25519 эфемерный публичный ключ клиента
    pub x25519_public: [u8; 32],
    /// Identity клиента
    pub identity: [u8; 32],
    /// Публичный ключ Ed25519 клиента
    pub identity_public_key: [u8; 32],
    /// Возможности клиента
    pub capabilities: Capabilities,
}

impl ClientHello {
    /// Создать ClientHello
    pub fn new(
        connection_id: u64,
        x25519_public: [u8; 32],
        identity: &Identity,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            version: crate::AETHER_VERSION,
            connection_id,
            supported_versions: vec![crate::AETHER_VERSION],
            aead: AeadAlgorithm::Aes256Gcm,
            x25519_public,
            identity: *identity.hash(),
            identity_public_key: identity.public_key_bytes(),
            capabilities,
        }
    }

    /// Сериализовать в CBOR-like формат (упрощённый бинарный формат)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // Version (1 byte)
        buf.push(self.version);

        // Connection ID (8 bytes)
        buf.extend_from_slice(&self.connection_id.to_be_bytes());

        // Supported versions count + versions
        buf.push(self.supported_versions.len() as u8);
        for &v in &self.supported_versions {
            buf.push(v);
        }

        // AEAD algorithm (1 byte: 0x00 = AES-256-GCM, 0x01 = ChaCha20)
        buf.push(match self.aead {
            AeadAlgorithm::Aes256Gcm => 0x00,
            AeadAlgorithm::ChaCha20Poly1305 => 0x01,
        });

        // X25519 public key (32 bytes)
        buf.extend_from_slice(&self.x25519_public);

        // Identity hash (32 bytes)
        buf.extend_from_slice(&self.identity);

        // Identity Ed25519 public key (32 bytes)
        buf.extend_from_slice(&self.identity_public_key);

        // Capabilities
        buf.push(if self.capabilities.multipath { 1 } else { 0 });
        buf.extend_from_slice(&self.capabilities.max_streams.to_be_bytes());
        buf.extend_from_slice(&self.capabilities.max_stream_data.to_be_bytes());
        buf.push(self.capabilities.ack_frequency);
        buf.extend_from_slice(&self.capabilities.idle_timeout_ms.to_be_bytes());

        buf
    }

    /// Десериализовать из бинарного формата
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 80 {
            return Err(Error::ProtocolViolation(
                "ClientHello too short".to_string(),
            ));
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        let connection_id = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);
        offset += 8;

        let versions_count = data[offset] as usize;
        offset += 1;
        let mut supported_versions = Vec::with_capacity(versions_count);
        for _ in 0..versions_count {
            supported_versions.push(data[offset]);
            offset += 1;
        }

        let aead = match data[offset] {
            0x00 => AeadAlgorithm::Aes256Gcm,
            0x01 => AeadAlgorithm::ChaCha20Poly1305,
            _ => return Err(Error::ProtocolViolation("Unknown AEAD algorithm".to_string())),
        };
        offset += 1;

        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut identity = [0u8; 32];
        identity.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut identity_public_key = [0u8; 32];
        identity_public_key.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let multipath = data[offset] != 0;
        offset += 1;

        let max_streams = u32::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
        ]);
        offset += 4;

        let max_stream_data = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);
        offset += 8;

        let ack_frequency = data[offset];
        offset += 1;

        let idle_timeout_ms = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);

        Ok(Self {
            version,
            connection_id,
            supported_versions,
            aead,
            x25519_public,
            identity,
            identity_public_key,
            capabilities: Capabilities {
                multipath,
                max_streams,
                max_stream_data,
                ack_frequency,
                idle_timeout_ms,
            },
        })
    }
}

/// ServerHello — ответ на ClientHello
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Версия протокола
    pub version: u8,
    /// Connection ID сервера
    pub source_connection_id: u64,
    /// Echo клиентского CID
    pub dest_connection_id: u64,
    /// X25519 эфемерный публичный ключ сервера
    pub x25519_public: [u8; 32],
    /// Identity сервера
    pub identity: [u8; 32],
    /// Публичный ключ Ed25519 сервера
    pub identity_public_key: [u8; 32],
    /// Подпись transcript'а (proof of identity)
    pub identity_proof: Vec<u8>,
    /// Возможности сервера (пересечение с клиентом)
    pub capabilities: Capabilities,
}

impl ServerHello {
    /// Создать ServerHello
    pub fn new(
        source_connection_id: u64,
        dest_connection_id: u64,
        x25519_public: [u8; 32],
        identity: &Identity,
        transcript: &[u8],
        capabilities: Capabilities,
    ) -> Self {
        let signature = identity.sign(transcript);
        Self {
            version: crate::AETHER_VERSION,
            source_connection_id,
            dest_connection_id,
            x25519_public,
            identity: *identity.hash(),
            identity_public_key: identity.public_key_bytes(),
            identity_proof: signature.to_bytes().to_vec(),
            capabilities,
        }
    }

    /// Сериализовать
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        buf.push(self.version);
        buf.extend_from_slice(&self.source_connection_id.to_be_bytes());
        buf.extend_from_slice(&self.dest_connection_id.to_be_bytes());
        buf.extend_from_slice(&self.x25519_public);
        buf.extend_from_slice(&self.identity);
        buf.extend_from_slice(&self.identity_public_key);

        // Proof length + proof
        buf.extend_from_slice(&(self.identity_proof.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.identity_proof);

        // Capabilities
        buf.push(if self.capabilities.multipath { 1 } else { 0 });
        buf.extend_from_slice(&self.capabilities.max_streams.to_be_bytes());
        buf.extend_from_slice(&self.capabilities.max_stream_data.to_be_bytes());
        buf.push(self.capabilities.ack_frequency);
        buf.extend_from_slice(&self.capabilities.idle_timeout_ms.to_be_bytes());

        buf
    }

    /// Десериализовать
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        let version = data[offset]; offset += 1;

        let source_connection_id = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]); offset += 8;

        let dest_connection_id = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]); offset += 8;

        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let mut identity = [0u8; 32];
        identity.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let mut identity_public_key = [0u8; 32];
        identity_public_key.copy_from_slice(&data[offset..offset+32]); offset += 32;

        let proof_len = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;
        offset += 2;
        let identity_proof = data[offset..offset+proof_len].to_vec();
        offset += proof_len;

        let multipath = data[offset] != 0; offset += 1;
        let max_streams = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        offset += 4;
        let max_stream_data = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]); offset += 8;
        let ack_frequency = data[offset]; offset += 1;
        let idle_timeout_ms = u64::from_be_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);

        Ok(Self {
            version,
            source_connection_id,
            dest_connection_id,
            x25519_public,
            identity,
            identity_public_key,
            identity_proof,
            capabilities: Capabilities { multipath, max_streams, max_stream_data, ack_frequency, idle_timeout_ms },
        })
    }
}

/// Контекст handshake (состояние одной стороны)
pub struct HandshakeContext {
    /// Текущее состояние
    pub state: HandshakeState,
    /// Наш Connection ID (64 бита)
    pub our_connection_id: u64,
    /// Connection ID пира (64 бита)
    pub peer_connection_id: Option<u64>,
    /// Наш эфемерный X25519 приватный ключ
    pub x25519_secret: Option<EphemeralSecret>,
    /// Публичный ключ X25519 пира
    pub peer_x25519_public: Option<[u8; 32]>,
    /// Transcript handshake
    pub transcript: Vec<u8>,
    /// Session key (после вычисления)
    pub session_key: Option<[u8; 32]>,
    /// Согласованные возможности
    pub capabilities: Option<Capabilities>,
    /// Identity пира
    pub peer_identity: Option<[u8; 32]>,
    /// Мы клиент?
    pub is_client: bool,
}

impl HandshakeContext {
    /// Создать контекст для клиента
    pub fn new_client(our_connection_id: u64) -> Self {
        Self {
            state: HandshakeState::Initial,
            our_connection_id,
            peer_connection_id: None,
            x25519_secret: None,
            peer_x25519_public: None,
            transcript: Vec::new(),
            session_key: None,
            capabilities: None,
            peer_identity: None,
            is_client: true,
        }
    }

    /// Создать контекст для сервера
    pub fn new_server() -> Self {
        Self {
            state: HandshakeState::Initial,
            our_connection_id: 0, // будет установлен при создании ServerHello
            peer_connection_id: None,
            x25519_secret: None,
            peer_x25519_public: None,
            transcript: Vec::new(),
            session_key: None,
            capabilities: None,
            peer_identity: None,
            is_client: false,
        }
    }

    /// Клиент: создать ClientHello и получить Frame для отправки
    pub fn create_client_hello(
        &mut self,
        identity: &Identity,
        capabilities: &Capabilities,
    ) -> Result<Frame> {
        // Генерируем X25519 эфемерную пару
        let (public, secret) = x25519_generate_keypair();
        self.x25519_secret = Some(secret);
        self.peer_x25519_public = None; // Пока не знаем публичный ключ сервера

        let hello = ClientHello::new(self.our_connection_id, public, identity, capabilities.clone());
        let hello_data = hello.encode();

        // Добавляем в transcript
        self.transcript.extend_from_slice(b"ClientHello:");
        self.transcript.extend_from_slice(&hello_data);

        self.state = HandshakeState::HelloSent;

        Ok(Frame::new_long(
            FrameType::Initial,
            CONTROL_STREAM_ID,
            (self.our_connection_id >> 32) as u32, // truncated dest CID (нет пира ещё)
            self.our_connection_id,
            hello_data,
        ))
    }

    /// Сервер: обработать ClientHello и создать ServerHello
    pub fn handle_client_hello(
        &mut self,
        frame: &Frame,
        identity: &Identity,
        capabilities: &Capabilities,
    ) -> Result<Frame> {
        let hello = ClientHello::decode(&frame.payload)?;

        // Проверяем версию
        if !hello.supported_versions.contains(&crate::AETHER_VERSION) {
            return Err(Error::VersionNegotiation(format!(
                "Unsupported version: peer supports {:?}, we are v{}",
                hello.supported_versions,
                crate::AETHER_VERSION
            )));
        }

        // Сохраняем CID пира
        self.peer_connection_id = Some(hello.connection_id);
        self.our_connection_id = crypto::generate_connection_id();

        // Сохраняем публичный ключ пира
        self.peer_x25519_public = Some(hello.x25519_public);

        // Сохраняем identity пира
        self.peer_identity = Some(hello.identity);

        // Transcript
        self.transcript.extend_from_slice(b"ClientHello:");
        self.transcript.extend_from_slice(&frame.payload);

        // Генерируем X25519 эфемерную пару
        let (public, secret) = x25519_generate_keypair();
        self.x25519_secret = Some(secret);

        // Согласовываем capabilities (пересечение)
        let negotiated = Capabilities {
            multipath: capabilities.multipath && hello.capabilities.multipath,
            max_streams: capabilities.max_streams.min(hello.capabilities.max_streams),
            max_stream_data: capabilities.max_stream_data.min(hello.capabilities.max_stream_data),
            ack_frequency: hello.capabilities.ack_frequency,
            idle_timeout_ms: capabilities.idle_timeout_ms.min(hello.capabilities.idle_timeout_ms),
        };

        // Создаём ServerHello
        let server_hello = ServerHello::new(
            self.our_connection_id,
            hello.connection_id,
            public,
            identity,
            &self.transcript,
            negotiated.clone(),
        );
        let hello_data = server_hello.encode();

        // Добавляем ServerHello в transcript
        self.transcript.extend_from_slice(b"ServerHello:");
        self.transcript.extend_from_slice(&hello_data);

        // Вычисляем shared secret и session key
        self.derive_keys()?;

        self.capabilities = Some(negotiated);
        self.state = HandshakeState::KeysDerived;

        Ok(Frame::new_long(
            FrameType::Initial,
            CONTROL_STREAM_ID,
            (hello.connection_id >> 32) as u32,
            self.our_connection_id,
            hello_data,
        ))
    }

    /// Клиент: обработать ServerHello
    pub fn handle_server_hello(&mut self, frame: &Frame) -> Result<()> {
        let server_hello = ServerHello::decode(&frame.payload)?;

        // Сохраняем CID сервера
        self.peer_connection_id = Some(server_hello.source_connection_id);

        // Сохраняем публичный ключ сервера
        self.peer_x25519_public = Some(server_hello.x25519_public);

        // Сохраняем identity сервера
        self.peer_identity = Some(server_hello.identity);

        // Проверяем identity proof сервера ПЕРЕД добавлением ServerHello в transcript
        // (сервер подписал transcript без ServerHello)
        let proof_bytes: [u8; 64] = server_hello.identity_proof
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("Invalid signature length".to_string()))?;
        Identity::verify(
            &server_hello.identity_public_key,
            &self.transcript,
            &ed25519_dalek::Signature::from_bytes(&proof_bytes),
        )?;

        // Добавляем ServerHello в transcript
        self.transcript.extend_from_slice(b"ServerHello:");
        self.transcript.extend_from_slice(&frame.payload);

        // Вычисляем shared secret и session key
        self.derive_keys()?;

        self.capabilities = Some(server_hello.capabilities);
        self.state = HandshakeState::KeysDerived;

        Ok(())
    }

    /// Сервер: создать Finished
    pub fn create_finished(&self) -> Result<Frame> {
        let session_key = self.session_key
            .ok_or_else(|| Error::InvalidState("Session key not derived".to_string()))?;

        let peer_cid = self.peer_connection_id
            .ok_or_else(|| Error::InvalidState("Peer CID not known".to_string()))?;

        let finished = compute_finished(&session_key, &self.transcript);

        Ok(Frame::new_long(
            FrameType::Handshake,
            CONTROL_STREAM_ID,
            (peer_cid >> 32) as u32,
            self.our_connection_id,
            finished,
        ))
    }

    /// Проверить Finished от пира и создать свой Finished (клиент)
    pub fn handle_finished_and_respond(
        &mut self,
        frame: &Frame,
    ) -> Result<Frame> {
        let session_key = self.session_key
            .ok_or_else(|| Error::InvalidState("Session key not derived".to_string()))?;

        // Проверяем Finished пира
        verify_finished(&session_key, &self.transcript, &frame.payload)?;

        // Создаём свой Finished
        let finished = compute_finished(&session_key, &self.transcript);

        self.state = HandshakeState::Complete;

        let peer_cid = self.peer_connection_id
            .ok_or_else(|| Error::InvalidState("Peer CID not known".to_string()))?;

        Ok(Frame::new_long(
            FrameType::Handshake,
            CONTROL_STREAM_ID,
            (peer_cid >> 32) as u32,
            self.our_connection_id,
            finished,
        ))
    }

    /// Проверить Finished от пира (для сервера, который уже отправил свой Finished)
    pub fn verify_finished(&mut self, frame: &Frame) -> Result<()> {
        let session_key = self.session_key
            .ok_or_else(|| Error::InvalidState("Session key not derived".to_string()))?;

        verify_finished(&session_key, &self.transcript, &frame.payload)?;
        self.state = HandshakeState::Complete;
        Ok(())
    }

    /// Вычислить shared secret и session key
    fn derive_keys(&mut self) -> Result<()> {
        let our_secret = self.x25519_secret.take()
            .ok_or_else(|| Error::InvalidState("Our X25519 secret not set".to_string()))?;
        let peer_public = self.peer_x25519_public
            .ok_or_else(|| Error::InvalidState("Peer X25519 public not set".to_string()))?;

        let shared_secret = x25519_dh(our_secret, &peer_public);
        let session_key = derive_session_key(&shared_secret, &self.transcript)?;

        self.session_key = Some(session_key);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_client_hello_encode_decode() {
        let id = Identity::generate();
        let hello = ClientHello::new(
            0xABCD,
            [0x42; 32],
            &id,
            Capabilities::default(),
        );

        let encoded = hello.encode();
        let decoded = ClientHello::decode(&encoded).unwrap();

        assert_eq!(decoded.version, crate::AETHER_VERSION);
        assert_eq!(decoded.connection_id, 0xABCD);
        assert_eq!(decoded.x25519_public, [0x42; 32]);
        assert_eq!(decoded.identity, *id.hash());
        assert_eq!(decoded.capabilities.multipath, true);
    }

    #[test]
    fn test_server_hello_encode_decode() {
        let id = Identity::generate();
        let transcript = b"test transcript";
        let hello = ServerHello::new(
            0x1234,
            0x5678,
            [0x99; 32],
            &id,
            transcript,
            Capabilities::default(),
        );

        let encoded = hello.encode();
        let decoded = ServerHello::decode(&encoded).unwrap();

        assert_eq!(decoded.source_connection_id, 0x1234);
        assert_eq!(decoded.dest_connection_id, 0x5678);
        assert_eq!(decoded.x25519_public, [0x99; 32]);

        // Проверяем proof
        let proof_bytes: [u8; 64] = decoded.identity_proof
            .as_slice()
            .try_into()
            .expect("signature must be 64 bytes");
        let result = Identity::verify(
            &decoded.identity_public_key,
            transcript,
            &ed25519_dalek::Signature::from_bytes(&proof_bytes),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_handshake() {
        let client_id = Identity::generate();
        let server_id = Identity::generate();

        let mut client_ctx = HandshakeContext::new_client(0xAAAA);
        let mut server_ctx = HandshakeContext::new_server();

        // ClientHello
        let ch_frame = client_ctx
            .create_client_hello(&client_id, &Capabilities::default())
            .unwrap();

        // Server обрабатывает ClientHello → ServerHello
        let sh_frame = server_ctx
            .handle_client_hello(&ch_frame, &server_id, &Capabilities::default())
            .unwrap();

        // Client обрабатывает ServerHello
        client_ctx.handle_server_hello(&sh_frame).unwrap();

        // Client создаёт Finished
        let cf_frame = client_ctx.handle_finished_and_respond(
            &Frame::new_long(FrameType::Handshake, 0, 0, 0, b"dummy".to_vec()),
        ).unwrap_err(); // Здесь нужен реальный Finished от сервера

        // Правильный порядок: сервер создаёт Finished
        let sf_frame = server_ctx.create_finished().unwrap();

        // Клиент проверяет Finished сервера и создаёт свой
        let cf_frame = client_ctx.handle_finished_and_respond(&sf_frame).unwrap();
        assert_eq!(client_ctx.state, HandshakeState::Complete);

        // Сервер проверяет Finished клиента
        server_ctx.verify_finished(&cf_frame).unwrap();
        assert_eq!(server_ctx.state, HandshakeState::Complete);

        // Оба имеют одинаковый session key
        assert_eq!(client_ctx.session_key, server_ctx.session_key);
    }

    #[test]
    fn test_capabilities_negotiation() {
        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let mut client_ctx = HandshakeContext::new_client(0xAAAA);
        let mut server_ctx = HandshakeContext::new_server();

        let client_caps = Capabilities {
            multipath: true,
            max_streams: 1000,
            max_stream_data: 1_000_000,
            ack_frequency: 2,
            idle_timeout_ms: 60_000,
        };

        let server_caps = Capabilities {
            multipath: false,
            max_streams: 500,
            max_stream_data: 2_000_000,
            ack_frequency: 1,
            idle_timeout_ms: 30_000,
        };

        let ch = client_ctx.create_client_hello(&client_id, &client_caps).unwrap();
        let _sh = server_ctx.handle_client_hello(&ch, &server_id, &server_caps).unwrap();

        let negotiated = server_ctx.capabilities.unwrap();
        assert_eq!(negotiated.multipath, false); // min(true, false)
        assert_eq!(negotiated.max_streams, 500); // min(1000, 500)
        assert_eq!(negotiated.max_stream_data, 1_000_000); // min(1M, 2M)
        assert_eq!(negotiated.idle_timeout_ms, 30_000); // min(60s, 30s)
    }

    #[test]
    fn test_version_mismatch() {
        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let mut client_ctx = HandshakeContext::new_client(0xAAAA);
        let mut server_ctx = HandshakeContext::new_server();

        // Создаём ClientHello с версией 5 (которую сервер не поддерживает)
        let (public, secret) = x25519_generate_keypair();
        let mut hello = ClientHello::new(0xAAAA, public, &client_id, Capabilities::default());
        hello.version = 5;
        hello.supported_versions = vec![5];

        let hello_data = hello.encode();
        let frame = Frame::new_long(FrameType::Initial, 0, 0, 0xAAAA, hello_data);

        let result = server_ctx.handle_client_hello(&frame, &server_id, &Capabilities::default());
        assert!(result.is_err());
        match result {
            Err(Error::VersionNegotiation(_)) => {} // ожидаемо
            _ => panic!("Expected VersionNegotiation error"),
        }
    }
}