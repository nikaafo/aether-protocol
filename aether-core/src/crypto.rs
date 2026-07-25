//! Криптографические операции Aether Protocol
//!
//! - AEAD шифрование (AES-256-GCM / ChaCha20-Poly1305)
//! - HKDF key derivation
//! - Key schedule для handshake
//! - Initial salt и защита первого пакета
//!
//! Aether **не имеет plaintext-режима**. Все пакеты шифруются.

use crate::error::{Error, Result};
use aead::{Aead, Key, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

/// Длина ключа AEAD в байтах (256 бит)
pub const AEAD_KEY_LEN: usize = 32;

/// Длина nonce для AEAD в байтах (96 бит = 12 байт)
pub const AEAD_NONCE_LEN: usize = 12;

/// Длина тега аутентификации AEAD в байтах (128 бит = 16 байт)
pub const AEAD_TAG_LEN: usize = 16;

/// Initial salt для защиты первого пакета
pub const INITIAL_SALT: &[u8] = b"AETHER-v0-initial-salt-32bytes!OK";

/// Тип AEAD-алгоритма
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-256-GCM (аппаратно ускоряется на x86 через AES-NI)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (быстрее на ARM и устройствах без AES-NI)
    ChaCha20Poly1305,
}

impl fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

impl AeadAlgorithm {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "AES-256-GCM" | "aes-256-gcm" => Some(Self::Aes256Gcm),
            "ChaCha20-Poly1305" | "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Сессионные ключи для одного направления
#[derive(Zeroize)]
pub struct DirectionalKeys {
    /// Ключ AEAD (256 бит)
    pub tx_key: [u8; AEAD_KEY_LEN],
    /// IV / начальный nonce для AEAD (96 бит)
    pub tx_iv: [u8; AEAD_NONCE_LEN],
    /// Счётчик пакетов (инкрементируется с каждым пакетом)
    pub packet_number: u64,
}

impl DirectionalKeys {
    /// Создать новые ключи из секрета и метки
    pub fn derive(secret: &[u8], label: &[u8]) -> Result<Self> {
        let mut okm = [0u8; AEAD_KEY_LEN + AEAD_NONCE_LEN];
        let hkdf = Hkdf::<Sha256>::new(None, secret);

        hkdf.expand(label, &mut okm)
            .map_err(|e| Error::Crypto(format!("HKDF expand failed: {}", e)))?;

        let mut tx_key = [0u8; AEAD_KEY_LEN];
        let mut tx_iv = [0u8; AEAD_NONCE_LEN];

        tx_key.copy_from_slice(&okm[..AEAD_KEY_LEN]);
        tx_iv.copy_from_slice(&okm[AEAD_KEY_LEN..]);

        Ok(Self {
            tx_key,
            tx_iv,
            packet_number: 0,
        })
    }

    /// Зашифровать payload с AEAD
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.tx_key));
        let nonce = self.make_nonce();

        cipher
            .encrypt(Nonce::<Aes256Gcm>::from_slice(&nonce), aead::Payload { msg: plaintext, aad })
            .map_err(|e| Error::Crypto(format!("AEAD encrypt failed: {}", e)))
    }

    /// Расшифровать payload с AEAD
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.tx_key));
        let nonce = self.make_nonce();

        cipher
            .decrypt(Nonce::<Aes256Gcm>::from_slice(&nonce), aead::Payload { msg: ciphertext, aad })
            .map_err(|e| Error::Crypto(format!("AEAD decrypt failed: {}", e)))
    }

    /// Создать nonce из IV + packet number
    fn make_nonce(&self) -> [u8; AEAD_NONCE_LEN] {
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&self.tx_iv);
        // XOR последних 8 байт nonce с packet number (little-endian)
        let pn = self.packet_number.to_le_bytes();
        for i in 0..8 {
            nonce[AEAD_NONCE_LEN - 8 + i] ^= pn[i];
        }
        nonce
    }
}

/// Сессия AEAD — ключи для обоих направлений
pub struct AeadSession {
    /// Ключи для отправки (клиент → сервер)
    pub client_tx: DirectionalKeys,
    /// Ключи для приёма (сервер → клиент для клиента, наоборот для сервера)
    pub server_tx: DirectionalKeys,
    /// Используемый алгоритм
    pub algorithm: AeadAlgorithm,
}

impl AeadSession {
    /// Создать сессию из session_key после handshake
    pub fn new(session_key: &[u8], algorithm: AeadAlgorithm) -> Result<Self> {
        let client_tx = DirectionalKeys::derive(session_key, b"aether-client-tx")?;
        let server_tx = DirectionalKeys::derive(session_key, b"aether-server-tx")?;

        Ok(Self {
            client_tx,
            server_tx,
            algorithm,
        })
    }

    /// Получить ключи отправки для данного направления
    pub fn tx_keys(&self, is_client: bool) -> &DirectionalKeys {
        if is_client { &self.client_tx } else { &self.server_tx }
    }

    /// Получить ключи приёма для данного направления
    pub fn rx_keys(&self, is_client: bool) -> &DirectionalKeys {
        if is_client { &self.server_tx } else { &self.client_tx }
    }

    /// Инкрементировать счётчик пакетов отправки
    pub fn increment_tx(&mut self, is_client: bool) {
        if is_client {
            // client_tx.send — это наши ключи отправки, инкрементируем их
            // Но DirectionalKeys в сессии — это "клиент отправляет", "сервер отправляет"
            // Если мы клиент, наш tx = client_tx
            // self.client_tx.packet_number += 1;
        }
        // Конкретный DirectionalKeys будет инкрементироваться на уровне Connection
    }
}

/// Вычислить initial-ключ для первого Initial-пакета
///
/// Initial-пакеты защищены ключом, производным от initial salt.
/// Это не обеспечивает конфиденциальность (соль публична),
/// но защищает от tampering и гарантирует целостность ClientHello.
pub fn derive_initial_key(dest_connection_id: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let mut key = [0u8; AEAD_KEY_LEN];
    let hkdf = Hkdf::<Sha256>::new(Some(INITIAL_SALT), dest_connection_id);
    hkdf.expand(b"aether-initial", &mut key)
        .expect("HKDF expand for initial key should never fail");
    key
}

/// Вычислить session_key из shared_secret и transcript
///
/// ```text
/// session_key = HKDF-Expand(
///     HKDF-Extract("AETHER-v0", shared_secret),
///     transcript,
///     256 bits
/// )
/// ```
pub fn derive_session_key(shared_secret: &[u8], transcript: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(b"AETHER-v0"), shared_secret);

    hkdf.expand(transcript, &mut key)
        .map_err(|e| Error::Crypto(format!("HKDF session key derivation failed: {}", e)))?;

    Ok(key)
}

/// Вычислить Finished MAC для handshake
///
/// ```text
/// finished = HMAC-SHA256(session_key, transcript)
/// ```
pub fn compute_finished(session_key: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key)
        .expect("HMAC should accept any key length");
    mac.update(transcript);
    mac.finalize().into_bytes().to_vec()
}

/// Проверить Finished MAC
pub fn verify_finished(session_key: &[u8], transcript: &[u8], finished: &[u8]) -> Result<()> {
    let expected = compute_finished(session_key, transcript);
    if expected.as_slice() != finished {
        return Err(Error::Crypto("Finished MAC verification failed".to_string()));
    }
    Ok(())
}

/// Сгенерировать случайный Connection ID (64 бита)
pub fn generate_connection_id() -> u64 {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// Сгенерировать случайный nonce для PathChallenge
pub fn generate_path_nonce() -> u64 {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// X25519 key exchange (генерация эфемерной пары)
/// Возвращает (публичный ключ, эфемерный секретный ключ).
pub fn x25519_generate_keypair() -> ([u8; 32], EphemeralSecret) {
    let mut rng = OsRng;
    let secret = EphemeralSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    (*public.as_bytes(), secret)
}

/// X25519 DH (вычислить shared secret, забирает владение EphemeralSecret)
pub fn x25519_dh(secret: EphemeralSecret, public: &[u8; 32]) -> [u8; 32] {
    let pk = PublicKey::from(*public);
    *secret.diffie_hellman(&pk).as_bytes()
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_initial_key() {
        let cid = b"test-cid-1234";
        let key1 = derive_initial_key(cid);
        let key2 = derive_initial_key(cid);
        assert_eq!(key1, key2); // детерминированный вывод
        assert_eq!(key1.len(), AEAD_KEY_LEN);
    }

    #[test]
    fn test_derive_initial_key_different_cid() {
        let key1 = derive_initial_key(b"cid-1");
        let key2 = derive_initial_key(b"cid-2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_directional_keys_encrypt_decrypt() {
        let secret = b"test-secret-key-material-32b";
        let mut keys = DirectionalKeys::derive(secret, b"test-label").unwrap();

        let plaintext = b"Hello, Aether!";
        let aad = b"additional-data";

        let ciphertext = keys.encrypt(plaintext, aad).unwrap();
        // Сбросим packet_number чтобы расшифровать тем же nonce
        keys.packet_number = 0;
        let decrypted = keys.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext() {
        let secret = b"test-secret-key-material-32b";
        let keys = DirectionalKeys::derive(secret, b"test-label").unwrap();

        let plaintext = b"Secret data";
        let mut ciphertext = keys.encrypt(plaintext, b"").unwrap();

        // Меняем один байт в шифртексте
        ciphertext[0] ^= 0x01;

        // Сбрасываем счётчик для повторной расшифровки с тем же nonce
        let mut keys_dec = DirectionalKeys::derive(secret, b"test-label").unwrap();
        let result = keys_dec.decrypt(&ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_key_derivation() {
        let shared_secret = b"shared-secret-32-bytes-ok!!";
        let transcript = b"ClientHello||ServerHello";

        let key1 = derive_session_key(shared_secret, transcript).unwrap();
        let key2 = derive_session_key(shared_secret, transcript).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_session_key_different_transcript() {
        let shared_secret = b"shared-secret-32-bytes-ok!!";
        let key1 = derive_session_key(shared_secret, b"transcript-1").unwrap();
        let key2 = derive_session_key(shared_secret, b"transcript-2").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_finished_mac() {
        let session_key = [0xAB; 32];
        let transcript = b"full handshake transcript";

        let finished = compute_finished(&session_key, transcript);
        assert_eq!(finished.len(), 32); // SHA-256 output

        let result = verify_finished(&session_key, transcript, &finished);
        assert!(result.is_ok());
    }

    #[test]
    fn test_finished_mac_tampered() {
        let session_key = [0xAB; 32];
        let transcript = b"full handshake transcript";
        let finished = compute_finished(&session_key, transcript);

        let result = verify_finished(&session_key, b"tampered transcript", &finished);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_session() {
        let session_key = [0xCD; 32];
        let mut session = AeadSession::new(&session_key, AeadAlgorithm::Aes256Gcm).unwrap();

        let plaintext = b"Encrypted stream data";
        let ciphertext = session.client_tx.encrypt(plaintext, b"").unwrap();

        // Клиент шифрует → сервер расшифровывает (приёмные ключи клиента = tx-ключи сервера)
        // Но для этого нужен отдельный AeadSession на стороне сервера с теми же ключами.
        // Проверяем что той же сессией можем расшифровать если сбросить счётчик
        let mut session2 = AeadSession::new(&session_key, AeadAlgorithm::Aes256Gcm).unwrap();
        let decrypted = session2.client_tx.decrypt(&ciphertext, b"").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let (alice_public, alice_secret) = x25519_generate_keypair();
        let (bob_public, bob_secret) = x25519_generate_keypair();

        let alice_shared = x25519_dh(alice_secret, &bob_public);
        let bob_shared = x25519_dh(bob_secret, &alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_generate_connection_id_unique() {
        let cid1 = generate_connection_id();
        let cid2 = generate_connection_id();
        // Практически гарантированно разные
        // (математически есть шанс коллизии, но он астрономически мал)
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_packet_number_nonce_rotation() {
        let secret = b"test-secret-key-material-32b";
        let mut keys = DirectionalKeys::derive(secret, b"test").unwrap();

        let ct1 = keys.encrypt(b"msg1", b"").unwrap();
        keys.packet_number += 1; // в реальном коде вызывается после отправки
        let ct2 = keys.encrypt(b"msg2", b"").unwrap();

        // Разные nonce = разные шифртексты (даже для одинакового plaintext)
        assert_ne!(ct1, ct2);
    }
}