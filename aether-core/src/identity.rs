//! Self-sovereign Identity для Aether протокола
//!
//! В отличие от TCP/IP (IP-адрес) и TLS (X.509 сертификаты),
//! Aether использует криптографическую идентичность на основе Ed25519.
//!
//! ## Формат Identity
//!
//! ```text
//! identity = SHA-256("AETHER-ID-" || Ed25519_public_key)
//! ```
//!
//! Identity — это 32-байтовый хеш публичного ключа. Он не зависит от DNS, CA, PKI.
//! Переключение IP-адреса не меняет identity (мобильность).

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

/// Префикс для identity-хеша (доменное разделение)
const IDENTITY_PREFIX: &[u8] = b"AETHER-ID-";

/// Криптографическая identity узла Aether
///
/// Каждый узел имеет Ed25519 ключевую пару.
/// Identity = SHA-256("AETHER-ID-" || public_key)
#[derive(Clone)]
pub struct Identity {
    /// Приватный ключ Ed25519 (хранится в памяти, не сериализуется)
    signing_key: SigningKey,
    /// Публичный ключ Ed25519 (32 байта)
    public_key: VerifyingKey,
    /// Identity hash: SHA-256(prefix || public_key)
    identity_hash: [u8; 32],
}

impl Identity {
    /// Сгенерировать новую случайную identity
    ///
    /// Использует системный генератор случайных чисел (OsRng).
    ///
    /// # Пример
    ///
    /// ```rust
    /// use aether_core::Identity;
    /// let id = Identity::generate();
    /// println!("Identity: {}", id);
    /// ```
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key();
        let identity_hash = Self::compute_identity_hash(&public_key);

        Self {
            signing_key,
            public_key,
            identity_hash,
        }
    }

    /// Создать identity из существующего приватного ключа (32 байта seed)
    ///
    /// Ed25519 приватный ключ может быть представлен как 32-байтовый seed.
    ///
    /// # Безопасность
    ///
    /// Входной seed будет очищен из памяти (zeroize) после использования.
    ///
    /// ```rust
    /// use aether_core::Identity;
    /// let seed = [42u8; 32];
    /// let id = Identity::from_seed(seed);
    /// ```
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let public_key = signing_key.verifying_key();
        let identity_hash = Self::compute_identity_hash(&public_key);

        Self {
            signing_key,
            public_key,
            identity_hash,
        }
    }

    /// Получить 32-байтный хеш identity
    pub fn hash(&self) -> &[u8; 32] {
        &self.identity_hash
    }

    /// Получить идентификатор в виде hex-строки
    pub fn hash_hex(&self) -> String {
        hex::encode(self.identity_hash)
    }

    /// Получить публичный ключ Ed25519 (32 байта)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Подписать сообщение приватным ключом
    ///
    /// Используется для:
    /// - Доказательства владения identity (proof в handshake)
    /// - Подписи transcript'а соединения
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Проверить подпись (статический метод, не требует приватного ключа)
    ///
    /// Используется для проверки proof при handshake.
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &Signature) -> Result<()> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        vk.verify(message, signature)
            .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
    }

    /// Вычислить identity hash из публичного ключа
    fn compute_identity_hash(public_key: &VerifyingKey) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_PREFIX);
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Проверить, соответствует ли публичный ключ данному identity hash
    pub fn verify_hash(public_key: &[u8; 32], identity_hash: &[u8; 32]) -> Result<bool> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_PREFIX);
        hasher.update(vk.as_bytes());
        let computed: [u8; 32] = hasher.finalize().into();

        Ok(computed == *identity_hash)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hash_hex())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("hash", &self.hash_hex())
            .field("public_key", &hex::encode(self.public_key_bytes()))
            .finish_non_exhaustive() // не показываем signing_key
    }
}

// Zeroize приватный ключ при дропе
impl Drop for Identity {
    fn drop(&mut self) {
        // SigningKey уже реализует Drop с zeroize через ed25519-dalek
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.identity_hash == other.identity_hash
    }
}

impl Eq for Identity {}

impl std::hash::Hash for Identity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity_hash.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = Identity::generate();
        assert_eq!(id.hash().len(), 32);
        assert!(id.hash_hex().len() == 64);
    }

    #[test]
    fn test_from_seed_reproducible() {
        let seed = [42u8; 32];
        let id1 = Identity::from_seed(seed);
        let id2 = Identity::from_seed(seed);
        assert_eq!(id1.hash(), id2.hash());
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let id = Identity::generate();
        let message = b"Aether handshake transcript";
        let signature = id.sign(message);

        let result =
            Identity::verify(&id.public_key_bytes(), message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let id = Identity::generate();
        let signature = id.sign(b"original message");
        let result = Identity::verify(
            &id.public_key_bytes(),
            b"tampered message",
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_display() {
        let seed = [1u8; 32];
        let id = Identity::from_seed(seed);
        let display = format!("{}", id);
        assert_eq!(display.len(), 64); // hex строка 32 байт
        // Все символы должны быть hex
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_hash() {
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        let ih = id.hash();

        let result = Identity::verify_hash(&pk, ih);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let result = Identity::verify_hash(&id1.public_key_bytes(), id2.hash());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_unique_identities() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        assert_ne!(id1.hash(), id2.hash());
    }

    #[test]
    fn test_equality() {
        let seed = [99u8; 32];
        let id1 = Identity::from_seed(seed);
        let id2 = Identity::from_seed(seed);
        assert_eq!(id1, id2);
    }
}