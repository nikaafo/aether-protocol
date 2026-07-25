use std::fmt;
use std::io;

/// Основной тип ошибки Aether протокола
#[derive(Debug)]
pub enum Error {
    /// Ошибка ввода-вывода (сеть, файл)
    Io(io::Error),
    /// Нарушение wire format: некорректный заголовок, битые данные
    ProtocolViolation(String),
    /// Криптографическая ошибка: неверный ключ, расшифровка не удалась
    Crypto(String),
    /// Превышен лимит flow control
    FlowControl(String),
    /// Таймаут соединения или операции
    Timeout(String),
    /// Несовместимая версия протокола
    VersionNegotiation(String),
    /// Соединение закрыто (нормально или с ошибкой)
    ConnectionClosed(CloseCode, String),
    /// Поток закрыт
    StreamClosed(StreamId, String),
    /// Идентичность не принята пиром
    IdentityRejected(String),
    /// Некорректное состояние (операция невозможна в текущем состоянии)
    InvalidState(String),
    /// Превышен максимальный размер пакета
    PacketTooLarge { size: usize, max: usize },
    /// Внутренняя ошибка (не должно случаться)
    Internal(String),
}

/// Код закрытия соединения (соответствует спецификации)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseCode {
    NoError = 0x00,
    InternalError = 0x01,
    ProtocolViolation = 0x02,
    CryptoError = 0x03,
    FlowControlError = 0x04,
    Timeout = 0x05,
    VersionNegotiation = 0x06,
    Refused = 0x07,
    IdentityRejected = 0x08,
}

impl CloseCode {
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InternalError),
            0x02 => Some(Self::ProtocolViolation),
            0x03 => Some(Self::CryptoError),
            0x04 => Some(Self::FlowControlError),
            0x05 => Some(Self::Timeout),
            0x06 => Some(Self::VersionNegotiation),
            0x07 => Some(Self::Refused),
            0x08 => Some(Self::IdentityRejected),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NO_ERROR"),
            Self::InternalError => write!(f, "INTERNAL_ERROR"),
            Self::ProtocolViolation => write!(f, "PROTOCOL_VIOLATION"),
            Self::CryptoError => write!(f, "CRYPTO_ERROR"),
            Self::FlowControlError => write!(f, "FLOW_CONTROL_ERROR"),
            Self::Timeout => write!(f, "TIMEOUT"),
            Self::VersionNegotiation => write!(f, "VERSION_NEGOTIATION"),
            Self::Refused => write!(f, "REFUSED"),
            Self::IdentityRejected => write!(f, "IDENTITY_REJECTED"),
        }
    }
}

/// Stream ID (18 бит, 0–262143)
pub type StreamId = u32;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            Self::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Self::FlowControl(msg) => write!(f, "Flow control: {}", msg),
            Self::Timeout(msg) => write!(f, "Timeout: {}", msg),
            Self::VersionNegotiation(msg) => write!(f, "Version negotiation: {}", msg),
            Self::ConnectionClosed(code, msg) => {
                write!(f, "Connection closed ({:?}): {}", code, msg)
            }
            Self::StreamClosed(id, msg) => write!(f, "Stream {} closed: {}", id, msg),
            Self::IdentityRejected(msg) => write!(f, "Identity rejected: {}", msg),
            Self::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            Self::PacketTooLarge { size, max } => {
                write!(f, "Packet too large: {} bytes (max {})", size, max)
            }
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Тип результата для всех операций Aether
pub type Result<T> = std::result::Result<T, Error>;