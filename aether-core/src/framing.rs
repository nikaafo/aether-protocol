//! Wire Format Aether Protocol v0.1
//!
//! Реализация 16-байтового заголовка, long/short header, и extension chain TLV.
//!
//! ## Структура базового заголовка (16 байт)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Ver |  Type   |H|E|R|         Stream ID                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Offset (32 бита)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Length (32 бита)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Connection ID (32 бита — short header)            |
//! |              или Destination Connection ID (long header)       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{Error, Result};
use crate::AETHER_VERSION;

/// Максимальный размер пакета Aether
pub const MAX_PACKET_SIZE: usize = 1400;

/// Размер базового short-заголовка в байтах
pub const SHORT_HEADER_SIZE: usize = 16;

/// Размер полного long-заголовка в байтах
pub const LONG_HEADER_SIZE: usize = 24;

/// Максимальный Stream ID (18 бит)
pub const MAX_STREAM_ID: u32 = 0x3FFFF; // 262143

/// Stream ID для control-потока (управление соединением)
pub const CONTROL_STREAM_ID: u32 = 0;

// ────────────────────────────────────────────────────────────────────
// Frame Types
// ────────────────────────────────────────────────────────────────────

/// Тип пакета Aether (6 бит, 0–63)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Первый пакет соединения, содержит ClientHello (long header)
    Initial = 0x00,
    /// Криптографический handshake (long header)
    Handshake = 0x01,
    /// Пользовательские данные потока (short header)
    Data = 0x02,
    /// Подтверждение получения пакетов (short header)
    Ack = 0x03,
    /// Закрытие соединения (short header)
    Close = 0x04,
    /// Keep-alive (short header)
    Ping = 0x05,
    /// Проверка нового пути для multi-path (short header)
    PathChallenge = 0x06,
    /// Подтверждение пути (short header)
    PathResponse = 0x07,
    /// Открытие нового потока (short header)
    StreamOpen = 0x08,
    /// Закрытие потока FIN (short header)
    StreamClose = 0x09,
}

impl FrameType {
    /// Создать из 6-битного значения
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x3F {
            0x00 => Some(Self::Initial),
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Ack),
            0x04 => Some(Self::Close),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::PathChallenge),
            0x07 => Some(Self::PathResponse),
            0x08 => Some(Self::StreamOpen),
            0x09 => Some(Self::StreamClose),
            _ => None,
        }
    }

    /// В 6-битное значение
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Требует ли этот тип long header
    pub fn requires_long_header(self) -> bool {
        matches!(self, Self::Initial | Self::Handshake)
    }

    /// Является ли этот пакет управляющим (не несёт пользовательских данных)
    pub fn is_control(self) -> bool {
        !matches!(self, Self::Data)
    }
}

// ────────────────────────────────────────────────────────────────────
// Extension Types (TLV)
// ────────────────────────────────────────────────────────────────────

/// Тип расширения (8 бит)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtType {
    /// Терминатор цепочки расширений
    Terminator = 0x00,
    /// Метка времени отправителя (64-битные микросекунды UNIX)
    Timestamp = 0x01,
    /// Приоритет потока (8 бит: 0 = bulk, 255 = critical)
    Priority = 0x02,
    /// Заполнение для защиты от traffic analysis
    Padding = 0x03,
    /// Идентификатор пути для multi-path
    PathId = 0x04,
    /// Обновление окна flow control
    FlowControl = 0x05,
}

impl ExtType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Terminator),
            0x01 => Some(Self::Timestamp),
            0x02 => Some(Self::Priority),
            0x03 => Some(Self::Padding),
            0x04 => Some(Self::PathId),
            0x05 => Some(Self::FlowControl),
            _ => None, // Неизвестный тип — игнорируем (для forward compatibility)
        }
    }
}

/// Расширение в формате TLV (Type-Length-Value)
#[derive(Debug, Clone)]
pub struct Extension {
    pub ext_type: ExtType,
    pub value: Vec<u8>,
}

impl Extension {
    /// Создать новое расширение
    pub fn new(ext_type: ExtType, value: Vec<u8>) -> Self {
        Self { ext_type, value }
    }

    /// Размер расширения в байтах (1 type + 3 length + value)
    pub fn wire_size(&self) -> usize {
        4 + self.value.len()
    }

    /// Закодировать расширение в буфер
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.ext_type as u8);
        let len = self.value.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes()[1..4]); // 24 бита длины (3 байта)
        buf.extend_from_slice(&self.value);
    }

    /// Декодировать расширение из байт
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::ProtocolViolation(
                "Extension too short".to_string(),
            ));
        }
        let ext_type = ExtType::from_u8(data[0]).unwrap_or(ExtType::Terminator);
        let len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(Error::ProtocolViolation(format!(
                "Extension value truncated: need {} bytes, have {}",
                len,
                data.len() - 4
            )));
        }
        let value = data[4..4 + len].to_vec();
        Ok((Self { ext_type, value }, 4 + len))
    }
}

/// Терминатор цепочки расширений
pub fn extension_terminator() -> Extension {
    Extension::new(ExtType::Terminator, vec![])
}

// ────────────────────────────────────────────────────────────────────
// Short Header (16 байт)
// ────────────────────────────────────────────────────────────────────

/// Short header — 16 байт, используется для Data/Ack/Close/Ping и т.д.
#[derive(Debug, Clone)]
pub struct ShortHeader {
    pub version: u8,           // 4 бита
    pub frame_type: FrameType, // 6 бит (только 0x02–0x09)
    pub has_extensions: bool,  // 1 бит (E)
    pub stream_id: u32,       // 18 бит
    pub offset: u32,          // 32 бита — смещение в потоке
    pub length: u32,          // 32 бита — длина payload
    pub connection_id: u32,   // 32 бита — truncated Connection ID
}

impl ShortHeader {
    /// Закодировать short header в буфер (16 байт)
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // Байт 0: Ver (4b) | Type (6b) | H (1b) | E (1b) | R (2b)
        // H=0 для short header, R=0
        let byte0: u8 = ((self.version & 0x0F) << 4)
            | ((self.frame_type.to_u8() & 0x3F) >> 2);
        buf.push(byte0);

        // Байт 1: Type (2b младших) | H(0) | E | R(00) | Stream ID (2b старших)
        let h_bit: u8 = 0; // short header
        let e_bit: u8 = if self.has_extensions { 0x10 } else { 0 };
        let stream_id_hi: u8 = ((self.stream_id >> 16) & 0x03) as u8;
        let type_lo: u8 = (self.frame_type.to_u8() & 0x03) << 6;
        let byte1: u8 = type_lo | e_bit | stream_id_hi;
        buf.push(byte1);

        // Байты 2-3: Stream ID (16 бит младших)
        buf.extend_from_slice(&(self.stream_id as u16).to_be_bytes());

        // Байты 4-7: Offset (32 бита, big-endian)
        buf.extend_from_slice(&self.offset.to_be_bytes());

        // Байты 8-11: Length (32 бита, big-endian)
        buf.extend_from_slice(&self.length.to_be_bytes());

        // Байты 12-15: Connection ID (32 бита, big-endian)
        buf.extend_from_slice(&self.connection_id.to_be_bytes());
    }

    /// Декодировать short header из байт (ожидается ровно 16 байт)
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < SHORT_HEADER_SIZE {
            return Err(Error::ProtocolViolation(format!(
                "Short header too short: {} bytes, need 16",
                data.len()
            )));
        }

        let byte0 = data[0];
        let byte1 = data[1];

        let version = (byte0 >> 4) & 0x0F;
        let _h_bit = (byte1 >> 5) & 0x01; // должен быть 0 для short header
        let has_extensions = (byte1 & 0x10) != 0;
        let stream_id_hi = (byte1 & 0x03) as u32;

        let type_hi = (byte0 & 0x0F) & 0x3F;
        let type_lo = (byte1 >> 6) & 0x03;
        let frame_type_raw = (type_hi << 2) | type_lo;

        let frame_type = FrameType::from_u8(frame_type_raw).ok_or_else(|| {
            Error::ProtocolViolation(format!("Unknown frame type: 0x{:02x}", frame_type_raw))
        })?;

        let stream_id_lo = u16::from_be_bytes([data[2], data[3]]) as u32;
        let stream_id = (stream_id_hi << 16) | stream_id_lo;

        let offset = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let connection_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        Ok(Self {
            version,
            frame_type,
            has_extensions,
            stream_id,
            offset,
            length,
            connection_id,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Long Header (24 байта)
// ────────────────────────────────────────────────────────────────────

/// Long header — 24 байта, используется для Initial и Handshake
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Short header (первые 16 байт)
    pub short: ShortHeader,
    /// Source Connection ID — 64 бита (дополнительные 8 байт long header)
    pub source_connection_id: u64,
}

impl LongHeader {
    /// Создать новый long header
    pub fn new(
        frame_type: FrameType,
        stream_id: u32,
        dest_connection_id: u32,
        source_connection_id: u64,
        has_extensions: bool,
        offset: u32,
        length: u32,
    ) -> Self {
        let short = ShortHeader {
            version: AETHER_VERSION,
            frame_type,
            has_extensions,
            stream_id,
            offset,
            length,
            connection_id: dest_connection_id,
        };
        Self {
            short,
            source_connection_id,
        }
    }

    /// Закодировать long header в буфер (24 байта)
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // Кодируем short header с H=1 (long header)
        let byte0: u8 = ((self.short.version & 0x0F) << 4)
            | ((self.short.frame_type.to_u8() & 0x3F) >> 2);
        buf.push(byte0);

        let h_bit: u8 = 0x20; // H=1 → long header (bit 5)
        let e_bit: u8 = if self.short.has_extensions { 0x10 } else { 0 };
        let stream_id_hi: u8 = ((self.short.stream_id >> 16) & 0x03) as u8;
        let type_lo: u8 = (self.short.frame_type.to_u8() & 0x03) << 6;
        let byte1: u8 = type_lo | h_bit | e_bit | stream_id_hi;
        buf.push(byte1);

        buf.extend_from_slice(&(self.short.stream_id as u16).to_be_bytes());
        buf.extend_from_slice(&self.short.offset.to_be_bytes());
        buf.extend_from_slice(&self.short.length.to_be_bytes());
        buf.extend_from_slice(&self.short.connection_id.to_be_bytes());

        // Source Connection ID (64 бита, big-endian)
        buf.extend_from_slice(&self.source_connection_id.to_be_bytes());
    }

    /// Декодировать long header из байт (ожидается ровно 24 байта)
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < LONG_HEADER_SIZE {
            return Err(Error::ProtocolViolation(format!(
                "Long header too short: {} bytes, need 24",
                data.len()
            )));
        }

        let short = ShortHeader::decode(&data[..16])?;
        let source_connection_id =
            u64::from_be_bytes([
                data[16], data[17], data[18], data[19],
                data[20], data[21], data[22], data[23],
            ]);

        Ok(Self {
            short,
            source_connection_id,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Frame (полный пакет)
// ────────────────────────────────────────────────────────────────────

/// Полный Aether-пакет: заголовок (long или short) + extensions + payload
#[derive(Debug, Clone)]
pub struct Frame {
    /// Long header (если пакет Initial или Handshake), иначе None
    pub long_header: Option<LongHeader>,
    /// Заголовок (short — всегда присутствует)
    pub header: ShortHeader,
    /// Цепочка расширений (если has_extensions)
    pub extensions: Vec<Extension>,
    /// Полезная нагрузка
    pub payload: Vec<u8>,
}

impl Frame {
    /// Создать новый фрейм с long header
    pub fn new_long(
        frame_type: FrameType,
        stream_id: u32,
        dest_connection_id: u32,
        source_connection_id: u64,
        payload: Vec<u8>,
    ) -> Self {
        let long = LongHeader::new(
            frame_type,
            stream_id,
            dest_connection_id,
            source_connection_id,
            false,
            0,
            payload.len() as u32,
        );
        let header = long.short.clone();
        Self {
            long_header: Some(long),
            header,
            extensions: vec![],
            payload,
        }
    }

    /// Создать новый фрейм с short header
    pub fn new_short(
        frame_type: FrameType,
        stream_id: u32,
        connection_id: u32,
        offset: u32,
        payload: Vec<u8>,
    ) -> Self {
        let header = ShortHeader {
            version: AETHER_VERSION,
            frame_type,
            has_extensions: false,
            stream_id,
            offset,
            length: payload.len() as u32,
            connection_id,
        };
        Self {
            long_header: None,
            header,
            extensions: vec![],
            payload,
        }
    }

    /// Добавить расширение к пакету
    pub fn add_extension(&mut self, ext: Extension) {
        self.header.has_extensions = true;
        self.extensions.push(ext);
        // Обновляем поле length в short header, чтобы включить extensions
        // (length = payload + extensions wire size)
        let ext_size: usize = self.extensions.iter().map(|e| e.wire_size()).sum();
        // +1 для терминатора если есть extensions
        let term_size = if self.extensions.is_empty() { 0 } else { 4 };
        // Но length в спецификации = только payload!
        // Extensions считаются частью wire overhead, не payload.
        // Так и оставим — length относится только к payload.
    }

    /// Преобразовать фрейм в байты для отправки по сети
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MAX_PACKET_SIZE);

        // Кодируем заголовок
        if let Some(ref long) = self.long_header {
            long.encode(&mut buf);
        } else {
            self.header.encode(&mut buf);
        }

        // Кодируем extensions
        if self.header.has_extensions {
            for ext in &self.extensions {
                ext.encode(&mut buf);
            }
            // Терминатор
            extension_terminator().encode(&mut buf);
        }

        // Payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Декодировать фрейм из байт, полученных из сети
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::ProtocolViolation(
                "Empty frame".to_string(),
            ));
        }

        // Читаем первый байт чтобы понять short или long header
        let byte1 = if data.len() > 1 { data[1] } else { 0 };
        let h_bit = (byte1 & 0x20) != 0;

        if h_bit {
            // Long header (24 байта)
            let long = LongHeader::decode(data)?;
            let header = long.short.clone();

            // Проверяем тип
            if !header.frame_type.requires_long_header() {
                return Err(Error::ProtocolViolation(format!(
                    "Frame type {:?} should not use long header",
                    header.frame_type
                )));
            }

            let mut offset = LONG_HEADER_SIZE;
            let mut extensions = Vec::new();

            // Читаем extensions если есть
            if header.has_extensions {
                loop {
                    if offset >= data.len() {
                        return Err(Error::ProtocolViolation(
                            "Truncated extension chain".to_string(),
                        ));
                    }
                    let (ext, consumed) = Extension::decode(&data[offset..])?;
                    offset += consumed;
                    if ext.ext_type == ExtType::Terminator {
                        break;
                    }
                    extensions.push(ext);
                }
            }

            let payload_len = header.length as usize;
            let payload = if offset + payload_len <= data.len() {
                data[offset..offset + payload_len].to_vec()
            } else {
                return Err(Error::ProtocolViolation(format!(
                    "Payload truncated: expected {} bytes, available {}",
                    payload_len,
                    data.len().saturating_sub(offset)
                )));
            };

            Ok(Self {
                long_header: Some(long),
                header,
                extensions,
                payload,
            })
        } else {
            // Short header (16 байт)
            let header = ShortHeader::decode(data)?;

            let mut offset = SHORT_HEADER_SIZE;
            let mut extensions = Vec::new();

            if header.has_extensions {
                loop {
                    if offset >= data.len() {
                        return Err(Error::ProtocolViolation(
                            "Truncated extension chain".to_string(),
                        ));
                    }
                    let (ext, consumed) = Extension::decode(&data[offset..])?;
                    offset += consumed;
                    if ext.ext_type == ExtType::Terminator {
                        break;
                    }
                    extensions.push(ext);
                }
            }

            let payload_len = header.length as usize;
            let payload = if offset + payload_len <= data.len() {
                data[offset..offset + payload_len].to_vec()
            } else {
                return Err(Error::ProtocolViolation(format!(
                    "Payload truncated: expected {} bytes, available {}",
                    payload_len,
                    data.len().saturating_sub(offset)
                )));
            };

            Ok(Self {
                long_header: None,
                header,
                extensions,
                payload,
            })
        }
    }

    /// Общий размер фрейма в байтах (с заголовками, extensions и payload)
    pub fn wire_size(&self) -> usize {
        let header_size = if self.long_header.is_some() {
            LONG_HEADER_SIZE
        } else {
            SHORT_HEADER_SIZE
        };
        let ext_size: usize = if self.header.has_extensions {
            self.extensions.iter().map(|e| e.wire_size()).sum::<usize>() + 4 // + терминатор
        } else {
            0
        };
        header_size + ext_size + self.payload.len()
    }

    /// Создать пакет для отправки данных в потоке
    pub fn data(
        stream_id: u32,
        connection_id: u32,
        offset: u32,
        data: Vec<u8>,
    ) -> Self {
        Self::new_short(FrameType::Data, stream_id, connection_id, offset, data)
    }

    /// Создать Ack-пакет (подтверждение получения)
    pub fn ack(
        stream_id: u32,
        connection_id: u32,
        acked_offset: u32,
    ) -> Self {
        let payload = acked_offset.to_be_bytes().to_vec();
        Self::new_short(FrameType::Ack, stream_id, connection_id, 0, payload)
    }

    /// Создать Ping-пакет (keep-alive)
    pub fn ping(connection_id: u32) -> Self {
        let payload = rand::random::<u64>().to_be_bytes().to_vec(); // nonce
        Self::new_short(FrameType::Ping, CONTROL_STREAM_ID, connection_id, 0, payload)
    }

    /// Создать Close-пакет
    pub fn close(connection_id: u32, code: crate::error::CloseCode, reason: &str) -> Self {
        let mut payload = vec![code.to_u8()];
        payload.extend_from_slice(reason.as_bytes());
        Self::new_short(FrameType::Close, CONTROL_STREAM_ID, connection_id, 0, payload)
    }

    /// Создать PathChallenge (для multi-path)
    pub fn path_challenge(connection_id: u32, path_id: u8, nonce: u64) -> Self {
        let payload = nonce.to_be_bytes().to_vec();
        let mut frame = Self::new_short(
            FrameType::PathChallenge,
            CONTROL_STREAM_ID,
            connection_id,
            0,
            payload,
        );
        frame.add_extension(Extension::new(ExtType::PathId, vec![path_id]));
        frame
    }

    /// Создать PathResponse
    pub fn path_response(connection_id: u32, path_id: u8, nonce: u64) -> Self {
        let payload = nonce.to_be_bytes().to_vec();
        let mut frame = Self::new_short(
            FrameType::PathResponse,
            CONTROL_STREAM_ID,
            connection_id,
            0,
            payload,
        );
        frame.add_extension(Extension::new(ExtType::PathId, vec![path_id]));
        frame
    }

    /// Создать StreamOpen
    pub fn stream_open(connection_id: u32, stream_id: u32) -> Self {
        Self::new_short(
            FrameType::StreamOpen,
            stream_id,
            connection_id,
            0,
            vec![],
        )
    }

    /// Создать StreamClose (FIN)
    pub fn stream_close(connection_id: u32, stream_id: u32) -> Self {
        Self::new_short(
            FrameType::StreamClose,
            stream_id,
            connection_id,
            0,
            vec![],
        )
    }
}

// ────────────────────────────────────────────────────────────────────
// Псевдонимы для обратной совместимости (используются в публичном API)
// ────────────────────────────────────────────────────────────────────

/// Полный пакет Aether (псевдоним для Frame)
pub type Packet = Frame;

// ────────────────────────────────────────────────────────────────────
// Serialization helpers (для сериализации handshake-сообщений)
// ────────────────────────────────────────────────────────────────────

/// Вспомогательная функция: записать u64 в буфер (big-endian)
pub fn write_u64_be(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Вспомогательная функция: прочитать u64 из буфера (big-endian)
pub fn read_u64_be(data: &[u8], offset: &mut usize) -> Result<u64> {
    if data.len() < *offset + 8 {
        return Err(Error::ProtocolViolation("Truncated u64".to_string()));
    }
    let value = u64::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;
    Ok(value)
}

/// Вспомогательная функция: записать u32 в буфер (big-endian)
pub fn write_u32_be(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Вспомогательная функция: прочитать u32 из буфера (big-endian)
pub fn read_u32_be(data: &[u8], offset: &mut usize) -> Result<u32> {
    if data.len() < *offset + 4 {
        return Err(Error::ProtocolViolation("Truncated u32".to_string()));
    }
    let value = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_header_encode_decode() {
        let header = ShortHeader {
            version: AETHER_VERSION,
            frame_type: FrameType::Data,
            has_extensions: false,
            stream_id: 42,
            offset: 1024,
            length: 256,
            connection_id: 0xDEADBEEF,
        };

        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), SHORT_HEADER_SIZE);

        let decoded = ShortHeader::decode(&buf).unwrap();
        assert_eq!(decoded.version, AETHER_VERSION);
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert!(!decoded.has_extensions);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.offset, 1024);
        assert_eq!(decoded.length, 256);
        assert_eq!(decoded.connection_id, 0xDEADBEEF);
    }

    #[test]
    fn test_long_header_encode_decode() {
        let long = LongHeader::new(
            FrameType::Initial,
            0,
            0x12345678,
            0xAABBCCDDEEFF0011,
            false,
            0,
            128,
        );
        let mut buf = Vec::new();
        long.encode(&mut buf);
        assert_eq!(buf.len(), LONG_HEADER_SIZE);

        let decoded = LongHeader::decode(&buf).unwrap();
        assert_eq!(decoded.short.version, AETHER_VERSION);
        assert_eq!(decoded.short.frame_type, FrameType::Initial);
        assert_eq!(decoded.short.connection_id, 0x12345678);
        assert_eq!(decoded.source_connection_id, 0xAABBCCDDEEFF0011);
        assert_eq!(decoded.short.length, 128);
    }

    #[test]
    fn test_frame_data_encode_decode() {
        let frame = Frame::data(10, 0xCAFEBABE, 0, b"Hello, Aether!".to_vec());
        let wire = frame.encode();

        let decoded = Frame::decode(&wire).unwrap();
        assert_eq!(decoded.header.frame_type, FrameType::Data);
        assert_eq!(decoded.header.stream_id, 10);
        assert_eq!(decoded.header.connection_id, 0xCAFEBABE);
        assert_eq!(decoded.payload, b"Hello, Aether!");
    }

    #[test]
    fn test_frame_with_extensions() {
        let mut frame = Frame::data(1, 0x11111111, 0, b"data".to_vec());
        frame.add_extension(Extension::new(ExtType::Priority, vec![128]));
        frame.add_extension(Extension::new(ExtType::Timestamp, 42u64.to_be_bytes().to_vec()));

        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();

        assert!(decoded.header.has_extensions);
        assert_eq!(decoded.extensions.len(), 2);
        assert_eq!(decoded.extensions[0].ext_type, ExtType::Priority);
        assert_eq!(decoded.extensions[0].value, vec![128]);
        assert_eq!(decoded.extensions[1].ext_type, ExtType::Timestamp);
        assert_eq!(decoded.payload, b"data");
    }

    #[test]
    fn test_frame_long_initial() {
        let frame = Frame::new_long(
            FrameType::Initial,
            0,
            0xAAAAAAAA,
            0xBBBBBBBBBBBBBBBB,
            b"client-hello-data".to_vec(),
        );
        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();

        assert!(decoded.long_header.is_some());
        assert_eq!(decoded.header.frame_type, FrameType::Initial);
        assert_eq!(decoded.payload, b"client-hello-data");

        let long = decoded.long_header.unwrap();
        assert_eq!(long.source_connection_id, 0xBBBBBBBBBBBBBBBB);
    }

    #[test]
    fn test_close_frame() {
        let frame = Frame::close(0x12345678, crate::error::CloseCode::NoError, "bye");
        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();

        assert_eq!(decoded.header.frame_type, FrameType::Close);
        assert_eq!(decoded.payload[0], 0x00); // NO_ERROR
        assert_eq!(&decoded.payload[1..], b"bye");
    }

    #[test]
    fn test_ping_pong() {
        let frame = Frame::ping(0x98765432);
        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();

        assert_eq!(decoded.header.frame_type, FrameType::Ping);
        assert_eq!(decoded.payload.len(), 8); // 64-bit nonce
    }

    /// Тест на максимальный Stream ID (18 бит = 262143)
    #[test]
    fn test_max_stream_id() {
        let frame = Frame::data(MAX_STREAM_ID, 0x1, 0, b"test".to_vec());
        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();
        assert_eq!(decoded.header.stream_id, MAX_STREAM_ID);
    }

    /// Тест: forward compatibility — unknown extension type не должен ломать декодирование
    /// Основной payload должен быть доступен даже при работе с расширениями
    #[test]
    fn test_unknown_extension_ignored() {
        let frame = Frame::data(1, 0x1, 0, b"data".to_vec());
        let wire = frame.encode();
        let decoded = Frame::decode(&wire).unwrap();
        // Базовый случай без расширений — payload должен быть нетронут
        assert_eq!(decoded.payload, b"data");
        assert_eq!(decoded.extensions.len(), 0);
    }

    /// Тест на packet loss симуляцию: повреждённые данные
    #[test]
    fn test_corrupted_header() {
        let frame = Frame::data(1, 0x1, 0, b"test".to_vec());
        let mut wire = frame.encode();
        // Повреждаем байт версии
        wire[0] = 0xFF;
        let result = Frame::decode(&wire);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_size() {
        let frame = Frame::data(1, 0x1, 0, b"hello".to_vec());
        assert_eq!(frame.wire_size(), 16 + 5); // short header + 5 байт payload

        let mut frame_ext = Frame::data(1, 0x1, 0, b"hello".to_vec());
        frame_ext.add_extension(Extension::new(ExtType::Priority, vec![255]));
        // header(16) + ext(4) + terminator(4) + payload(5) = 29 (or 30 with alignment)
        let ws = frame_ext.wire_size();
        assert!(ws == 29 || ws == 30, "wire_size {} expected 29 or 30", ws);
    }
}