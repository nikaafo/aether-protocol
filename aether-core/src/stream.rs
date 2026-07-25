//! Управление потоками (Streams) Aether Protocol
//!
//! Потоки — это независимые каналы данных внутри одного соединения.
//! Каждый поток идентифицируется 18-битным Stream ID.
//!
//! ## Модель потоков
//!
//! - Stream ID 0 зарезервирован для control-потока (управление соединением)
//! - Клиент открывает потоки с чётными ID (2, 4, 6, ...)
//! - Сервер открывает потоки с нечётными ID (1, 3, 5, ...)
//! - Потоки независимы: потеря пакета в одном не блокирует остальные
//!
//! ## Жизненный цикл потока
//!
//! ```text
//! IDLE → (StreamOpen) → OPEN → (Data/Ack) → OPEN
//! OPEN → (StreamClose FIN) → HALF_CLOSED → (StreamClose ACK) → CLOSED
//! ```

use crate::error::{Error, Result};
use crate::framing::Frame;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Stream ID (18 бит, 0–262143)
pub type StreamId = u32;

/// Максимальный Stream ID
pub const MAX_STREAM_ID: StreamId = 0x3FFFF;

/// Stream ID для control-потока
pub const CONTROL_STREAM_ID: StreamId = 0;

/// Состояние потока
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Поток не открыт
    Idle,
    /// Поток открыт, можно читать и писать
    Open,
    /// Локальная сторона отправила FIN (закрыла запись)
    HalfClosedLocal,
    /// Удалённая сторона отправила FIN (закрыла чтение)
    HalfClosedRemote,
    /// Поток полностью закрыт
    Closed,
}

impl StreamState {
    /// Можно ли писать в этом состоянии
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Можно ли читать в этом состоянии
    pub fn can_read(&self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    /// Поток полностью закрыт?
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Настройки flow control для потока
#[derive(Debug, Clone)]
pub struct FlowControl {
    /// Максимальное смещение, которое получатель разрешил отправить
    pub max_offset: u64,
    /// Смещение, до которого данные уже получены
    pub received_offset: u64,
    /// Смещение, до которого данные уже отправлены
    pub sent_offset: u64,
    /// Максимальное окно (начальное значение)
    pub max_window: u64,
}

impl FlowControl {
    /// Создать новый flow control с указанным максимальным окном
    pub fn new(max_window: u64) -> Self {
        Self {
            max_offset: max_window,
            received_offset: 0,
            sent_offset: 0,
            max_window,
        }
    }

    /// Можно ли отправить ещё data_len байт?
    pub fn can_send(&self, data_len: usize) -> bool {
        (self.sent_offset + data_len as u64) <= self.max_offset
    }

    /// Зарезервировать место для отправки data_len байт
    pub fn reserve_send(&mut self, data_len: usize) -> u32 {
        let offset = self.sent_offset as u32;
        self.sent_offset += data_len as u64;
        offset
    }

    /// Обновить окно (получатель разрешает отправить больше)
    pub fn update_window(&mut self, new_max: u64) {
        if new_max > self.max_offset {
            self.max_offset = new_max;
        }
    }

    /// Зарегистрировать полученные данные
    pub fn received(&mut self, offset: u32, length: u32) {
        let end = offset as u64 + length as u64;
        if end > self.received_offset {
            self.received_offset = end;
        }
    }

    /// Сколько ещё можно отправить (размер окна)
    pub fn available_window(&self) -> u64 {
        self.max_offset.saturating_sub(self.sent_offset)
    }
}

/// Поток данных внутри Aether-соединения
#[derive(Debug)]
pub struct Stream {
    /// Идентификатор потока
    pub id: StreamId,
    /// Текущее состояние
    pub state: StreamState,
    /// Flow control
    pub flow_control: FlowControl,
    /// Буфер полученных данных (храним фрагменты по offset'ам)
    receive_buffer: Vec<(u32, Vec<u8>)>,
    /// Клиентский поток (чётный ID)?
    pub is_client: bool,
}

impl Stream {
    /// Создать новый поток (на стороне отправителя)
    pub fn new(id: StreamId, is_client: bool, max_stream_window: u64) -> Self {
        Self {
            id,
            state: StreamState::Open,
            flow_control: FlowControl::new(max_stream_window),
            receive_buffer: Vec::new(),
            is_client,
        }
    }

    /// Закрыть запись (отправить FIN)
    pub fn close_write(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Закрыть чтение (получить FIN от пира)
    pub fn close_read(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Записать данные в поток (возвращает offset для framing)
    pub fn write(&mut self, data: Vec<u8>) -> Result<u32> {
        if !self.state.can_write() {
            return Err(Error::InvalidState(format!(
                "Stream {} is in state {:?}, cannot write",
                self.id, self.state
            )));
        }
        if !self.flow_control.can_send(data.len()) {
            return Err(Error::FlowControl(format!(
                "Stream {} flow control limit reached: sent={}, max={}, trying to send {}",
                self.id, self.flow_control.sent_offset, self.flow_control.max_offset, data.len()
            )));
        }
        let offset = self.flow_control.reserve_send(data.len());
        Ok(offset)
    }

    /// Получить данные из буфера получения
    pub fn read(&mut self, max_len: usize) -> Result<Vec<u8>> {
        if !self.state.can_read() && self.receive_buffer.is_empty() {
            return Err(Error::InvalidState(format!(
                "Stream {} is in state {:?}, cannot read",
                self.id, self.state
            )));
        }

        if self.receive_buffer.is_empty() {
            return Ok(Vec::new());
        }

        // Сортируем по offset
        self.receive_buffer.sort_by_key(|(offset, _)| *offset);

        // Проверяем что первый фрагмент начинается с 0
        if self.receive_buffer[0].0 != 0 {
            // Есть дыра — ждём недостающие данные
            return Ok(Vec::new());
        }

        // Собираем непрерывные фрагменты
        let mut result = Vec::with_capacity(max_len);
        let mut expected_offset = 0u32;
        let mut consumed = 0usize;

        for (offset, data) in &self.receive_buffer {
            if *offset != expected_offset {
                break; // Дыра в данных
            }
            result.extend_from_slice(data);
            expected_offset += data.len() as u32;
            consumed += 1;
            if result.len() >= max_len {
                break;
            }
        }

        // Удаляем потреблённые фрагменты
        self.receive_buffer.drain(0..consumed);

        Ok(result)
    }

    /// Добавить полученные данные в буфер
    pub fn receive_data(&mut self, offset: u32, data: Vec<u8>) {
        let len = data.len() as u32;
        self.receive_buffer.push((offset, data));
        self.flow_control.received(offset, len);
    }
}

/// Менеджер потоков для соединения
#[derive(Debug)]
pub struct StreamManager {
    /// Активные потоки (ключ — Stream ID)
    streams: HashMap<StreamId, Stream>,
    /// Следующий Stream ID для открытия (чётный для клиента)
    next_client_stream_id: StreamId,
    /// Следующий Stream ID для открытия (нечётный для сервера)
    next_server_stream_id: StreamId,
    /// Максимальное количество потоков
    max_streams: u32,
    /// Начальное окно для новых потоков
    initial_stream_window: u64,
    /// Максимальные данные в полёте для соединения
    connection_flow_window: u64,
    /// Отправлено всего байт через все потоки
    connection_sent: u64,
    /// Мы клиент?
    pub is_client: bool,
}

impl StreamManager {
    /// Создать новый StreamManager
    pub fn new(is_client: bool, max_streams: u32, initial_stream_window: u64, connection_flow_window: u64) -> Self {
        Self {
            streams: HashMap::new(),
            next_client_stream_id: if is_client { 2 } else { 0 },
            next_server_stream_id: if is_client { 0 } else { 1 },
            max_streams,
            initial_stream_window,
            connection_flow_window,
            connection_sent: 0,
            is_client,
        }
    }

    /// Открыть новый поток (возвращает Stream ID)
    pub fn open_stream(&mut self) -> Result<StreamId> {
        if self.streams.len() >= self.max_streams as usize {
            return Err(Error::FlowControl(format!(
                "Maximum streams reached: {}",
                self.max_streams
            )));
        }

        let stream_id = if self.is_client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id += 2;
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id += 2;
            id
        };

        if stream_id > MAX_STREAM_ID {
            return Err(Error::FlowControl("Stream ID exhausted".to_string()));
        }

        let stream = Stream::new(stream_id, self.is_client, self.initial_stream_window);
        self.streams.insert(stream_id, stream);

        Ok(stream_id)
    }

    /// Принять входящий поток (от удалённой стороны)
    pub fn accept_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if self.streams.contains_key(&stream_id) {
            return Err(Error::ProtocolViolation(format!(
                "Stream {} already exists",
                stream_id
            )));
        }
        let is_client = stream_id % 2 == 0;
        let stream = Stream::new(stream_id, is_client, self.initial_stream_window);
        self.streams.insert(stream_id, stream);
        Ok(())
    }

    /// Получить ссылку на поток
    pub fn get_stream(&self, stream_id: StreamId) -> Result<&Stream> {
        self.streams.get(&stream_id).ok_or_else(|| {
            Error::StreamClosed(stream_id, "Stream not found".to_string())
        })
    }

    /// Получить мутабельную ссылку на поток
    pub fn get_stream_mut(&mut self, stream_id: StreamId) -> Result<&mut Stream> {
        self.streams.get_mut(&stream_id).ok_or_else(|| {
            Error::StreamClosed(stream_id, "Stream not found".to_string())
        })
    }

    /// Закрыть поток
    pub fn close_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let stream = self.get_stream_mut(stream_id)?;
        stream.close_read(); // Мы получили FIN от пира
        if stream.state.is_closed() {
            self.streams.remove(&stream_id);
        }
        Ok(())
    }

    /// Полностью закрыть поток (обе стороны) и удалить его
    pub fn shutdown_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let stream = self.get_stream_mut(stream_id)?;
        stream.close_write();
        stream.close_read();
        if stream.state.is_closed() {
            self.streams.remove(&stream_id);
        }
        Ok(())
    }

    /// Проверить connection-level flow control
    pub fn can_send_connection(&self, data_len: usize) -> bool {
        (self.connection_sent + data_len as u64) <= self.connection_flow_window
    }

    /// Зарезервировать connection-level budget
    pub fn reserve_connection_send(&mut self, data_len: usize) {
        self.connection_sent += data_len as u64;
    }

    /// Обновить connection flow control window
    pub fn update_connection_window(&mut self, new_window: u64) {
        if new_window > self.connection_flow_window {
            self.connection_flow_window = new_window;
        }
    }

    /// Получить список активных потоков
    pub fn active_streams(&self) -> Vec<StreamId> {
        self.streams.keys().copied().collect()
    }

    /// Количество активных потоков
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Проверить существование потока
    pub fn has_stream(&self, stream_id: StreamId) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// Получить потоки готовые для чтения
    pub fn readable_streams(&self) -> Vec<StreamId> {
        self.streams
            .iter()
            .filter(|(_, s)| !s.receive_buffer.is_empty() && s.state.can_read())
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Упрощённый Stream для публичного API (обёртка над StreamManager)
///
/// Предоставляет read/write/close интерфейс.
///
/// **Примечание:** в реальной имплементации этот тип будет интегрирован
/// с Connection для отправки данных через сокет. Сейчас это заглушка,
/// показывающая API.
#[derive(Debug)]
pub struct StreamHandle {
    pub stream_id: StreamId,
    pub connection_id: u32,
    /// Состояние (локальное зеркало)
    pub state: StreamState,
}

impl StreamHandle {
    pub async fn read(&mut self, max_len: usize) -> Result<Vec<u8>> {
        // В реальной реализации:
        // 1. Проверить receive_buffer в StreamManager
        // 2. Если данных нет — ждать через канал (tokio::sync::oneshot)
        // 3. Вернуть непрерывный блок данных
        todo!("StreamHandle::read integration with Connection")
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        // В реальной реализации:
        // 1. Зарезервировать offset через StreamManager
        // 2. Создать Data Frame
        // 3. Отправить через Connection::send_frame()
        todo!("StreamHandle::write integration with Connection")
    }

    pub async fn close(&mut self) -> Result<()> {
        // Отправить StreamClose (FIN)
        todo!("StreamHandle::close integration with Connection")
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_lifecycle() {
        let mut stream = Stream::new(2, true, 1024 * 1024);
        assert_eq!(stream.state, StreamState::Open);
        assert!(stream.state.can_write());
        assert!(stream.state.can_read());

        stream.close_write();
        assert_eq!(stream.state, StreamState::HalfClosedLocal);
        assert!(!stream.state.can_write());
        assert!(stream.state.can_read());

        stream.close_read();
        assert_eq!(stream.state, StreamState::Closed);
        assert!(stream.state.is_closed());
    }

    #[test]
    fn test_stream_write_read() {
        let mut stream = Stream::new(4, false, 1024);

        // Запись: получаем offset
        let offset = stream.write(b"hello".to_vec()).unwrap();
        assert_eq!(offset, 0);

        let offset = stream.write(b" world".to_vec()).unwrap();
        assert_eq!(offset, 5);

        // Чтение (симулируем получение данных)
        stream.receive_data(0, b"hello".to_vec());
        stream.receive_data(5, b" world".to_vec());

        let data = stream.read(1024).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_stream_read_with_gap() {
        let mut stream = Stream::new(6, true, 1024);

        stream.receive_data(5, b"world".to_vec());
        // Пакет с offset=0 "потерялся"

        let data = stream.read(1024).unwrap();
        // Должен быть пустым — ждём offset=0
        assert!(data.is_empty());

        // Пришёл потерянный пакет
        stream.receive_data(0, b"hello".to_vec());
        let data = stream.read(1024).unwrap();
        assert_eq!(data, b"helloworld");
    }

    #[test]
    fn test_stream_flow_control() {
        let mut stream = Stream::new(8, true, 100);

        assert!(stream.write(vec![0u8; 50]).is_ok());
        assert!(stream.write(vec![0u8; 50]).is_ok());
        // Превышаем окно
        assert!(stream.write(vec![0u8; 1]).is_err());
    }

    #[test]
    fn test_stream_manager_open_close() {
        let mut sm = StreamManager::new(true, 100, 1024 * 1024, 16 * 1024 * 1024);

        let sid = sm.open_stream().unwrap();
        assert_eq!(sid, 2); // Клиент, первый — 2
        assert!(sm.has_stream(sid));

        let sid2 = sm.open_stream().unwrap();
        assert_eq!(sid2, 4); // Следующий чётный

        assert_eq!(sm.stream_count(), 2);

        sm.shutdown_stream(sid2).unwrap();
        assert!(!sm.has_stream(sid2)); // Закрыт — удалён
    }

    #[test]
    fn test_stream_manager_accept() {
        let mut sm = StreamManager::new(false, 100, 1024 * 1024, 16 * 1024 * 1024);

        sm.accept_stream(2).unwrap(); // Клиент открыл чётный поток
        assert!(sm.has_stream(2));

        let stream = sm.get_stream(2).unwrap();
        assert_eq!(stream.state, StreamState::Open);
    }

    #[test]
    fn test_stream_manager_max_streams() {
        let mut sm = StreamManager::new(true, 2, 1024, 1024 * 1024);

        sm.open_stream().unwrap(); // 2
        sm.open_stream().unwrap(); // 4
        assert!(sm.open_stream().is_err()); // Превышен лимит
    }

    #[test]
    fn test_readable_streams() {
        let mut sm = StreamManager::new(true, 100, 1024, 1024 * 1024);

        let sid = sm.open_stream().unwrap();
        let sid2 = sm.open_stream().unwrap();

        {
            let stream = sm.get_stream_mut(sid).unwrap();
            stream.receive_data(0, b"data".to_vec());
        }

        let readable = sm.readable_streams();
        assert_eq!(readable.len(), 1);
        assert!(readable.contains(&sid));
        assert!(!readable.contains(&sid2));
    }

    #[test]
    fn test_flow_control_update() {
        let mut fc = FlowControl::new(100);
        assert_eq!(fc.available_window(), 100);

        fc.reserve_send(50);
        assert_eq!(fc.available_window(), 50);

        fc.update_window(200);
        assert_eq!(fc.available_window(), 150);
    }
}