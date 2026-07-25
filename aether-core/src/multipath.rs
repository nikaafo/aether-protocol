//! Multi-path логика Aether Protocol
//!
//! Соединение Aether идентифицируется Connection ID, а не IP-адресом.
//! Это позволяет передавать данные через несколько сетевых путей одновременно.
//!
//! ## Механика
//!
//! 1. Клиент обнаруживает новый сетевой интерфейс (Wi-Fi → 5G)
//! 2. Клиент отправляет PathChallenge с нового адреса
//! 3. Сервер отвечает PathResponse — путь подтверждён
//! 4. Данные идут через все активные пути
//! 5. При отказе одного пути — переключение без разрыва соединения

use crate::crypto;
use crate::error::{Error, Result};
use crate::framing::{Extension, ExtType, Frame};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// Идентификатор пути (8 бит, 0–255)
pub type PathId = u8;

/// Состояние конкретного сетевого пути
#[derive(Debug, Clone)]
pub struct PathState {
    /// ID пути
    pub id: PathId,
    /// Локальный адрес (IP + порт)
    pub local_addr: SocketAddr,
    /// Адрес пира для этого пути
    pub remote_addr: SocketAddr,
    /// Активен ли путь
    pub active: bool,
    /// RTT в микросекундах (последнее измерение)
    pub rtt_us: u64,
    /// Потеряно пакетов на этом пути
    pub packets_lost: u64,
    /// Отправлено пакетов через этот путь
    pub packets_sent: u64,
    /// Время последней активности
    pub last_active: Instant,
    /// Nonce для проверки пути
    pub challenge_nonce: Option<u64>,
}

impl PathState {
    pub fn new(id: PathId, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            id,
            local_addr,
            remote_addr,
            active: false,
            rtt_us: 0,
            packets_lost: 0,
            packets_sent: 0,
            last_active: Instant::now(),
            challenge_nonce: None,
        }
    }

    /// Оценка качества пути (меньше = лучше)
    pub fn quality_score(&self) -> f64 {
        if !self.active {
            return f64::MAX;
        }
        let rtt_ms = self.rtt_us as f64 / 1000.0;
        let loss_rate = if self.packets_sent > 0 {
            self.packets_lost as f64 / self.packets_sent as f64
        } else {
            0.0
        };
        // Комбинированная метрика: RTT + штраф за потери
        rtt_ms * (1.0 + loss_rate * 10.0)
    }
}

/// Менеджер мультипутевости
#[derive(Debug)]
pub struct PathManager {
    /// Все известные пути
    paths: HashMap<PathId, PathState>,
    /// Следующий доступный Path ID
    next_path_id: PathId,
    /// Основной путь (используется для handshake)
    pub primary_path_id: PathId,
    /// Максимальное количество одновременных путей
    max_paths: usize,
    /// Connection ID соединения
    connection_id: u64,
}

impl PathManager {
    /// Создать менеджер путей
    pub fn new(connection_id: u64, max_paths: usize) -> Self {
        Self {
            paths: HashMap::new(),
            next_path_id: 1,
            primary_path_id: 0,
            max_paths,
            connection_id,
        }
    }

    /// Зарегистрировать основной путь
    pub fn register_primary(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> PathId {
        let mut path = PathState::new(0, local_addr, remote_addr);
        path.active = true;
        self.paths.insert(0, path);
        self.primary_path_id = 0;
        0
    }

    /// Создать PathChallenge для нового пути
    pub fn create_path_challenge(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(Frame, PathId)> {
        if self.paths.len() >= self.max_paths {
            return Err(Error::FlowControl(format!(
                "Maximum paths reached: {}",
                self.max_paths
            )));
        }

        let path_id = self.next_path_id;
        self.next_path_id = self.next_path_id.wrapping_add(1);

        let nonce = crypto::generate_path_nonce();

        let mut path = PathState::new(path_id, local_addr, remote_addr);
        path.challenge_nonce = Some(nonce);
        path.last_active = Instant::now();
        self.paths.insert(path_id, path);

        let frame = Frame::path_challenge(
            (self.connection_id >> 32) as u32,
            path_id,
            nonce,
        );

        Ok((frame, path_id))
    }

    /// Обработать PathResponse (вызывается при получении ответа)
    pub fn handle_path_response(&mut self, frame: &Frame) -> Result<PathId> {
        let path_id = self.extract_path_id(frame)?;
        let nonce = if frame.payload.len() >= 8 {
            u64::from_be_bytes([
                frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3],
                frame.payload[4], frame.payload[5], frame.payload[6], frame.payload[7],
            ])
        } else {
            return Err(Error::ProtocolViolation(
                "PathResponse payload too short".to_string(),
            ));
        };

        let path = self.paths.get_mut(&path_id).ok_or_else(|| {
            Error::ProtocolViolation(format!("Unknown path ID: {}", path_id))
        })?;

        // Проверяем nonce
        if path.challenge_nonce != Some(nonce) {
            return Err(Error::Crypto(format!(
                "PathResponse nonce mismatch for path {}: expected {:?}, got {}",
                path_id, path.challenge_nonce, nonce
            )));
        }

        // Путь подтверждён
        path.active = true;
        path.challenge_nonce = None;
        path.last_active = Instant::now();

        tracing::info!("Path {} activated: {:?} → {:?}", path_id, path.local_addr, path.remote_addr);
        Ok(path_id)
    }

    /// Обработать входящий PathChallenge (серверная сторона)
    pub fn handle_path_challenge(
        &mut self,
        frame: &Frame,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<(Frame, PathId)> {
        let path_id = self.extract_path_id(frame)?;
        let nonce = if frame.payload.len() >= 8 {
            u64::from_be_bytes([
                frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3],
                frame.payload[4], frame.payload[5], frame.payload[6], frame.payload[7],
            ])
        } else {
            return Err(Error::ProtocolViolation(
                "PathChallenge payload too short".to_string(),
            ));
        };

        // Создаём или обновляем путь
        let path = self.paths.entry(path_id).or_insert_with(|| {
            PathState::new(path_id, local_addr, remote_addr)
        });
        path.remote_addr = remote_addr;
        path.last_active = Instant::now();

        // Создаём ответ
        let response = Frame::path_response(
            (self.connection_id >> 32) as u32,
            path_id,
            nonce,
        );

        // Помечаем путь как активный
        path.active = true;

        tracing::info!("PathChallenge from {} accepted as path {}", remote_addr, path_id);
        Ok((response, path_id))
    }

    /// Деактивировать путь (при таймауте или ошибке)
    pub fn deactivate_path(&mut self, path_id: PathId) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.active = false;
            tracing::warn!("Path {} deactivated (was: {:?})", path_id, path.remote_addr);
        }
    }

    /// Получить лучший активный путь для отправки
    pub fn best_path(&self) -> Option<(PathId, &PathState)> {
        self.paths
            .iter()
            .filter(|(_, p)| p.active)
            .min_by(|(_, a), (_, b)| {
                a.quality_score()
                    .partial_cmp(&b.quality_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, path)| (*id, path))
    }

    /// Получить все активные пути
    pub fn active_paths(&self) -> Vec<(PathId, &PathState)> {
        self.paths
            .iter()
            .filter(|(_, p)| p.active)
            .map(|(id, p)| (*id, p))
            .collect()
    }

    /// Обновить статистику пути
    pub fn record_send(&mut self, path_id: PathId) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.packets_sent += 1;
            path.last_active = Instant::now();
        }
    }

    pub fn record_loss(&mut self, path_id: PathId) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.packets_lost += 1;
        }
    }

    pub fn record_rtt(&mut self, path_id: PathId, rtt_us: u64) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            // Экспоненциальное сглаживание RTT
            if path.rtt_us == 0 {
                path.rtt_us = rtt_us;
            } else {
                path.rtt_us = (path.rtt_us as f64 * 0.875 + rtt_us as f64 * 0.125) as u64;
            }
        }
    }

    /// Проверить пути на таймаут и деактивировать просроченные
    pub fn check_timeouts(&mut self, timeout_ms: u64) {
        let now = Instant::now();
        for path in self.paths.values_mut() {
            if path.active && now.duration_since(path.last_active).as_millis() as u64 > timeout_ms {
                path.active = false;
                tracing::warn!("Path {} timed out", path.id);
            }
        }
    }

    /// Извлечь Path ID из extensions фрейма
    fn extract_path_id(&self, frame: &Frame) -> Result<PathId> {
        for ext in &frame.extensions {
            if ext.ext_type == ExtType::PathId {
                if ext.value.is_empty() {
                    return Err(Error::ProtocolViolation("Empty PathId extension".to_string()));
                }
                return Ok(ext.value[0]);
            }
        }
        Err(Error::ProtocolViolation("Missing PathId extension".to_string()))
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_path_lifecycle() {
        let mut pm = PathManager::new(0xABCD, 4);

        // Регистрируем основной путь
        let primary = pm.register_primary(make_addr(9000), make_addr(9001));
        assert_eq!(primary, 0);

        // Создаём challenge для нового пути
        let (challenge, path_id) = pm
            .create_path_challenge(make_addr(10000), make_addr(10001))
            .unwrap();
        assert!(path_id > 0);

        // Симулируем PathResponse
        let response = Frame::path_response(0, path_id, {
            let path = pm.paths.get(&path_id).unwrap();
            path.challenge_nonce.unwrap()
        });
        let confirmed = pm.handle_path_response(&response).unwrap();
        assert_eq!(confirmed, path_id);

        let active = pm.active_paths();
        assert_eq!(active.len(), 2); // primary + новый
    }

    #[test]
    fn test_handle_path_challenge() {
        let mut pm = PathManager::new(0xABCD, 4);

        let challenge = Frame::path_challenge(0, 5, 0xDEADBEEF);
        let (response, path_id) = pm
            .handle_path_challenge(&challenge, make_addr(20001), make_addr(20000))
            .unwrap();

        assert_eq!(path_id, 5);
        assert!(pm.paths.get(&5).unwrap().active);
    }

    #[test]
    fn test_best_path_selection() {
        let mut pm = PathManager::new(0xABCD, 4);

        pm.register_primary(make_addr(9000), make_addr(9001));
        pm.record_rtt(0, 50_000); // 50ms RTT

        // Добавляем второй путь
        let (ch, pid) = pm.create_path_challenge(make_addr(10000), make_addr(10001)).unwrap();
        pm.record_rtt(pid, 10_000); // 10ms RTT — быстрее

        // Симулируем ответ
        let nonce = pm.paths.get(&pid).unwrap().challenge_nonce.unwrap();
        let resp = Frame::path_response(0, pid, nonce);
        pm.handle_path_response(&resp).unwrap();

        let best = pm.best_path().unwrap();
        assert_eq!(best.0, pid); // Второй путь быстрее
    }

    #[test]
    fn test_timeout_deactivation() {
        let mut pm = PathManager::new(0xABCD, 4);
        pm.register_primary(make_addr(9000), make_addr(9001));

        // Проверяем с нулевым таймаутом — путь должен деактивироваться
        std::thread::sleep(std::time::Duration::from_millis(1));
        pm.check_timeouts(0);

        assert!(pm.active_paths().is_empty());
    }

    #[test]
    fn test_max_paths() {
        let mut pm = PathManager::new(0xABCD, 2);
        pm.register_primary(make_addr(9000), make_addr(9001)); // 0

        pm.create_path_challenge(make_addr(10000), make_addr(10001)).unwrap(); // 1
        let result = pm.create_path_challenge(make_addr(20000), make_addr(20001)); // должно отказать
        assert!(result.is_err());
    }
}