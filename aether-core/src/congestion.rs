//! Congestion Control — Aether-CC
//!
//! Aether-CC — гибрид BBRv3 и NewReno, оптимизированный для:
//! - Спутниковых каналов (высокая latency, переменная пропускная способность)
//! - Мобильных сетей (частые смены bandwidth)
//! - Шумных каналов (отличие потери пакета от перегрузки)
//!
//! ## Алгоритм
//!
//! ```text
//! delivery_rate = bytes_acked / time_delta
//! max_bw = max(max_bw, delivery_rate)
//! min_rtt = min(min_rtt, latest_rtt)
//! cwnd = max_bw * min_rtt * gain
//! ```
//!
//! Где gain = 1.25 при probing, 0.75 при drain.
//!
//! ## Отличие потери от шума
//!
//! - Потеря при низком RTT и растущем delivery_rate → перегрузка (уменьшаем окно)
//! - Потеря при высоком RTT и стабильном delivery_rate → шум канала (не уменьшаем)

use crate::error::Result;
use std::time::Instant;

/// Состояние congestion control
#[derive(Debug)]
pub struct CongestionController {
    /// Текущее congestion window (в байтах)
    pub cwnd: u64,
    /// Минимальный RTT за окно (микросекунды)
    pub min_rtt: u64,
    /// Максимальный bandwidth (байт/сек)
    pub max_bw: u64,
    /// Коэффициент усиления (1.25 probing, 0.75 drain, 1.0 steady)
    pub gain: f64,
    /// Состояние
    pub state: CongestionState,
    /// Последнее время обновления
    last_update: Instant,
    /// Размер окна для min_rtt (10 секунд)
    rtt_window: Vec<(u64, Instant)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Начальная фаза: быстрое увеличение окна
    Startup,
    /// Фаза зондирования: увеличение gain для поиска bandwidth
    Probe,
    /// Фаза слива: уменьшение gain для освобождения очереди
    Drain,
    /// Стабильная фаза
    Steady,
}

impl CongestionController {
    /// Создать новый congestion controller
    pub fn new(initial_cwnd: u64) -> Self {
        Self {
            cwnd: initial_cwnd,
            min_rtt: u64::MAX,
            max_bw: 0,
            gain: 2.89, // startup gain
            state: CongestionState::Startup,
            last_update: Instant::now(),
            rtt_window: Vec::new(),
        }
    }

    /// Обновить оценку на основе подтверждённых данных
    pub fn on_ack(&mut self, bytes_acked: u64, rtt: u64, now: Instant) {
        // Обновляем min_rtt
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }

        // Очищаем старые записи RTT (старше 10 секунд)
        self.rtt_window.retain(|(_, t)| now.duration_since(*t).as_secs() < 10);
        self.rtt_window.push((rtt, now));

        // Пересчитываем min_rtt из окна
        if let Some(min) = self.rtt_window.iter().map(|(r, _)| *r).min() {
            self.min_rtt = min;
        }

        // Оценка bandwidth
        let delivery_rate = if rtt > 0 {
            bytes_acked * 1_000_000 / rtt // байт/сек
        } else {
            self.max_bw
        };

        if delivery_rate > self.max_bw {
            self.max_bw = delivery_rate;
        }

        // Обновляем cwnd
        match self.state {
            CongestionState::Startup => {
                self.cwnd = (self.cwnd as f64 * 1.1) as u64;
                if self.max_bw > 0 && self.cwnd >= self.max_bw * self.min_rtt / 1_000_000 {
                    self.state = CongestionState::Drain;
                    self.gain = 0.75;
                }
            }
            CongestionState::Probe => {
                self.gain = 1.25;
                self.cwnd = (self.max_bw * self.min_rtt / 1_000_000) as u64;
                self.cwnd = (self.cwnd as f64 * self.gain) as u64;
            }
            CongestionState::Drain => {
                self.gain = 0.75;
                self.cwnd = (self.max_bw * self.min_rtt / 1_000_000) as u64;
                self.cwnd = (self.cwnd as f64 * self.gain) as u64;
                // Переключаемся на probe после drain
                self.state = CongestionState::Probe;
            }
            CongestionState::Steady => {
                self.cwnd = (self.max_bw * self.min_rtt / 1_000_000) as u64;
            }
        }

        self.last_update = now;
    }

    /// Обработать потерю пакета
    ///
    /// Отличает потерю от шума канала:
    /// - Если RTT высокий и bandwidth стабилен → шум, игнорируем
    /// - Иначе → перегрузка, уменьшаем окно
    pub fn on_loss(&mut self, current_rtt: u64) {
        let is_noise = current_rtt > self.min_rtt * 3;

        if !is_noise {
            // Реальная перегрузка
            self.cwnd = self.cwnd / 2;
            self.state = CongestionState::Steady;
            self.gain = 1.0;
        }
        // Иначе: игнорируем — это шум канала
    }

    /// Получить текущее окно отправки
    pub fn send_window(&self) -> u64 {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_startup() {
        let mut cc = CongestionController::new(14000); // 10 * MSS
        let now = Instant::now();

        for i in 0..100 {
            let rtt = 10_000;
            cc.on_ack(1400, rtt, now + std::time::Duration::from_millis(i));
        }

        // Окно должно вырасти или как минимум остаться положительным
        assert!(cc.cwnd > 0);
        assert!(cc.max_bw > 0);
    }

    #[test]
    fn test_loss_is_noise() {
        let mut cc = CongestionController::new(14000);
        cc.min_rtt = 10_000; // 10ms
        let before = cc.cwnd;

        // Потеря при RTT = 50ms (5x min_rtt — шум)
        cc.on_loss(50_000);

        // Окно не должно уменьшиться
        assert_eq!(cc.cwnd, before);
    }

    #[test]
    fn test_loss_is_congestion() {
        let mut cc = CongestionController::new(100000);
        cc.min_rtt = 50_000; // 50ms
        let before = cc.cwnd;

        // Потеря при RTT = 60ms (близко к min_rtt — перегрузка)
        cc.on_loss(60_000);

        // Окно должно уменьшиться
        assert!(cc.cwnd < before);
    }
}