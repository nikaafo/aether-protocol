# Aether Protocol v0.1 — Спецификация

## Статус документа

**Draft 0.1** — Work in Progress. Community-driven стандарт.
Авторы: Aether Protocol Working Group
Дата: Июль 2026

---

## 1. Введение

### 1.1 Мотивация

Aether — это транспортный протокол четвёртого уровня (L4), спроектированный для замены TCP и UDP в сценариях, требующих:

- **Потоковой мультиплексации без блокировки очереди** (head-of-line blocking)
- **Шифрования с первого байта** (обязательное, не опциональное)
- **Multi-path соединений** (переключение между сетями без разрыва)
- **Identity на уровне протокола** (не IP-based идентификация)
- **Работы в userspace** (без прав root, без kernel-зависимостей)

Aether объединяет лучшие идеи из QUIC (мультиплексированные потоки, шифрование), SCTP (multi-homing), WireGuard (минимализм и userspace) и TCP (проверенная модель надёжности) в один компактный протокол.

### 1.2 Философия дизайна

| Принцип | Применение в Aether |
|---------|---------------------|
| **Простое ядро, расширяемая периферия** | Фиксированный 16-байтовый заголовок; все фичи — через extensions |
| **Безопасность не опциональна** | Шифрование AEAD с первого пакета, без plaintext-режима |
| **Версионирование и negotiation** | Первый пакет объявляет версию и capabilities |
| **Self-describing protocol** | Метаданные протокола встроены в handshake |
| **Userspace-first** | Реализация не требует модификации ядра ОС |

---

## 2. Wire Format

### 2.1 Базовый заголовок (16 байт)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver |  Type   |H|E|R|         Stream ID                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Offset (32 бита)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Length (32 бита)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Connection ID (32 бита — short header)            |
|              или Destination Connection ID (long header)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Поля:

| Поле | Биты | Описание |
|------|------|----------|
| **Ver** | 4 | Версия протокола. Начинается с 0. При несовместимости увеличивается. |
| **Type** | 6 | Тип пакета (см. таблицу ниже) |
| **H** | 1 | 0 = Short header (данные), 1 = Long header (управляющие пакеты) |
| **E** | 1 | Extensions present — если 1, за базовым заголовком следует extension chain |
| **R** | 2 | Зарезервировано (должны быть 0) |
| **Stream ID** | 18 | Идентификатор потока (18 бит: 0–262143). Stream 0 зарезервирован для управления. |
| **Offset** | 32 | Смещение данных в потоке (для надёжной доставки) |
| **Length** | 32 | Длина payload в байтах (не включая заголовок и extensions) |
| **Connection ID** | 32/64 | Short header: 32-битный truncated CID. Long header: 64-битный полный Dest CID. |

### 2.2 Long Header (для Initial, Handshake, Retry)

Long header добавляет 8 дополнительных байт после базового заголовка:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Source Connection ID (64 бита)             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Итого: Long Header = 24 байта, Short Header = 16 байт.**

### 2.3 Типы пакетов (поле Type, 6 бит)

| Код | Имя | Назначение | Header |
|-----|-----|-----------|--------|
| 0x00 | **Initial** | Первый пакет соединения, содержит ClientHello | Long |
| 0x01 | **Handshake** | Криптографический handshake (ServerHello, Finished) | Long |
| 0x02 | **Data** | Пользовательские данные потока | Short |
| 0x03 | **Ack** | Подтверждение получения пакетов | Short |
| 0x04 | **Close** | Закрытие соединения (с кодом причины) | Short |
| 0x05 | **Ping** | Keep-alive / проверка живости | Short |
| 0x06 | **PathChallenge** | Проверка нового пути (multi-path) | Short |
| 0x07 | **PathResponse** | Подтверждение пути | Short |
| 0x08 | **StreamOpen** | Открытие нового потока | Short |
| 0x09 | **StreamClose** | Закрытие потока (FIN) | Short |
| 0x0A-0x3F | **Reserved** | Зарезервировано для будущего использования | — |

### 2.4 Extension Chain

Когда бит **E** установлен в 1, после заголовка идёт цепочка расширений в формате TLV (Type-Length-Value):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ext Type     |  Ext Length                   | Ext Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ext Type     |  Ext Length                   | Ext Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0x00 (terminator)                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Ext Type** — 8 бит. 0x00 = терминатор цепочки.
**Ext Length** — 24 бита.
**Ext Value** — переменной длины.

Предопределённые extension types:

| Код | Имя | Описание |
|-----|-----|----------|
| 0x01 | **Timestamp** | Метка времени отправителя (64-битный UNIX микросекунды) |
| 0x02 | **Priority** | Приоритет потока (8 бит: 0-255, где 0 = bulk, 255 = critical) |
| 0x03 | **Padding** | Заполнение для защиты от traffic analysis |
| 0x04 | **PathId** | Идентификатор пути для multi-path |
| 0x05 | **FlowControl** | Window update для flow control |

---

## 3. Handshake (установление соединения)

### 3.1 Фазы Handshake

```
Client                          Server
  |                               |
  |--- Initial (ClientHello) ---->|
  |                               |
  |<-- Initial (ServerHello) -----|
  |                               |
  |--- Handshake (ClientFinished)->|  <-- после этого клиент может слать Data
  |                               |
  |<-- Handshake (ServerFinished)-|  <-- после этого сервер может слать Data
  |                               |
  |<===== Data (Encrypted) =====>|
```

### 3.2 ClientHello (в Initial-пакете от клиента)

Структура (CBOR-encoded внутри AEAD-encrypted payload):

```
{
  "ver": 0,
  "cid": <64-bit random client connection ID>,
  "supported_versions": [0],
  "crypto": {
    "kem": "Kyber768",          // PQC key encapsulation mechanism
    "classical_kem": "X25519",  // Classical fallback
    "aead": "AES-256-GCM",
    "hash": "SHA-256"
  },
  "capabilities": {
    "multipath": true,
    "max_streams": 65536,
    "max_stream_data": 1048576,
    "ack_frequency": 2,
    "idle_timeout_ms": 30000
  },
  "identity": {
    "type": "ed25519",          // Self-sovereign identity key
    "public_key": <32-byte Ed25519 public key>
  },
  "extensions": []
}
```

### 3.3 ServerHello (в Initial-пакете от сервера)

```
{
  "ver": 0,
  "src_cid": <64-bit random server connection ID>,
  "dst_cid": <client's CID echoed back>,
  "crypto": {
    "kem": "Kyber768",
    "kem_ciphertext": <Kyber ciphertext>,
    "classical_kem": "X25519",
    "classical_public": <X25519 ephemeral public key>
  },
  "capabilities": {
    "multipath": true,
    "max_streams": 65536,
    "max_stream_data": 2097152
  },
  "identity": {
    "type": "ed25519",
    "public_key": <server's Ed25519 public key>,
    "proof": <signature of transcript>
  },
  "extensions": []
}
```

### 3.4 Вычисление ключей

После обмена ClientHello и ServerHello:

```
shared_secret = Kyber768.Decapsulate(server_kem_ciphertext)
             || X25519.DH(client_ephemeral, server_classical_public)

transcript = ClientHello || ServerHello

session_key = HKDF-Expand(
    HKDF-Extract("AETHER-v0", shared_secret),
    transcript,
    256 bits
)

// Создаём две пары ключей:
client_tx_key = HKDF-Expand(session_key, "client-tx", key_len)
server_tx_key = HKDF-Expand(session_key, "server-tx", key_len)
```

### 3.5 ClientFinished / ServerFinished

После вычисления ключей, стороны отправляют Handshake-пакеты:

```
{
  "finished": HMAC-SHA256(session_key, transcript)
}
```

После успешной проверки `finished` — соединение установлено. Все последующие Data-пакеты шифруются AEAD с использованием session_key.

---

## 4. Streams (потоки)

### 4.1 Модель потоков

- Каждый поток идентифицируется 18-битным **Stream ID**
- Stream ID 0 зарезервирован для внутреннего управления (control stream)
- Клиент открывает потоки с **чётными** ID (0, 2, 4, ...)
- Сервер открывает потоки с **нечётными** ID (1, 3, 5, ...)
- Потоки независимы: потеря пакета в одном потоке не блокирует остальные

### 4.2 Жизненный цикл потока

```
                   Frame: StreamOpen
   IDLE  ---------------------------------->  OPEN
                                                 |
                                                 | Frame: Data (много)
                                                 | Frame: Ack (подтверждения)
                                                 |
                                                 v
                   Frame: StreamClose (FIN)
   OPEN  ---------------------------------->  HALF-CLOSED
                                                 |
                                                 | (другая сторона дочитывает)
                                                 |
                                                 v
                   Frame: StreamClose (ACK)
   HALF-CLOSED ---------------------------->  CLOSED
```

### 4.3 Flow Control (управление потоком)

- **Connection-level**: общий лимит данных в полёте для всего соединения
- **Stream-level**: лимит данных в полёте для конкретного потока
- Обновление окон через Extension Type 0x05 (FlowControl)

Начальные окна (объявляются в Capabilities):
- Stream flow control window: 1 MB (регулируется)
- Connection flow control window: 16 MB (регулируется)

### 4.4 Надёжность и доставка

- Каждый Data-пакет имеет **Offset** — байтовое смещение в потоке
- Получатель отправляет **Ack** с диапазонами полученных offset'ов
- Неподтверждённые пакеты повторяются с экспоненциальной задержкой
- Максимальное количество retransmissions: 10

---

## 5. Multi-path (многопутевость)

### 5.1 Установление нового пути

Соединение идентифицируется **Connection ID**, не IP-адресом. Это позволяет:

1. Клиент обнаруживает новый сетевой интерфейс (например, 5G после Wi-Fi)
2. Клиент отправляет **PathChallenge** с нового IP на сервер
3. Сервер отвечает **PathResponse**, подтверждая, что пакеты с нового IP принадлежат тому же соединению
4. Сервер начинает отправлять данные на оба пути
5. Клиент также может дублировать данные на оба пути для надёжности

### 5.2 Path Identifier

Каждый путь имеет уникальный **Path ID** (Extension Type 0x04). Пакеты с разных путей мультиплексируются на общие потоки — получатель собирает их по Offset.

### 5.3 Миграция соединения

При потере одного пути (например, Wi-Fi отключился) данные автоматически идут через оставшиеся пути. Connection ID не меняется — соединение выживает.

---

## 6. Congestion Control (управление перегрузкой)

### 6.1 Алгоритм по умолчанию: Aether-CC

Aether-CC — это гибрид BBRv3 и NewReno, оптимизированный для:

- **Спутниковых каналов** (высокая latency, переменная пропускная способность)
- **Мобильных сетей** (частые смены bandwidth)
- **Шумных каналов** (не путать потерю пакета с перегрузкой)

#### Оценка bandwidth:

```
delivery_rate = bytes_acked / time_delta
max_bw = max(max_bw, delivery_rate)  // экспоненциальное сглаживание
```

#### Оценка RTT:

```
min_rtt = min(min_rtt, latest_rtt)   // за окно 10 секунд
```

#### Окно отправки:

```
cwnd = max_bw * min_rtt * gain      // gain: 1.25 при probing, 0.75 при drain
```

#### Отличие от потери:

- Потеря при низком RTT и растущем delivery_rate → **перегрузка**
- Потеря при высоком RTT и стабильном delivery_rate → **шум канала** (не уменьшаем окно)

### 6.2 Подключаемые алгоритмы

Протокол позволяет сменить congestion control через Capabilities при handshake. Возможные варианты:
- `aether-cc` (по умолчанию)
- `bbrv3` (для совместимости)
- `cubic` (для legacy-сетей)
- `none` (для тестирования)

---

## 7. Безопасность

### 7.1 Обязательное шифрование

Aether **не имеет plaintext-режима**. Все пакеты, включая Initial, шифруются:

- Initial-пакеты: AEAD с ключом, производным от initial salt
- Handshake-пакеты: AEAD с ключами, производными от shared_secret
- Data-пакеты: AEAD с session_key

### 7.2 Постквантовая стойкость

Handshake использует **Kyber-768** (NIST PQC стандарт) как основной KEM, с **X25519** как классический fallback. Это обеспечивает стойкость даже против квантового компьютера при условии, что хотя бы один из алгоритмов стоек.

### 7.3 Защита метаданных

- Connection ID в short header — 32-битный truncated, не раскрывает полный CID
- Padding extension (0x03) позволяет добавлять случайные байты для маскировки размера пакета
- Multipath затрудняет пассивный анализ трафика

### 7.4 Perfect Forward Secrecy

Каждое соединение генерирует эфемерные ключи. Компрометация identity-ключа не раскрывает прошлые сессии.

---

## 8. Identity (идентификация)

### 8.1 Self-sovereign Identity

В отличие от TCP/IP, где идентификатор узла — IP-адрес, и TLS, где идентификатор — сертификат X.509, Aether использует **криптографическую идентичность**:

- Каждый узел имеет Ed25519 ключевую пару
- Identity = хеш публичного ключа (32 байта)
- При handshake узел доказывает владение ключом через подпись transcript'а

### 8.2 Преимущества

- **Не зависит от DNS / CA / PKI** — идентичность самодостаточна
- **Мобильность**: переключение IP не меняет идентичность
- **Децентрализация**: не требует централизованного registry
- **Совместимость с DIDs**: identity может быть представлен как W3C DID

### 8.3 Формат Identity

```
identity = SHA-256( "AETHER-ID-" || Ed25519_public_key )
```

---

## 9. Закрытие соединения

### 9.1 Graceful Close

```
Отправитель -> Close (код: 0x00 "NO_ERROR")
Получатель -> Close (код: 0x00 "NO_ERROR")
Соединение закрыто -> ключи уничтожаются через 3x PTO
```

### 9.2 Коды ошибок

| Код | Имя | Описание |
|-----|-----|----------|
| 0x00 | NO_ERROR | Нормальное закрытие |
| 0x01 | INTERNAL_ERROR | Внутренняя ошибка |
| 0x02 | PROTOCOL_VIOLATION | Нарушение протокола |
| 0x03 | CRYPTO_ERROR | Ошибка криптографии |
| 0x04 | FLOW_CONTROL_ERROR | Превышение лимита потока |
| 0x05 | TIMEOUT | Таймаут бездействия |
| 0x06 | VERSION_NEGOTIATION | Несовместимая версия |
| 0x07 | REFUSED | Соединение отклонено |
| 0x08 | IDENTITY_REJECTED | Идентичность не принята |

---

## 10. Discovery (автообнаружение)

### 10.1 Локальное обнаружение (LAN)

Aether использует mDNS-подобный механизм для обнаружения пиров в локальной сети:

- Мультикаст-группа: `224.0.0.251:9000` (IPv4), `ff02::fb:9000` (IPv6)
- Периодические анонсы: каждые 30 секунд
- Формат анонса: Initial-пакет с типом "Announce" в extensions

### 10.2 Глобальное обнаружение (WAN)

Для WAN-обнаружения Aether определяет интерфейс DHT-поиска:

- DHT на основе Kademlia (как в libp2p)
- Ключ в DHT = Identity пира
- Значение = набор (IP, порт, Connection ID)

Это позволяет найти пира по его Identity без централизованного сервера.

---

## 11. Реализация

### 11.1 Эталонная реализация

- **Язык:** Rust (v1.80+, edition 2024)
- **Крейт:** `aether-core`
- **Зависимости:** `ring` (криптография), `cbor4ii` (CBOR), `tokio` (async runtime)
- **Лицензия:** Apache 2.0 / MIT

### 11.2 Структура крейта

```
aether-core/
├── framing.rs      — wire format, encode/decode пакетов
├── handshake.rs    — ClientHello, ServerHello, key derivation
├── stream.rs       — управление потоками, flow control
├── connection.rs   — управление соединением, мультиплексирование
├── congestion.rs   — Aether-CC алгоритм
├── multipath.rs    — multi-path логика
├── identity.rs     — Ed25519 identity, proof generation
├── discovery.rs    — mDNS/DHT обнаружение
├── crypto.rs       — AEAD шифрование, HKDF
└── error.rs        — типы ошибок
```

### 11.3 API (пример)

```rust
use aether_core::{Connection, Config, Identity};

// Создаём identity
let identity = Identity::generate();

// Конфигурация
let config = Config {
    capabilities: Capabilities {
        multipath: true,
        max_streams: 65536,
        ..Default::default()
    },
    ..Default::default()
};

// Сервер
let listener = Connection::bind("0.0.0.0:9000", identity.clone(), config).await?;
while let Some(conn) = listener.accept().await {
    tokio::spawn(async move {
        while let Some(mut stream) = conn.accept_stream().await {
            let data = stream.read(1024).await?;
            stream.write(b"echo: ").await?;
            stream.write(&data).await?;
            stream.close().await?;
        }
    });
}

// Клиент
let mut conn = Connection::connect("peer-identity-hash", config).await?;
let mut stream = conn.open_stream().await?;
stream.write(b"Hello, Aether!").await?;
let response = stream.read(1024).await?;
stream.close().await?;
conn.close(CloseCode::NO_ERROR).await?;
```

---

## 12. Тестирование и Conformance

### 12.1 Conformance Test Suite

Каждая реализация Aether должна проходить следующие тесты:

1. **Wire format**: encode/decode всех типов пакетов, extension chain
2. **Handshake**: полный цикл ClientHello → Data
3. **Handshake (несовместимая версия)**: Version Negotiation
4. **Streams**: открытие/закрытие, flow control, FIN
5. **Multi-path**: PathChallenge/Response, миграция соединения
6. **Congestion**: Aether-CC на симулированных каналах (0%, 1%, 5%, 10% loss)
7. **Interop**: две независимые реализации должны общаться

### 12.2 Симулятор сети

Встроенный симулятор позволяет тестировать:

- Задержку (0–500 мс)
- Потерю пакетов (0–30%)
- Джиттер (0–100 мс)
- Переупорядочивание пакетов
- Асимметричные каналы

---

## 13. Дорожная карта

| Версия | Содержание | Статус |
|--------|-----------|--------|
| **v0.1** | Базовая спецификация: wire format, handshake, streams, crypto | 🔨 В разработке |
| **v0.2** | Multi-path, congestion control Aether-CC, identity | 📋 План |
| **v0.3** | Discovery (mDNS + DHT), NAT traversal (STUN) | 📋 План |
| **v0.5** | Стабилизация wire format, interop testing | 📋 План |
| **v1.0** | RFC-style спецификация, conformance suite | 🎯 Цель |

---

## Приложение A: Константы

| Константа | Значение | Описание |
|-----------|----------|----------|
| `AETHER_DEFAULT_PORT` | 9000 | Порт по умолчанию |
| `AETHER_VERSION` | 0 | Текущая версия протокола |
| `AETHER_INITIAL_SALT` | `SHA-256("AETHER-v0-initial-salt")` | Соль для Initial-шифрования |
| `MAX_PACKET_SIZE` | 1400 | Максимальный размер пакета (с запасом под MTU) |
| `MAX_STREAM_ID` | 262143 | Максимальный Stream ID (18 бит) |
| `IDLE_TIMEOUT_MS` | 30000 | Таймаут бездействия соединения (30 сек) |
| `PTO_BASE_MS` | 100 | Базовый Probe Timeout |
| `MAX_RETRANSMISSIONS` | 10 | Максимум повторных передач |
| `INITIAL_CWND` | 10 * MSS | Начальное congestion window |
| `INITIAL_STREAM_WINDOW` | 1048576 | Начальное окно потока (1 MB) |
| `INITIAL_CONNECTION_WINDOW` | 16777216 | Начальное окно соединения (16 MB) |

---

## Приложение B: Сравнение с существующими протоколами

| Характеристика | TCP | UDP | QUIC | SCTP | **Aether** |
|---------------|-----|-----|------|------|------------|
| Надёжная доставка | ✅ | ❌ | ✅ | ✅ | ✅ |
| Мультиплексирование | ❌ | ❌ | ✅ (HTTP-tied) | ✅ | ✅ (generic) |
| Шифрование | ❌ (нужен TLS) | ❌ | ✅ (обязат.) | ❌ (нужен DTLS) | ✅ (обязат.) |
| Multi-path | ❌ | ❌ | ✅ (v2) | ✅ | ✅ (из коробки) |
| Userspace | ❌ | ✅ | ✅ | ❌ | ✅ |
| Identity layer | ❌ | ❌ | ❌ | ❌ | ✅ |
| PQC-ready | ❌ | ❌ | ⚠️ (в процессе) | ❌ | ✅ |
| NAT friendly | ✅ | ❌ | ✅ | ❌ | ✅ |
| Head-of-line blocking | ✅ (блокирует) | ❌ | ❌ (stream-level) | ❌ | ❌ |

---

> **"The best protocols are discovered, not invented."**
> Aether is discovered from the future needs of a hyperconnected, quantum-threatened, identity-first internet.

---

*© 2026 Aether Protocol Working Group. Licensed under Apache 2.0 / MIT.*