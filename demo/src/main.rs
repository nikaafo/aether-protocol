//! Aether Protocol — Demo Application
//!
//! Echo-сервер и клиент, демонстрирующие работу протокола Aether:
//! - Handshake с X25519 + AES-256-GCM
//! - Мультиплексированные потоки
//! - Self-sovereign Ed25519 identity
//! - Keep-alive (Ping)
//! - Graceful shutdown (Close)
//!
//! ## Запуск сервера
//!
//! ```bash
//! cargo run --bin aether-demo -- server
//! ```
//!
//! ## Запуск клиента
//!
//! ```bash
//! cargo run --bin aether-demo -- client
//! ```

use aether_core::connection::{Connection, Config, Listener};
use aether_core::error::{CloseCode, Error, Result};
use aether_core::framing::Frame;
use aether_core::identity::Identity;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Демо: запуск echo-сервера
///
/// Сервер принимает соединения, читает данные из потоков,
/// отправляет обратно с префиксом "echo: ".
async fn run_server() -> Result<()> {
    // Генерируем identity сервера
    let identity = Identity::from_seed([0x42; 32]);
    println!("🚀 Aether Echo Server");
    println!("   Identity: {}", identity.hash_hex());
    println!("   Listening on 0.0.0.0:9000");

    let config = Config::default();
    let socket = UdpSocket::bind("0.0.0.0:9000").await?;
    let socket = Arc::new(socket);

    println!("✅ Server is ready. Waiting for connections...\n");

    loop {
        match Connection::accept(socket.clone(), &identity, &config).await {
            Ok(mut conn) => {
                println!("📡 New connection accepted! CID: 0x{:08x}", conn.our_connection_id);

                tokio::spawn(async move {
                    // Принимаем фреймы от клиента
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match conn.recv_frame().await {
                            Ok(frame) => {
                                match frame.header.frame_type {
                                    aether_core::framing::FrameType::Data => {
                                        let data = frame.payload;
                                        let response = format!("echo: {}", String::from_utf8_lossy(&data));
                                        println!("   Received: {}", String::from_utf8_lossy(&data));
                                        println!("   Sending:  {}", response);

                                        // Отправляем ответ
                                        if let Err(e) = conn.send_stream_data(
                                            frame.header.stream_id,
                                            response.as_bytes(),
                                        ).await {
                                            eprintln!("   Failed to send response: {}", e);
                                            break;
                                        }
                                    }
                                    aether_core::framing::FrameType::Ping => {
                                        println!("   🏓 Ping received");
                                    }
                                    aether_core::framing::FrameType::Close => {
                                        println!("   👋 Client disconnected");
                                        break;
                                    }
                                    _ => {
                                        println!("   📦 Received frame: {:?}", frame.header.frame_type);
                                    }
                                }
                            }
                            Err(Error::ConnectionClosed(_, _)) => {
                                println!("   Connection closed by peer");
                                break;
                            }
                            Err(e) => {
                                eprintln!("   Error receiving frame: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Демо: запуск клиента
///
/// Клиент подключается к серверу, отправляет тестовые сообщения,
/// получает echo-ответы и отключается.
async fn run_client() -> Result<()> {
    println!("🔌 Aether Echo Client");
    println!("   Connecting to 127.0.0.1:9000...");

    let config = Config::default();
    let mut conn = Connection::connect("127.0.0.1:9000", config).await?;

    println!("✅ Connected! Our CID: 0x{:08x}", conn.our_connection_id);
    println!("   Peer CID: 0x{:08x}", conn.peer_connection_id.unwrap_or(0));

    // Отправляем несколько сообщений
    let messages = vec![
        "Hello, Aether! 👋",
        "This is message #2 📨",
        "Multi-stream multiplexing 🚀",
        "Encrypted with AES-256-GCM 🔐",
        "Self-sovereign identity 🪪",
        "Goodbye! 👋",
    ];

    for msg in &messages {
        println!("\n   Sending: {}", msg);
        conn.send_stream_data(0, msg.as_bytes()).await?;

        // Ждём ответ
        match conn.recv_frame().await {
            Ok(frame) => {
                if frame.header.frame_type == aether_core::framing::FrameType::Data {
                    println!("   Received: {}", String::from_utf8_lossy(&frame.payload));
                }
            }
            Err(e) => {
                eprintln!("   Failed to receive: {}", e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Отправляем Ping
    println!("\n   🏓 Sending Ping...");
    conn.ping().await?;

    // Закрываем соединение
    println!("\n   👋 Closing connection...");
    conn.close(CloseCode::NoError).await?;
    println!("✅ Connection closed gracefully.");

    Ok(())
}

/// Точка входа
#[tokio::main]
async fn main() -> Result<()> {
    // Инициализируем логирование
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("client");

    match mode {
        "server" | "s" => run_server().await?,
        "client" | "c" => run_client().await?,
        _ => {
            println!("Usage: aether-demo [server|client]");
            println!("  server  — Start echo server on port 9000");
            println!("  client  — Connect to server and run test exchange");
        }
    }

    Ok(())
}