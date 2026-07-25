//! # Aether Gateway
//!
//! L4 прокси для приёма Aether-соединений и проксирования в TCP/HTTP.
//!
//! ## Использование
//!
//! ```bash
//! # Запуск с перенаправлением на localhost:8080
//! cargo run -- --target 127.0.0.1:8080
//!
//! # Запуск на кастомном порту
//! cargo run -- --listen 0.0.0.0:9000 --target 127.0.0.1:3000
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

/// Aether Gateway — L4 прокси
#[derive(Parser, Debug)]
#[command(name = "aether-gateway", version = "0.1.0")]
struct Args {
    /// Адрес для приёма Aether-соединений
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: SocketAddr,

    /// Целевой адрес (куда проксировать)
    #[arg(short, long)]
    target: SocketAddr,

    /// Максимальное количество одновременных соединений
    #[arg(long, default_value = "1024")]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Инициализация логирования
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aether_gateway=info".into()),
        )
        .init();

    let args = Args::parse();
    info!(
        "Aether Gateway starting — listen on {}, proxy to {}",
        args.listen, args.target
    );

    // Создаём TCP listener (в будущем — Aether listener)
    let listener = TcpListener::bind(args.listen)
        .await
        .context("Failed to bind listener")?;

    let target = args.target;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(args.max_connections));

    loop {
        let permit = semaphore.clone().acquire_owned().await;
        match permit {
            Ok(permit) => {
                match listener.accept().await {
                    Ok((inbound, peer_addr)) => {
                        info!("New connection from {}", peer_addr);
                        let target = target;
                        tokio::spawn(async move {
                            if let Err(e) = proxy_connection(inbound, target).await {
                                error!("Proxy error from {}: {:?}", peer_addr, e);
                            }
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e);
                    }
                }
            }
            Err(_) => {
                warn!("Max connections reached, waiting...");
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Проксировать одно соединение: inbound ↔ target (двунаправленно)
async fn proxy_connection(inbound: TcpStream, target: SocketAddr) -> Result<()> {
    let outbound = TcpStream::connect(target)
        .await
        .context("Failed to connect to target")?;

    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_server = tokio::spawn(async move { io::copy(&mut ri, &mut wo).await });
    let server_to_client = tokio::spawn(async move { io::copy(&mut ro, &mut wi).await });

    let (result_a, result_b) = tokio::join!(client_to_server, server_to_client);

    result_a.context("Client→Server copy failed")??;
    result_b.context("Server→Client copy failed")??;

    Ok(())
}
