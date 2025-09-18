use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::io::{self, AsyncBufReadExt, BufReader, AsyncReadExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use std::convert::TryInto;
use std::fs::Metadata;
use rand::RngCore;
use std::path::Path;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

const MAX_UDP_PAYLOAD: usize = 65507;
const ACK_PREFIX: &[u8] = b"ACK";
const MSG_PREFIX: &[u8] = b"MSG";
const WINDOW_SIZE: usize = 32;
const ACK_TIMEOUT_MS: u64 = 500;
const MAX_RETRIES: usize = 10;
const SOCKET_IDLE_TIMEOUT: u64 = 10; // seconds
const DRAIN_TIMEOUT_SECS: u64 = 2; // how long to drain an old socket

// -------------------- TYPES --------------------
pub type FileMap = Arc<Mutex<HashMap<u32, FileBuffer>>>;
pub type AckMap = Arc<Mutex<HashMap<(u32, u32), bool>>>;
pub type TransferCounter = Arc<Mutex<u32>>;

pub struct FileBuffer {
    pub chunks: HashMap<u32, Vec<u8>>,
    pub expected_chunks: Option<u32>,
    pub received_size: usize,
    pub filename: Option<String>,
}

pub struct TrackedSocket {
    pub socket: Arc<UdpSocket>,
    pub last_active: Arc<Mutex<Instant>>,
    pub cancel_token: CancellationToken,
    pub handle: JoinHandle<()>,
}

// -------------------- CLI --------------------
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    role: Role,
    #[arg(short, long, default_value = "4000")]
    base_port: u16,
    #[arg(short, long, default_value = "1000")]
    port_range: u16,
    #[arg(short, long)]
    secret: String,
}

#[derive(Subcommand)]
enum Role {
    Server,
    Client { #[arg(short, long, default_value = "127.0.0.1")] server: String },
}

// -------------------- MAIN --------------------
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.role {
        Role::Server => run_server(cli.base_port, cli.port_range, cli.secret).await?,
        Role::Client { server } => run_client(server, cli.base_port, cli.port_range, cli.secret).await?,
    }
    Ok(())
}

// -------------------- SECRET → BYTES --------------------
fn secret_to_bytes(secret: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

// -------------------- SIMPLE ROLLING PORT --------------------
fn compute_port(secret_bytes: &[u8], base_port: u16, port_range: u16) -> u16 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let period_index = now / 60;
    let mut hasher = Sha1::new();
    hasher.update(secret_bytes);
    hasher.update(&period_index.to_be_bytes());
    let digest = hasher.finalize();
    let slice: [u8;4] = digest[16..20].try_into().unwrap();
    let val = u32::from_be_bytes(slice);
    base_port + (val % port_range as u32) as u16
}

// -------------------- DRAIN SOCKET --------------------
async fn drain_socket(
    socket: Arc<UdpSocket>,
    files: FileMap,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
) {
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    let start = Instant::now();
    let timeout = Duration::from_secs(DRAIN_TIMEOUT_SECS);

    loop {
        tokio::select! {
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, src)) => {
                        if len >= 11 && &buf[..3] == ACK_PREFIX {
                            let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                            let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                            ack_map.lock().await.insert((file_id, chunk_index), true);
                        } else if len >= 9 {
                            handle_file_chunk(&buf, len, src, files.clone(), socket.clone(), transfer_counter.clone()).await;
                        } else if len >= 3 && &buf[..3] == MSG_PREFIX {
                            let msg = String::from_utf8_lossy(&buf[3..len]);
                            println!("{} says (drained): {}", src, msg);
                        }
                    }
                    Err(_) => break,
                }
            },
            _ = sleep(Duration::from_millis(50)) => {
                if start.elapsed() >= timeout {
                    break;
                }
            }
        }
    }
}

// -------------------- SERVER --------------------
async fn run_server(base_port: u16, port_range: u16, secret: String) -> anyhow::Result<()> {
    let secret_bytes = secret_to_bytes(&secret);
    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_in_progress: TransferCounter = Arc::new(Mutex::new(0));
    let tracked_sockets: Arc<Mutex<Vec<TrackedSocket>>> = Arc::new(Mutex::new(Vec::new()));

    // ---------------- Spawn Cleanup Task ----------------
    {
        let tracked_sockets_clone = tracked_sockets.clone();
        let files_clone = files.clone();
        let ack_map_clone = ack_map.clone();
        let transfer_clone = transfer_in_progress.clone();

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let now = Instant::now();
                let mut sockets_guard = tracked_sockets_clone.lock().await;

                let mut i = 0;
                while i < sockets_guard.len() {
                    let ts = &sockets_guard[i];
                    let last = *ts.last_active.lock().await;

                    if now.duration_since(last).as_secs() >= SOCKET_IDLE_TIMEOUT {
                        println!("Closing idle socket...");
                        ts.cancel_token.cancel();
                        ts.handle.abort();

                        // Clone inside the loop for drain_socket
                        let socket_clone = ts.socket.clone();
                        let files_clone2 = files_clone.clone();
                        let ack_map_clone2 = ack_map_clone.clone();
                        let transfer_clone2 = transfer_clone.clone();

                        tokio::spawn(async move {
                            drain_socket(socket_clone, files_clone2, ack_map_clone2, transfer_clone2).await;
                        });

                        sockets_guard.remove(i);
                    } else {
                        i += 1;
                    }
                }
            }
        });
    }


    // ---------------- Main Port Loop ----------------
    {
        let secret_bytes_clone = secret_bytes.clone();
        let tracked_sockets_clone = tracked_sockets.clone();
        let files_clone = files.clone();
        let ack_map_clone = ack_map.clone();
        let transfer_clone = transfer_in_progress.clone();
        let last_client_clone = last_client.clone();

        tokio::spawn(async move {
            let mut previous_port: Option<u16> = None;

            loop {
                let port = compute_port(&secret_bytes_clone, base_port, port_range);
                if Some(port) != previous_port {
                    previous_port = Some(port);

                    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
                    let socket = Arc::new(UdpSocket::bind(addr).await.unwrap());
                    let last_active = Arc::new(Mutex::new(Instant::now()));
                    let cancel_token = CancellationToken::new();
                    let cancel_child = cancel_token.child_token();

                    println!("Server listening on UDP port {}", port);

                    // ---------------- Receiver ----------------
                    let socket_clone = socket.clone();
                    let last_client_clone2 = last_client_clone.clone();
                    let files_clone2 = files_clone.clone();
                    let ack_map_clone2 = ack_map_clone.clone();
                    let transfer_clone2 = transfer_clone.clone();
                    let last_active_clone = last_active.clone();

                    let handle = tokio::spawn(async move {
                        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
                        loop {
                            tokio::select! {
                                biased;
                                _ = cancel_child.cancelled() => {
                                    println!("Receiver loop on port {} cancelled", port);
                                    break;
                                }
                                result = socket_clone.recv_from(&mut buf) => {
                                    match result {
                                        Ok((len, src)) => {
                                            *last_active_clone.lock().await = Instant::now();
                                            if len >= 3 && &buf[..3] == MSG_PREFIX {
                                                let msg = String::from_utf8_lossy(&buf[3..len]);
                                                println!("{} says: {}", src, msg);
                                                *last_client_clone2.lock().await = Some(src);
                                            } else if len >= 11 && &buf[..3] == ACK_PREFIX {
                                                let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                                                let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                                                ack_map_clone2.lock().await.insert((file_id, chunk_index), true);
                                            } else if len >= 9 {
                                                handle_file_chunk(
                                                    &buf,
                                                    len,
                                                    src,
                                                    files_clone2.clone(),
                                                    socket_clone.clone(),
                                                    transfer_clone2.clone()
                                                ).await;
                                            }
                                        }
                                        Err(_) => sleep(Duration::from_millis(50)).await,
                                    }
                                }
                            }
                        }
                    });

                    // Track the socket
                    tracked_sockets_clone.lock().await.push(TrackedSocket {
                        socket: socket.clone(),
                        last_active: last_active.clone(),
                        cancel_token,
                        handle,
                    });
                }

                sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // ---------------- Stdin → Client ----------------
    {
        let last_client_clone = last_client.clone();
        let ack_map_clone = ack_map.clone();
        let transfer_clone = transfer_in_progress.clone();
        let tracked_sockets_clone = tracked_sockets.clone();

        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut reader = tokio::io::BufReader::new(stdin).lines();

            while let Ok(Some(line)) = reader.next_line().await {
                if let Some(addr) = *last_client_clone.lock().await {
                    let socket_opt = tracked_sockets_clone.lock().await.last().map(|ts| ts.socket.clone());
                    if let Some(socket) = socket_opt {
                        if line.starts_with("/sendfile ") {
                            let path = line[10..].trim().to_string();
                            let socket2 = socket.clone();
                            let ack_map2 = ack_map_clone.clone();
                            let transfer2 = transfer_clone.clone();
                            tokio::spawn(async move {
                                let file_id: u32 = rand::thread_rng().next_u32();
                                *transfer2.lock().await += 1;
                                send_file(
                                    &socket2,
                                    &addr,
                                    &path,
                                    ack_map2,
                                    std::fs::metadata(&path).ok(),
                                    file_id,
                                    transfer2.clone()
                                ).await.ok();
                            });
                        } else {
                            let mut msg_packet = Vec::new();
                            msg_packet.extend_from_slice(MSG_PREFIX);
                            msg_packet.extend_from_slice(line.as_bytes());
                            let _ = socket.send_to(&msg_packet, addr).await;
                        }
                    }
                }
            }
        });
    }

    loop { sleep(Duration::from_secs(60)).await; }
}


// -------------------- CLIENT --------------------
async fn run_client(server: String, base_port: u16, port_range: u16, secret: String) -> anyhow::Result<()> {
    let secret_bytes = secret_to_bytes(&secret);
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_in_progress: TransferCounter = Arc::new(Mutex::new(0));

    let server_addr: Arc<Mutex<std::net::SocketAddr>> = Arc::new(Mutex::new(
        format!("{}:{}", server, compute_port(&secret_bytes, base_port, port_range))
            .parse()?
    ));

    // ----------- Receiver -----------
    {
        let socket_clone = socket.clone();
        let ack_map_clone = ack_map.clone();
        let files_clone = files.clone();
        let transfer_clone = transfer_in_progress.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if len >= 3 && &buf[..3] == MSG_PREFIX {
                            let msg = String::from_utf8_lossy(&buf[3..len]);
                            println!("{} says: {}", src, msg);
                        } else if len >= 11 && &buf[..3] == ACK_PREFIX {
                            let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                            let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                            ack_map_clone.lock().await.insert((file_id, chunk_index), true);
                        } else if len >= 9 {
                            handle_file_chunk(&buf, len, src, files_clone.clone(), socket_clone.clone(), transfer_clone.clone()).await;
                        }
                    },
                    Err(_) => sleep(Duration::from_millis(50)).await,
                }
            }
        });
    }

    // ----------- Stdin → Server -----------
    {
        let socket_clone = socket.clone();
        let server_addr_clone = server_addr.clone();
        let ack_map_clone2 = ack_map.clone();
        let transfer_clone = transfer_in_progress.clone();

        tokio::spawn(async move {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin).lines();

            while let Ok(Some(line)) = reader.next_line().await {
                let addr = *server_addr_clone.lock().await;
                if line.starts_with("/sendfile ") {
                    let path = line[10..].trim().to_string();
                    let socket2 = socket_clone.clone();
                    let addr2 = addr;
                    let ack_map2 = ack_map_clone2.clone();
                    let transfer2 = transfer_clone.clone();
                    tokio::spawn(async move {
                        let file_id: u32 = rand::thread_rng().next_u32();
                        *transfer2.lock().await += 1;
                        send_file(&socket2, &addr2, &path, ack_map2, std::fs::metadata(&path).ok(), file_id, transfer2.clone()).await.ok();
                    });
                } else {
                    let mut msg_packet = Vec::new();
                    msg_packet.extend_from_slice(MSG_PREFIX);
                    msg_packet.extend_from_slice(line.as_bytes());
                    let _ = socket_clone.send_to(&msg_packet, addr).await;
                }
            }
        });
    }

    // ----------- Port Updater Task -----------
    {
        let server_addr_clone = server_addr.clone();
        let secret_bytes_clone = secret_bytes.clone();
        tokio::spawn(async move {
            let mut previous_port: Option<u16> = None;
            loop {
                sleep(Duration::from_secs(1)).await;
                let new_port = compute_port(&secret_bytes_clone, base_port, port_range);
                if Some(new_port) != previous_port {
                    previous_port = Some(new_port);
                    let mut addr_guard = server_addr_clone.lock().await;
                    *addr_guard = format!("{}:{}", server, new_port).parse::<std::net::SocketAddr>().unwrap();
                    println!("Updated server port to {}", new_port);
                }
            }
        });
    }

    loop { sleep(Duration::from_secs(60)).await; }
}

// -------------------- SEND FILE (SLIDING WINDOW) ----------------
async fn send_file(
    socket: &UdpSocket,
    server_addr: &std::net::SocketAddr,
    path: &str,
    ack_map: AckMap,
    _metadata: Option<Metadata>,
    file_id: u32,
    transfer_counter: TransferCounter,
) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0u8; MAX_UDP_PAYLOAD - 512];
    let filename = Path::new(path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "unknown_file".to_string());

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut chunk_index: u32 = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 { break; }
        let last_chunk: u8 = if n < buffer.len() { 1 } else { 0 };
        let mut packet = Vec::with_capacity(n + 512);
        packet.extend_from_slice(&file_id.to_be_bytes());
        packet.extend_from_slice(&chunk_index.to_be_bytes());
        packet.push(last_chunk);

        if chunk_index == 0 {
            let fname_bytes = filename.as_bytes();
            packet.push(fname_bytes.len() as u8);
            packet.extend_from_slice(fname_bytes);
        }

        packet.extend_from_slice(&buffer[..n]);
        chunks.push(packet);
        chunk_index += 1;
    }

    println!("Sending {} chunks for file {} (id={})", chunks.len(), path, file_id);
    let mut sent_index: usize = 0;
    let mut retries: Vec<usize> = vec![0; chunks.len()];

    while sent_index < chunks.len() {
        let window_end = (sent_index + WINDOW_SIZE).min(chunks.len());
        for i in sent_index..window_end {
            if retries[i] >= MAX_RETRIES { continue; }
            let _ = socket.send_to(&chunks[i], server_addr).await;
        }

        sleep(Duration::from_millis(ACK_TIMEOUT_MS)).await;

        let mut map = ack_map.lock().await;
        while sent_index < chunks.len() && map.remove(&(file_id, sent_index as u32)).is_some() {
            sent_index += 1;
        }

        for i in sent_index..window_end {
            if !map.contains_key(&(file_id, i as u32)) {
                retries[i] += 1;
                if retries[i] > MAX_RETRIES {
                    *transfer_counter.lock().await -= 1;
                    return Err(anyhow::anyhow!("Failed to send chunk {}", i));
                }
            }
        }
    }

    println!("File {} sent successfully ({} chunks)", path, chunks.len());
    *transfer_counter.lock().await -= 1;
    Ok(())
}

// -------------------- HANDLE FILE CHUNK --------------------
pub async fn handle_file_chunk(
    buf: &[u8],
    len: usize,
    src: std::net::SocketAddr,
    files: FileMap,
    socket: Arc<UdpSocket>,
    transfer_counter: TransferCounter,
) {
    if len < 9 { return; }

    let file_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let chunk_index = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let last_chunk_flag = buf[8];

    let mut offset: usize = 9;
    let filename_opt: Option<String>;
    if chunk_index == 0 {
        let name_len = buf[9] as usize;
        offset += 1;
        filename_opt = Some(String::from_utf8_lossy(&buf[offset..offset + name_len]).to_string());
        offset += name_len;
    } else {
        filename_opt = None;
    }

    let payload = buf[offset..len].to_vec();

    let mut files_lock = files.lock().await;
    let entry = files_lock.entry(file_id).or_insert(FileBuffer {
        chunks: HashMap::new(),
        expected_chunks: None,
        received_size: 0,
        filename: filename_opt.clone(),
    });

    entry.received_size += payload.len();
    entry.chunks.insert(chunk_index, payload);

    if last_chunk_flag == 1 {
        entry.expected_chunks = Some(chunk_index);
    }

    if filename_opt.is_some() {
        entry.filename.get_or_insert_with(|| filename_opt.clone().unwrap());
    }

    // send ACK
    let mut ack = Vec::with_capacity(11);
    ack.extend_from_slice(b"ACK");
    ack.extend_from_slice(&file_id.to_be_bytes());
    ack.extend_from_slice(&chunk_index.to_be_bytes());
    let _ = socket.send_to(&ack, src).await;

    // assemble file if all chunks received
    if let Some(last_idx) = entry.expected_chunks {
        if entry.chunks.len() as u32 == last_idx + 1 {
            let mut assembled = Vec::new();
            for i in 0..=last_idx {
                if let Some(chunk) = entry.chunks.remove(&i) {
                    assembled.extend_from_slice(&chunk);
                }
            }

            let filename = entry.filename.clone().unwrap_or_else(|| format!("received_file_{}.dat", file_id));
            if let Err(e) = tokio::fs::write(&filename, &assembled).await {
                eprintln!("\nFailed to write file {}: {}", filename, e);
            } else {
                println!("\nFile {} received successfully ({} bytes) from {}", filename, assembled.len(), src);
            }

            files_lock.remove(&file_id);
            *transfer_counter.lock().await -= 1;
        }
    }
}
