use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use std::convert::TryInto;
use rand::RngCore;
use std::path::Path;
use std::net::SocketAddr;
use crossterm::{
    cursor,
    execute,
    style::Print,
    terminal::{Clear, ClearType, size, enable_raw_mode, disable_raw_mode},
};
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use std::future;
use std::io::{stdout, Write};

const MAX_UDP_PAYLOAD: usize = 65507;
const ACK_PREFIX: &[u8] = b"ACK";
const MSG_PREFIX: &[u8] = b"MSG";
const WINDOW_SIZE: usize = 32;
const ACK_TIMEOUT_MS: u64 = 500;
const MAX_RETRIES: usize = 10;

type FileMap = Arc<Mutex<HashMap<u32, FileBuffer>>>;
type AckMap = Arc<Mutex<HashMap<(u32, u32), bool>>>;
type TransferCounter = Arc<Mutex<u32>>;
type ChatHistory = Arc<Mutex<Vec<String>>>;
type FileTransfers = Arc<Mutex<Vec<(String, u64, u64)>>>;

struct FileBuffer {
    chunks: HashMap<u32, Vec<u8>>,
    expected_chunks: Option<u32>,
    received_size: usize,
    filename: Option<String>,
}

// -------------------- CLI --------------------
#[derive(Parser, Clone)]
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

#[derive(Subcommand, Clone)]
enum Role {
    Server,
    Client { #[arg(short, long, default_value = "127.0.0.1")] server: String },
}

// -------------------- UTILS --------------------
fn secret_to_bytes(secret: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

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
    let slice: [u8; 4] = digest[16..20].try_into().unwrap();
    let val = u32::from_be_bytes(slice);
    base_port + (val % port_range as u32) as u16
}

// -------------------- INPUT & RENDER LOOP --------------------
async fn terminal_loop(
    chat: ChatHistory,
    socket: Arc<UdpSocket>,
    last_client: Arc<Mutex<Option<SocketAddr>>>,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
) {
    use std::cmp::min;

    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input_buffer = String::new();

    // Clear screen once at start
    execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0)).unwrap();

    let mut last_chat_len = 0;
    let mut last_file_transfers: Vec<(String, u64, u64)> = Vec::new();

    loop {
        let (cols, rows) = size().unwrap_or((100, 30));
        let chat_width = (cols * 2 / 3) as usize;
        let file_width = (cols - chat_width as u16) as usize;
        let input_row = rows.saturating_sub(1); // bottom row
        let visible_chat_rows = rows as usize - 1; // all rows above input

        // -------------------- CHAT --------------------
        let chat_lock = chat.lock().await;
        let total_chat_len = chat_lock.len();

        // Determine visible slice for scrolling
        let start_index = total_chat_len.saturating_sub(visible_chat_rows);
        let visible_chat = &chat_lock[start_index..];

        // Only redraw changed lines
        for (i, msg) in visible_chat.iter().enumerate() {
            let color = if msg.starts_with("You:") { Color::Green } else { Color::Yellow };
            execute!(
                stdout,
                cursor::MoveTo(0, i as u16),
                Clear(ClearType::CurrentLine),
                SetForegroundColor(color),
                Print(msg.chars().take(chat_width).collect::<String>()),
                ResetColor
            ).unwrap();
        }
        last_chat_len = total_chat_len;
        drop(chat_lock);

        // -------------------- FILE TRANSFERS --------------------
        let transfers_lock = file_transfers.lock().await;
        for (i, (filename, done, total)) in transfers_lock.iter().enumerate() {
            if last_file_transfers.get(i) != Some(&(filename.clone(), *done, *total)) {
                let bar_len = min(((*done * file_width as u64) / (*total).max(1)) as usize, file_width);
                let completed = "=".repeat(bar_len);
                let remaining = " ".repeat(file_width - bar_len);

                execute!(
                    stdout,
                    cursor::MoveTo(chat_width as u16, i as u16),
                    Clear(ClearType::CurrentLine),
                    SetForegroundColor(Color::White),
                    Print(format!("{:15} [", filename)),
                    ResetColor,
                    SetForegroundColor(Color::Green),
                    Print(completed),
                    ResetColor,
                    SetForegroundColor(Color::DarkGrey),
                    Print(remaining),
                    ResetColor,
                    SetForegroundColor(Color::White),
                    Print(format!("] {}/{}", done, total)),
                    ResetColor
                ).unwrap();
            }
        }
        last_file_transfers = transfers_lock.clone();
        drop(transfers_lock);

        // -------------------- INPUT LINE --------------------
        execute!(
            stdout,
            cursor::MoveTo(0, input_row),
            Clear(ClearType::CurrentLine),
            Print(&input_buffer),
            cursor::MoveTo(input_buffer.len() as u16, input_row)
        ).unwrap();

        stdout.flush().unwrap();

        // -------------------- INPUT HANDLING --------------------
        if event::poll(Duration::from_millis(50)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char(c) => {
                        if key_event.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                            break;
                        }
                        input_buffer.push(c);
                    }
                    KeyCode::Backspace => { input_buffer.pop(); }
                    KeyCode::Enter => {
                        let line = input_buffer.trim().to_string();
                        if !line.is_empty() {
                            if line.starts_with("/sendfile ") {
                                let path = line[10..].trim().to_string();
                                if let Some(addr) = *last_client.lock().await {
                                    let sock = socket.clone();
                                    let ack = ack_map.clone();
                                    let transfer = transfer_counter.clone();
                                    let transfers = file_transfers.clone();
                                    tokio::spawn(async move {
                                        let file_id: u32 = rand::thread_rng().next_u32();
                                        let _ = send_file(sock, addr, path, ack, file_id, transfer, transfers).await;
                                    });
                                } else {
                                    chat.lock().await.push("No known client to send file to".into());
                                }
                            } else {
                                if let Some(addr) = *last_client.lock().await {
                                    let mut pkt = Vec::with_capacity(3 + line.len());
                                    pkt.extend_from_slice(MSG_PREFIX);
                                    pkt.extend_from_slice(line.as_bytes());
                                    let _ = socket.send_to(&pkt, addr).await;
                                    chat.lock().await.push(format!("You: {}", line));
                                } else {
                                    chat.lock().await.push("No known client to send to".into());
                                }
                            }
                        }
                        input_buffer.clear();
                    }
                    KeyCode::Esc => { input_buffer.clear(); }
                    _ => {}
                }
            }
        }

        tokio::task::yield_now().await;
    }

    disable_raw_mode().unwrap();
}


// -------------------- FILE CHUNK HANDLING --------------------
async fn handle_file_chunk(
    buf: &[u8],
    len: usize,
    src: SocketAddr,
    files: FileMap,
    socket: Arc<UdpSocket>,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
) {
    if len < 9 { return; }

    let file_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let chunk_index: u32 = u32::from_be_bytes(buf[4..8].try_into().unwrap());

    let mut offset = 9;
    let mut total_chunks = None;

    let filename_opt = if chunk_index == 0 {
        let name_len = buf[9] as usize;
        offset += 1;
        let name = String::from_utf8_lossy(&buf[offset..offset + name_len]).to_string();
        offset += name_len;
        let total_bytes: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        offset += 4;
        total_chunks = Some(u32::from_be_bytes(total_bytes));
        Some(name)
    } else { None };

    let payload = buf[offset..len].to_vec();
    let mut files_lock = files.lock().await;

    let entry = files_lock.entry(file_id).or_insert(FileBuffer {
        chunks: HashMap::new(),
        expected_chunks: total_chunks,
        received_size: 0,
        filename: filename_opt.clone(),
    });

    entry.received_size += payload.len();
    entry.chunks.insert(chunk_index, payload);

    // Update file transfers
    if let Some(fname) = &entry.filename {
        let mut transfers = file_transfers.lock().await;
        if let Some(e) = transfers.iter_mut().find(|(name, _, _)| name == fname) {
            e.1 += 1;
        } else {
            transfers.push((fname.clone(), 1, entry.expected_chunks.unwrap_or(1) as u64));
        }
    }

    // Send ACK
    let mut ack = Vec::with_capacity(11);
    ack.extend_from_slice(ACK_PREFIX);
    ack.extend_from_slice(&file_id.to_be_bytes());
    ack.extend_from_slice(&chunk_index.to_be_bytes());
    let _ = socket.send_to(&ack, src).await;

    // Assemble file if complete
    if let Some(last_idx) = entry.expected_chunks {
        if entry.chunks.len() as u32 == last_idx {
            let mut assembled = Vec::new();
            for i in 0..last_idx {
                if let Some(chunk) = entry.chunks.remove(&i) {
                    assembled.extend_from_slice(&chunk);
                }
            }
            let filename = entry.filename.clone().unwrap_or(format!("received_file_{}.dat", file_id));
            let _ = tokio::fs::write(&filename, &assembled).await;
            files_lock.remove(&file_id);
            let mut counter = transfer_counter.lock().await;
            *counter -= 1;
        }
    }
}

// -------------------- SEND FILE --------------------
async fn send_file(
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    path: String,
    ack_map: AckMap,
    file_id: u32,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();
    let buffer_size = MAX_UDP_PAYLOAD - 512;
    let mut buffer = vec![0u8; buffer_size];

    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or("unknown_file".to_string());

    let total_chunks = ((file_size + buffer_size as u64 -1)/buffer_size as u64) as u32;
    {
        let mut counter = transfer_counter.lock().await;
        *counter +=1;
    }

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut chunk_index: u32 = 0;
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 { break; }

        let last_chunk = if n < buffer.len() { 1 } else { 0 };
        let mut packet = Vec::with_capacity(n + 512);
        packet.extend_from_slice(&file_id.to_be_bytes());
        packet.extend_from_slice(&chunk_index.to_be_bytes());
        packet.push(last_chunk);

        if chunk_index == 0 {
            let fname_bytes = filename.as_bytes();
            packet.push(fname_bytes.len() as u8);
            packet.extend_from_slice(fname_bytes);
            packet.extend_from_slice(&total_chunks.to_be_bytes());
        }
        packet.extend_from_slice(&buffer[..n]);
        chunks.push(packet);
        chunk_index += 1;
    }

    // Track in file transfers
    {
        let mut transfers = file_transfers.lock().await;
        transfers.push((filename.clone(), 0, total_chunks as u64));
    }

    let mut sent_index = 0;
    let mut retries = vec![0; chunks.len()];

    while sent_index < chunks.len() {
        let window_end = (sent_index + WINDOW_SIZE).min(chunks.len());
        for i in sent_index..window_end {
            if retries[i] >= MAX_RETRIES { continue; }
            let _ = socket.send_to(&chunks[i], server_addr).await;
        }

        sleep(Duration::from_millis(ACK_TIMEOUT_MS)).await;

        let mut map = ack_map.lock().await;
        while sent_index < chunks.len() && map.remove(&(file_id, sent_index as u32)).is_some() {
            // Update progress
            let mut transfers = file_transfers.lock().await;
            if let Some(e) = transfers.iter_mut().find(|(name, _, _)| name == &filename) {
                e.1 += 1;
            }
            sent_index += 1;
        }

        for i in sent_index..window_end {
            if !map.contains_key(&(file_id, i as u32)) {
                retries[i] += 1;
                if retries[i] > MAX_RETRIES {
                    let mut counter = transfer_counter.lock().await;
                    *counter -=1;
                    return Err(anyhow::anyhow!("Failed chunk {}", i));
                }
            }
        }
    }

    let mut counter = transfer_counter.lock().await;
    *counter -=1;
    Ok(())
}

// -------------------- RECEIVER --------------------
fn spawn_receiver(
    socket: Arc<UdpSocket>,
    chat: ChatHistory,
    files: FileMap,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
    last_client: Arc<Mutex<Option<SocketAddr>>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if len >= 3 && &buf[..3] == MSG_PREFIX {
                        let msg = String::from_utf8_lossy(&buf[3..len]).to_string();
                        chat.lock().await.push(format!("{} says: {}", src, msg));
                        *last_client.lock().await = Some(src);
                    } else if len >= 11 && &buf[..3] == ACK_PREFIX {
                        let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                        let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                        ack_map.lock().await.insert((file_id, chunk_index), true);
                    } else if len >= 9 {
                        handle_file_chunk(
                            &buf,
                            len,
                            src,
                            files.clone(),
                            socket.clone(),
                            transfer_counter.clone(),
                            file_transfers.clone(),
                        )
                        .await;
                    }
                }
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    });
}

// -------------------- SERVER LOOP --------------------
async fn run_server(cli: Cli) -> anyhow::Result<()> {
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(Vec::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));

    let secret_bytes = secret_to_bytes(&cli.secret);
    let current_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", current_port)).await?);
    println!("Server listening on port {}", current_port);

    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Terminal + input loop
    {
        let chat_clone = chat_history.clone();
        let socket_clone = socket.clone();
        let last_clone = last_client.clone();
        let ack_clone = ack_map.clone();
        let counter_clone = transfer_counter.clone();
        let transfers_clone = file_transfers.clone();
        tokio::spawn(async move {
            terminal_loop(
                chat_clone,
                socket_clone,
                last_clone,
                ack_clone,
                counter_clone,
                transfers_clone,
            )
            .await;
        });
    }

    spawn_receiver(
        socket.clone(),
        chat_history.clone(),
        files.clone(),
        ack_map.clone(),
        transfer_counter.clone(),
        file_transfers.clone(),
        last_client.clone(),
    );

    // Server port rotation
    tokio::spawn(async move {
        let mut current_port = current_port;
        loop {
            sleep(Duration::from_secs(10)).await;
            let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
            if new_port != current_port {
                println!("Rotating port {} -> {}", current_port, new_port);
                current_port = new_port;
                let new_socket = Arc::new(UdpSocket::bind(("0.0.0.0", new_port)).await.unwrap());
                spawn_receiver(
                    new_socket,
                    chat_history.clone(),
                    files.clone(),
                    ack_map.clone(),
                    transfer_counter.clone(),
                    file_transfers.clone(),
                    last_client.clone(),
                );
            }
        }
    });

    future::pending::<()>().await;
    Ok(())
}

// -------------------- CLIENT LOOP --------------------
async fn run_client(cli: Cli, server: String) -> anyhow::Result<()> {
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(Vec::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));

    let secret_bytes = secret_to_bytes(&cli.secret);

    // Wrap server_addr in Option for terminal loop
    let server_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(
        Some(format!("{}:{}", server, compute_port(&secret_bytes, cli.base_port, cli.port_range))
            .parse()?),
    ));

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    println!("Client bound to {}", socket.local_addr()?);

    // Terminal loop
    {
        let chat_clone = chat_history.clone();
        let socket_clone = socket.clone();
        let last_client = server_addr.clone();
        let ack_clone = ack_map.clone();
        let counter_clone = transfer_counter.clone();
        let transfers_clone = file_transfers.clone();

        tokio::spawn(async move {
            terminal_loop(
                chat_clone,
                socket_clone,
                last_client,
                ack_clone,
                counter_clone,
                transfers_clone,
            ).await;
        });
    }

    // Spawn receiver
    spawn_receiver(
        socket.clone(),
        chat_history.clone(),
        files.clone(),
        ack_map.clone(),
        transfer_counter.clone(),
        file_transfers.clone(),
        Arc::new(Mutex::new(None)),
    );

    // Server port rotation
    {
        let server_addr_clone = server_addr.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
                let new_addr: SocketAddr = format!("{}:{}", server, new_port).parse().unwrap();
                let mut addr_lock = server_addr_clone.lock().await;
                if *addr_lock != Some(new_addr) {
                    println!("Server port changed: {:?} -> {:?}", *addr_lock, new_addr);
                    *addr_lock = Some(new_addr);
                }
            }
        });
    }

    future::pending::<()>().await;
    Ok(())
}

// -------------------- MAIN --------------------
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.role {
        Role::Server => {
            println!("Starting server...");
            run_server(cli.clone()).await?;
        }
        Role::Client { server } => {
            println!("Starting client connecting to {}...", server);
            run_client(cli.clone(), server.clone()).await?;
        }
    }

    // Keep alive
    future::pending::<()>().await;
    Ok(())
}