use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use std::convert::TryInto;
use std::path::Path;
use std::net::SocketAddr;
use crossterm::{
    cursor,
    execute,
    style::{Print, Color, SetForegroundColor, ResetColor},
    terminal::{Clear, ClearType, size, enable_raw_mode, disable_raw_mode},
    event::{self, Event, KeyCode, KeyModifiers},
};
use std::io::stdout;
use anyhow::Result;
use std::time::{Instant, SystemTime};
use chrono::Local;
use std::io::Write;
use std::future;

// -------------------- CONSTANTS --------------------
const MAX_UDP_PAYLOAD: usize = 65507;
const MSG_PREFIX: &[u8] = b"MSG";
const ACK_PREFIX: &[u8] = b"ACK";
const WINDOW_SIZE: usize = 32;
const ACK_TIMEOUT_MS: u64 = 500;
const MAX_RETRIES: usize = 10;

// -------------------- TYPES --------------------
type FileMap = Arc<Mutex<HashMap<u32, FileBuffer>>>;
type AckMap = Arc<Mutex<HashMap<(u32, u32), bool>>>;
type TransferCounter = Arc<Mutex<u32>>;
type ChatHistory = Arc<Mutex<Vec<ChatLine>>>;
type FileTransfers = Arc<Mutex<HashMap<String, (u64, u64, TransferDirection)>>>;

#[derive(Clone, Copy, Debug)]
enum TransferDirection { Upload, Download }

struct FileBuffer {
    chunks: HashMap<u32, Vec<u8>>,
    expected_chunks: Option<u32>,
    received_size: usize,
    filename: Option<String>,
}

#[derive(Clone, Debug)]
enum ChatLine {
    Message {
        ts: chrono::DateTime<Local>,
        msg: String,
    },
    Transfer {
        ts: chrono::DateTime<Local>,
        filename: String,
        id: u32,
        done: u64,
        total: u64,
        direction: TransferDirection,
    },
}

impl std::fmt::Display for ChatLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatLine::Message { msg, .. } => write!(f, "{}", msg),
            ChatLine::Transfer { filename, done, total, .. } => {
                if filename.len() > 20 {
                    write!(f, "[T] {}… {}/{}", &filename[..20], done, total)
                } else {
                    write!(f, "[T] {} {}/{}", filename, done, total)
                }
            }
        }
    }
}

impl From<String> for ChatLine {
    fn from(s: String) -> Self { ChatLine::Message { ts: Local::now(), msg: s } }
}
impl From<&str> for ChatLine {
    fn from(s: &str) -> Self { ChatLine::Message { ts: Local::now(), msg: s.to_string() } }
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
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let period_index = now / 60;
    let mut hasher = Sha1::new();
    hasher.update(secret_bytes);
    hasher.update(&period_index.to_be_bytes());
    let digest = hasher.finalize();
    let slice: [u8; 4] = digest[16..20].try_into().unwrap();
    let val = u32::from_be_bytes(slice);
    base_port + (val % port_range as u32) as u16
}

fn render_progress_bar(progress: f32, width: usize, direction: TransferDirection) -> String {
    let filled = (progress * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);
    let color = match direction {
        TransferDirection::Upload => Color::Green,
        TransferDirection::Download => Color::Blue,
    };
    let mut bar = String::new();
    bar.push_str(&format!("{}{}{}", SetForegroundColor(color), "█".repeat(filled), ResetColor));
    bar.push_str(&format!("{}{}{}", SetForegroundColor(Color::DarkGrey), "░".repeat(empty), ResetColor));
    bar
}

// -------------------- TERMINAL --------------------
struct TerminalGuard;
impl TerminalGuard {
    fn new() -> Self { enable_raw_mode().unwrap(); TerminalGuard }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        disable_raw_mode().unwrap();
        let mut stdout = stdout();
        let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0,0));
    }
}

// -------------------- SEND CHAT MESSAGE --------------------
async fn send_chat_message(socket: Arc<UdpSocket>, target: SocketAddr, msg: &str) -> Result<()> {
    let mut buf = Vec::with_capacity(3 + msg.len());
    buf.extend_from_slice(MSG_PREFIX);
    buf.extend_from_slice(msg.as_bytes());
    socket.send_to(&buf, target).await?;
    Ok(())
}

// -------------------- TERMINAL LOOP --------------------
async fn terminal_loop(
    chat: ChatHistory,
    socket: Arc<UdpSocket>,
    last_client: Arc<Mutex<Option<SocketAddr>>>,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
) {
    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input_buffer = String::new();

    execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0)).unwrap();

    let mut screen_buf: Vec<String> = Vec::new();
    let mut last_file_snapshot: Vec<(String, u64, u64, TransferDirection)> = Vec::new();
    let mut last_progress_update = Instant::now();
    let progress_rate = Duration::from_millis(200);
    let mut scroll_offset = 0usize;
    let mut user_scrolled = false;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                disable_raw_mode().unwrap();
                execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0,0)).unwrap();
                println!("Exiting gracefully...");
                std::process::exit(0);
            }
            _ = async {
                let (cols, rows) = size().unwrap_or((100,30));
                let input_row = rows.saturating_sub(1);
                let visible_rows = rows as usize - 1;

                let mut lines: Vec<String> = Vec::new();

                // CHAT
                { let chat_lock = chat.lock().await;
                  for entry in chat_lock.iter() {
                      let ts = match entry {
                          ChatLine::Message { ts, .. } => ts,
                          ChatLine::Transfer { ts, .. } => ts,
                      };
                      lines.push(format!("[{}] {}", ts.format("%H:%M:%S"), entry.to_string()));
                  }
                }

                // FILE TRANSFERS
                if last_progress_update.elapsed() >= progress_rate {
                    let mut ft_lock = file_transfers.lock().await;
                    last_file_snapshot.clear();
                    let mut to_remove = Vec::new();

                    for (filename, &(done, total, direction)) in ft_lock.iter() {
                        if done >= total {
                            to_remove.push(filename.clone());
                        } else {
                            last_file_snapshot.push((filename.clone(), done, total, direction));
                        }
                    }

                    for fname in to_remove {
                        ft_lock.remove(&fname);
                    }

                    last_progress_update = Instant::now();
                }

                // SCROLL
                let total_lines = lines.len();
                let max_scroll = total_lines.saturating_sub(visible_rows);
                if !user_scrolled { scroll_offset = max_scroll; } else { scroll_offset = std::cmp::min(scroll_offset, max_scroll); }
                let visible_lines = &lines[scroll_offset..];

                // DRAW
                for (i,line) in visible_lines.iter().enumerate() {
                    if screen_buf.get(i) != Some(line) {
                        execute!(stdout, cursor::MoveTo(0,i as u16), Clear(ClearType::CurrentLine),
                            SetForegroundColor(Color::White), Print(line.chars().take(cols as usize).collect::<String>()), ResetColor).unwrap();
                    }
                }
                screen_buf = visible_lines.to_vec();

                // INPUT
                execute!(stdout, cursor::MoveTo(0,input_row), Clear(ClearType::CurrentLine), Print(&input_buffer), cursor::MoveTo(input_buffer.len() as u16, input_row)).unwrap();
                stdout.flush().unwrap();

                // HANDLE INPUT
                if event::poll(Duration::from_millis(50)).unwrap() {
                    if let Event::Key(key_event) = event::read().unwrap() {
                        match key_event.code {
                            KeyCode::Char(c) => { 
                                if key_event.modifiers.contains(KeyModifiers::CONTROL) && c=='c' {
                                    disable_raw_mode().unwrap(); execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0,0)).unwrap(); println!("Exiting..."); std::process::exit(0);
                                }
                                input_buffer.push(c); user_scrolled=false;
                            },
                            KeyCode::Backspace => { input_buffer.pop(); user_scrolled=false; },
                            KeyCode::Enter => {
                                if !input_buffer.is_empty() {
                                    let input = input_buffer.clone();
                                    input_buffer.clear();
                                    user_scrolled = false;

                                    if input.starts_with("/send ") {
                                        if let Some(path) = input.strip_prefix("/send ") {
                                            let path_owned = path.to_string();
                                            if let Some(target) = *last_client.lock().await {
                                                let socket_clone = socket.clone();
                                                let ack_clone = ack_map.clone();
                                                let counter_clone = transfer_counter.clone();
                                                let chat_clone = chat.clone();
                                                let file_transfers_clone = file_transfers.clone();

                                                tokio::spawn(async move {
                                                    let file_id = SystemTime::now()
                                                        .duration_since(SystemTime::UNIX_EPOCH)
                                                        .unwrap()
                                                        .as_millis() as u32;

                                                    match send_file(
                                                        socket_clone,
                                                        target,
                                                        path_owned,
                                                        ack_clone,
                                                        file_id,
                                                        counter_clone,
                                                        chat_clone,
                                                        file_transfers_clone,
                                                    ).await {
                                                        Ok(_) => {},
                                                        Err(e) => println!("Error sending file: {:?}", e),
                                                    }
                                                });
                                            }
                                        }
                                    } else {
                                        if let Some(target) = *last_client.lock().await {
                                            let _ = send_chat_message(socket.clone(), target, &input).await;
                                            chat.lock().await.push(ChatLine::Message { ts: Local::now(), msg: format!("You: {}", input) });
                                        }
                                    }
                                }
                            },
                            KeyCode::Esc => { input_buffer.clear(); },
                            KeyCode::Up => { if scroll_offset>0 { scroll_offset-=1; user_scrolled=true; } },
                            KeyCode::Down => { if scroll_offset<max_scroll { scroll_offset+=1; user_scrolled=true; } },
                            KeyCode::PageUp => { scroll_offset = scroll_offset.saturating_sub(visible_rows/2); user_scrolled=true; },
                            KeyCode::PageDown => { scroll_offset = std::cmp::min(scroll_offset + visible_rows/2,max_scroll); user_scrolled=true; },
                            _ => {}
                        }
                    }
                }

                tokio::task::yield_now().await;
            } => {}
        }
    }
}

// -------------------- FILE CHUNK HANDLING --------------------
async fn handle_file_chunk(
    buf: &[u8],
    len: usize,
    src: SocketAddr,
    files: FileMap,
    socket: Arc<UdpSocket>,
    transfer_counter: TransferCounter,
    chat: ChatHistory,
    last_client: Arc<Mutex<Option<SocketAddr>>>,
    file_transfers: FileTransfers,
) {
    if len < 9 { return; }

    let file_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let chunk_index: u32 = u32::from_be_bytes(buf[4..8].try_into().unwrap());

    let mut offset = 9;
    let mut total_chunks = None;

    let filename_opt = if chunk_index == 0 {
        let name_len = buf[offset] as usize;
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

    // Update chat + file_transfers progress
    if let Some(fname) = &entry.filename {
        let done = entry.chunks.len() as u64;
        let total = entry.expected_chunks.unwrap_or(1) as u64;

        let mut ft = file_transfers.lock().await;
        ft.insert(fname.clone(), (done, total, TransferDirection::Download));

        let mut c = chat.lock().await;
        if let Some(pos) = c.iter_mut().rposition(|line| match line {
            ChatLine::Transfer { filename, id, .. } => filename == fname && *id == file_id,
            _ => false,
        }) {
            if let ChatLine::Transfer { done: d, total: t, .. } = &mut c[pos] {
                *d = done;
                *t = total;
            }
        } else {
            c.push(ChatLine::Transfer {
                ts: Local::now(),
                id: file_id,
                filename: fname.clone(),
                done,
                total,
                direction: TransferDirection::Download,
            });
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
            if *counter > 0 { *counter -= 1; }

            chat.lock().await.push(ChatLine::Message { ts: Local::now(), msg: format!("Saved received file '{}' from {}", filename, src) });
        }
    }

    *last_client.lock().await = Some(src);
}

// -------------------- SEND FILE WITH LIVE PROGRESS --------------------
async fn send_file(
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    path: String,
    ack_map: AckMap,
    file_id: u32,
    transfer_counter: TransferCounter,
    chat: ChatHistory,
    file_transfers: FileTransfers,
) -> Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();
    let buffer_size = MAX_UDP_PAYLOAD - 512;
    let mut buffer = vec![0u8; buffer_size];

    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or("unknown_file".to_string());

    let total_chunks = ((file_size + buffer_size as u64 - 1)/buffer_size as u64) as u32;

    {
        let mut counter = transfer_counter.lock().await;
        *counter += 1;
    }

    // initialize progress
    file_transfers.lock().await.insert(filename.clone(), (0, total_chunks as u64, TransferDirection::Upload));
    chat.lock().await.push(ChatLine::Transfer {
        ts: Local::now(),
        id: file_id,
        filename: filename.clone(),
        done: 0,
        total: total_chunks as u64,
        direction: TransferDirection::Upload,
    });

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut chunk_index: u32 = 0;
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 { break; }

        let mut packet = Vec::with_capacity(n + 512);
        packet.extend_from_slice(&file_id.to_be_bytes());
        packet.extend_from_slice(&chunk_index.to_be_bytes());
        packet.push(0); // reserved

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

    let mut sent_index = 0usize;
    let mut retries = vec![0usize; chunks.len()];

    while sent_index < chunks.len() {
        let window_end = (sent_index + WINDOW_SIZE).min(chunks.len());
        for i in sent_index..window_end {
            if retries[i] >= MAX_RETRIES { continue; }
            let _ = socket.send_to(&chunks[i], server_addr).await;
        }

        sleep(Duration::from_millis(ACK_TIMEOUT_MS)).await;

        // Move window for ACKs
        {
            let mut map = ack_map.lock().await;
            while sent_index < chunks.len() && map.remove(&(file_id, sent_index as u32)).is_some() {
                // update progress
                let mut ft = file_transfers.lock().await;
                if let Some((done, _, _)) = ft.get_mut(&filename) {
                    *done += 1;
                }

                let mut c = chat.lock().await;
                if let Some(pos) = c.iter_mut().rposition(|line| match line {
                    ChatLine::Transfer { id, .. } => *id == file_id,
                    _ => false,
                }) {
                    if let ChatLine::Transfer { done: d, .. } = &mut c[pos] {
                        *d += 1;
                    }
                }

                sent_index += 1;
            }
        }

        for i in sent_index..window_end {
            let map = ack_map.lock().await;
            if !map.contains_key(&(file_id, i as u32)) {
                retries[i] += 1;
                if retries[i] > MAX_RETRIES {
                    let mut counter = transfer_counter.lock().await;
                    if *counter > 0 { *counter -=1; }
                    return Err(anyhow::anyhow!("Failed chunk {}", i));
                }
            }
        }
    }

    // finish
    let mut counter = transfer_counter.lock().await;
    if *counter > 0 { *counter -=1; }
    chat.lock().await.push(ChatLine::Message { ts: Local::now(), msg: format!("Finished sending '{}'", filename) });
    file_transfers.lock().await.remove(&filename);

    Ok(())
}

// -------------------- RECEIVER --------------------
fn spawn_receiver(
    socket: Arc<UdpSocket>,
    chat: ChatHistory,
    files: FileMap,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    last_client: Arc<Mutex<Option<SocketAddr>>>,
    file_transfers: FileTransfers,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if len >= 3 && &buf[..3] == MSG_PREFIX {
                        let msg = String::from_utf8_lossy(&buf[3..len]).to_string();
                        chat.lock().await.push(ChatLine::Message { ts: Local::now(), msg: format!("{} says: {}", src, msg) });
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
                            chat.clone(),
                            last_client.clone(),
                            file_transfers.clone(),
                        ).await;
                    }
                }
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    });
}

// -------------------- SERVER LOOP --------------------
async fn run_server(cli: Cli) -> Result<()> {
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let secret_bytes = secret_to_bytes(&cli.secret);
    let current_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", current_port)).await?);
    println!("Server listening on port {}", current_port);

    {
        let chat_clone = chat_history.clone();
        let socket_clone = socket.clone();
        let last_clone = last_client.clone();
        let ack_clone = ack_map.clone();
        let counter_clone = transfer_counter.clone();
        let transfers_clone = file_transfers.clone();
        tokio::spawn(async move {
            let _guard = TerminalGuard::new();
            terminal_loop(
                chat_clone,
                socket_clone,
                last_clone,
                ack_clone,
                counter_clone,
                transfers_clone,
            ).await;
        });
    }

    spawn_receiver(
        socket.clone(),
        chat_history.clone(),
        files.clone(),
        ack_map.clone(),
        transfer_counter.clone(),
        last_client.clone(),
        file_transfers.clone(),
    );

    future::pending::<()>().await;
    Ok(())
}

// -------------------- CLIENT LOOP --------------------
async fn run_client(cli: Cli, server: String) -> Result<()> {
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));

    let secret_bytes = secret_to_bytes(&cli.secret);
    let server_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(
        Some(format!("{}:{}", server, compute_port(&secret_bytes, cli.base_port, cli.port_range))
            .parse()?),
    ));

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    println!("Client bound to {}", socket.local_addr()?);

    {
        let chat_clone = chat_history.clone();
        let socket_clone = socket.clone();
        let last_client = server_addr.clone();
        let ack_clone = ack_map.clone();
        let counter_clone = transfer_counter.clone();
        let transfers_clone = file_transfers.clone();

        tokio::spawn(async move {
            let _guard = TerminalGuard::new();
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

    spawn_receiver(
        socket.clone(),
        chat_history.clone(),
        files.clone(),
        ack_map.clone(),
        transfer_counter.clone(),
        Arc::new(Mutex::new(None)),
        file_transfers.clone(),
    );

    future::pending::<()>().await;
    Ok(())
}

// -------------------- MAIN --------------------
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.role {
        Role::Server => { println!("Starting server..."); run_server(cli.clone()).await?; }
        Role::Client { server } => { println!("Starting client connecting to {}...", server); run_client(cli.clone(), server.clone()).await?; }
    }
    Ok(())
}


