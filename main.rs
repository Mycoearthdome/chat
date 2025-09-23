use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::time::{Duration};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, Notify, mpsc, broadcast};
use tokio::time::Instant;
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
    event::{self, Event, KeyCode, KeyModifiers, KeyEvent},
};
use std::io::stdout;
use anyhow::Result;
use std::time::SystemTime;
use chrono::Local;
use std::io::Write;
use std::fmt;
use std::collections::HashSet;
use std::future;

// -------------------- CONSTANTS --------------------
const MAX_UDP_PAYLOAD: usize = 65507;
const MSG_PREFIX: &[u8] = b"MSG";
const ACK_PREFIX: &[u8] = b"ACK";
const WINDOW_SIZE: usize = 1400;
const ACK_TIMEOUT_MS: u64 = 5000;
const MAX_RETRIES: usize = 10;
const HISTORY_LIMIT: usize = 50;

// -------------------- TYPES --------------------
type TransferCounter = Arc<Mutex<u32>>;
type ChatHistory = Arc<Mutex<Vec<ChatLine>>>;
type FileTransfers = Arc<Mutex<HashMap<String, (u64, u64, TransferDirection, TransferState)>>>;
type Targets = Arc<Mutex<HashSet<SocketAddr>>>;
type FileAckTracker = Arc<Mutex<HashMap<String, HashMap<SocketAddr, HashSet<u32>>>>>;

#[derive(Clone, Copy, Debug)]
enum TransferDirection { Upload, Download }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferState { InProgress, Done, Failed }

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
        state: TransferState,
    },
}

impl fmt::Display for ChatLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatLine::Message { msg, .. } => write!(f, "{}", msg),
            ChatLine::Transfer { filename, done, total, direction, state, .. } => {
                let dir = match direction {
                    TransferDirection::Upload => "↑",
                    TransferDirection::Download => "↓",
                };
                let st = match state {
                    TransferState::InProgress => "…",
                    TransferState::Done => "✔",
                    TransferState::Failed => "✘",
                };
                write!(f, "{} {} {}/{} {}", dir, filename, done, total, st)
            }
        }
    }
}

// Message representing a received chunk to be processed by the file manager.
#[derive(Debug)]
struct FileChunk {
    file_id: u32,
    chunk_index: u32,
    filename: Option<String>,
    total_chunks: Option<u32>,
    payload: Vec<u8>,
    src: SocketAddr,
}

// -------------------- TERMINAL ARGs --------------------
struct TerminalArgs {
    pub socket: Arc<UdpSocket>,
    pub targets: Arc<Mutex<HashSet<SocketAddr>>>,
    pub redraw_notify: Arc<Notify>,
    pub file_transfers: FileTransfers,
    pub ack_bcast: broadcast::Sender<(u32,u32,std::net::SocketAddr)>,
    pub transfer_counter: TransferCounter,
    pub last_client: Option<Arc<Mutex<Option<SocketAddr>>>>,
    pub chat_rx: Arc<Mutex<mpsc::Receiver<ChatLine>>>,
    pub ack_tracker: FileAckTracker,
    
}

// -------------------- CHAT UTILS --------------------
async fn chat_push_cap(chat: &ChatHistory, line: ChatLine) {
    let mut c = chat.lock().await;
    if c.len() >= HISTORY_LIMIT {
        c.remove(0);
    }
    c.push(line);
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
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let period_index = now / 60; // floor to minute

    let mut hasher = Sha1::new();
    hasher.update(secret_bytes);
    hasher.update(&period_index.to_be_bytes());
    let digest = hasher.finalize();
    let slice: [u8; 4] = digest[16..20].try_into().unwrap();
    let val = u32::from_be_bytes(slice);

    base_port + (val % port_range as u32) as u16
}

fn compute_possible_ports(secret_bytes: &[u8], base_port: u16, port_range: u16) -> Vec<u16> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let period_index = now / 60;

    (0..=1).map(|offset| {
        let idx = period_index.saturating_sub(offset);
        let mut hasher = Sha1::new();
        hasher.update(secret_bytes);
        hasher.update(&idx.to_be_bytes());
        let digest = hasher.finalize();
        let slice: [u8; 4] = digest[16..20].try_into().unwrap();
        let val = u32::from_be_bytes(slice);
        base_port + (val % port_range as u32) as u16
    }).collect()
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
async fn send_chat_message_to_target(
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    msg: &str,
) -> Result<()> {
    let mut buf = Vec::with_capacity(3 + msg.len());
    buf.extend_from_slice(MSG_PREFIX);
    buf.extend_from_slice(msg.as_bytes());
    socket.send_to(&buf, target).await?;
    Ok(())
}

// -------------------- HELPERS & REDRAW --------------------
fn calculate_start_index(total_lines: usize, visible_rows: usize, scroll_offset: usize) -> usize {
    if total_lines <= visible_rows {
        0
    } else {
        let max_offset = total_lines - visible_rows;
        total_lines - visible_rows - scroll_offset.min(max_offset)
    }
}

async fn redraw_terminal(
    stdout: &mut std::io::Stdout,
    chat_lines: &[ChatLine],
    file_transfers: &FileTransfers,
    input_buffer: &str,
    search_mode: bool,
    search_buffer: &str,
    scroll_offset: usize,
) {
    let (cols, rows) = size().unwrap_or((100, 30));
    let visible_rows = rows.saturating_sub(1) as usize;
    let input_row = rows.saturating_sub(1);

    let mut lines = Vec::new();

    // --- Chat messages ---
    for entry in chat_lines {
        let ts = match entry {
            ChatLine::Message { ts, .. } | ChatLine::Transfer { ts, .. } => ts,
        };
        lines.push(format!("[{}] {}", ts.format("%H:%M:%S"), entry));
    }

    // --- File transfers ---
    let ft_snapshot = {
        let ft_lock = file_transfers.lock().await;
        ft_lock.clone() // clone the hashmap
    };

    for (fname, &(done, total, direction, state)) in ft_snapshot.iter() {
        let percent = if total > 0 { (done as f64 / total as f64 * 100.0).round() as u64 } else { 0 };
        let bar_width = (cols as usize).saturating_sub(30);
        let filled = ((percent as usize * bar_width) / 100).min(bar_width);
        let mut bar = String::new();
        bar.push_str(&"█".repeat(filled));
        bar.push_str(&"-".repeat(bar_width - filled));

        let color = match (direction, state) {
            (TransferDirection::Upload, TransferState::InProgress) => Color::Blue,
            (TransferDirection::Download, TransferState::InProgress) => Color::Green,
            (_, TransferState::Done) => match direction {
                TransferDirection::Upload => Color::Blue,
                TransferDirection::Download => Color::Green,
            },
            (_, TransferState::Failed) => Color::Red,
        };

        let status = match state {
            TransferState::InProgress => format!("[{}] {}% {}", bar, percent, fname),
            TransferState::Done => format!("[{} - DONE]", fname),
            TransferState::Failed => format!("[{} - FAILED]", fname),
        };

        let _ = execute!(
            stdout,
            cursor::MoveTo(0, lines.len() as u16),
            Clear(ClearType::CurrentLine),
            SetForegroundColor(color),
            Print(status.chars().take(cols as usize).collect::<String>()),
            ResetColor
        );

        lines.push(status);
    }

    // --- Draw visible lines ---
    let start_idx = calculate_start_index(lines.len(), visible_rows, scroll_offset);
    for (i, line) in lines[start_idx..].iter().enumerate() {
        let _ = execute!(
            stdout,
            cursor::MoveTo(0, i as u16),
            Clear(ClearType::CurrentLine),
            SetForegroundColor(Color::White),
            Print(line.chars().take(cols as usize).collect::<String>()),
            ResetColor
        );
    }

    // Clear remaining lines
    for i in lines.len()..visible_rows {
        let _ = execute!(stdout, cursor::MoveTo(0, i as u16), Clear(ClearType::CurrentLine));
    }

    // --- Draw prompt ---
    let prompt = if search_mode {
        format!("(reverse-i-search)`{}': {}", search_buffer, input_buffer)
    } else {
        format!("> {}", input_buffer)
    };

    let _ = execute!(
        stdout,
        cursor::MoveTo(0, input_row),
        Clear(ClearType::CurrentLine),
        SetForegroundColor(Color::Yellow),
        Print(prompt.chars().take(cols as usize).collect::<String>()),
        ResetColor,
        cursor::MoveTo(prompt.len() as u16, input_row)
    );

    let _ = stdout.flush();
}

async fn redraw(
    stdout: &mut std::io::Stdout,
    chat: &ChatHistory,
    file_transfers: &FileTransfers,
    input_buffer: &str,
    search_mode: bool,
    search_buffer: &str,
    scroll_offset: usize,
) {
    let snapshot = {
        let chat_lock = chat.lock().await;
        chat_lock.clone()
    };
    redraw_terminal(stdout, &snapshot, file_transfers, input_buffer, search_mode, search_buffer, scroll_offset).await;
}

// -------------------- KEY HANDLING --------------------
async fn handle_key(
    key_event: KeyEvent,
    input_buffer: &mut String,
    chat: &ChatHistory,
    socket: &Arc<UdpSocket>,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    redraw_notify: &Arc<Notify>,
    _ack_bcast: &broadcast::Sender<(u32, u32, SocketAddr)>,
    transfer_counter: &TransferCounter,
    file_transfers: &FileTransfers,
    _last_client: &Option<Arc<Mutex<Option<SocketAddr>>>>,
    history: &mut Vec<String>,
    history_index: &mut Option<usize>,
    search_mode: &mut bool,
    search_buffer: &mut String,
    search_result_index: &mut Option<usize>,
    scroll_offset: &mut usize,
    visible_rows: usize,
    socket_clone_for_send: Arc<UdpSocket>,
    ack_bcast_for_send: broadcast::Sender<(u32, u32, SocketAddr)>,
    targets_clone_for_send: Arc<Mutex<HashSet<SocketAddr>>>,
    transfer_counter_clone_for_send: TransferCounter,
    file_transfers_clone_for_send: FileTransfers,
    chat_history_clone_for_send: ChatHistory,
    redraw_notify_clone_for_send: Arc<Notify>,
    ack_tracker: FileAckTracker,
) {
    match key_event.code {
        KeyCode::Char('r') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
            *search_mode = true;
            *search_buffer = String::new();
            *search_result_index = None;
        }
        KeyCode::Char(c) => {
            if *search_mode {
                search_buffer.push(c);
                *search_result_index = history.iter().rposition(|entry| entry.contains(&*search_buffer));
                if let Some(idx) = *search_result_index {
                    *input_buffer = history[idx].clone();
                }
            } else {
                input_buffer.push(c);
                *history_index = None;
            }
        }
        KeyCode::Backspace => {
            if *search_mode {
                search_buffer.pop();
                *search_result_index = history.iter().rposition(|entry| entry.contains(&*search_buffer));
                if let Some(idx) = *search_result_index {
                    *input_buffer = history[idx].clone();
                } else {
                    input_buffer.clear();
                }
            } else {
                input_buffer.pop();
                *history_index = None;
            }
        }
        KeyCode::Enter => {
            if *search_mode {
                *search_mode = false;
                *search_buffer = String::new();
                *search_result_index = None;
            } else if !input_buffer.trim().is_empty() {
                let input = input_buffer.clone();
                input_buffer.clear();
                history.push(input.clone());
                *history_index = None;

                if input.starts_with("/send ") {
                    let path = input[6..].trim().to_string();

                    let file_id = {
                        let mut ctr = transfer_counter.lock().await;
                        *ctr += 1;
                        *ctr
                    };

                    // Clones for spawn
                    let socket2 = socket_clone_for_send.clone();
                    let targets2 = targets_clone_for_send.clone();
                    let ack_bcast2 = ack_bcast_for_send.clone(); // Type now consistent
                    let transfer_counter2 = transfer_counter_clone_for_send.clone();
                    let file_transfers2 = file_transfers_clone_for_send.clone();
                    let chat2 = chat_history_clone_for_send.clone();
                    let redraw2 = redraw_notify_clone_for_send.clone();

                    tokio::spawn(async move {
                        if let Err(e) = send_file(
                            socket2,
                            targets2,
                            path,
                            ack_bcast2,
                            file_id,
                            transfer_counter2,
                            chat2,
                            file_transfers2,
                            ack_tracker,
                            redraw2,
                            None,
                        ).await {
                            eprintln!("Failed to send file: {}", e);
                        }
                    });

                } else if input.starts_with("/quit") {
                    let _ = disable_raw_mode();
                    let mut stdout = stdout();
                    let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
                    std::process::exit(0);
                } else {
                    let targets_lock = targets.lock().await;
                    for &addr in targets_lock.iter() {
                        let _ = send_chat_message_to_target(socket.clone(), addr, &input).await;
                    }
                    chat_push_cap(chat, ChatLine::Message { ts: Local::now(), msg: format!("You: {}", input) }).await;
                    redraw_notify.notify_one();
                }
            }
        }
        KeyCode::Up => {
            if !*search_mode {
                if let Some(idx) = history_index {
                    if *idx > 0 { *idx -= 1; *input_buffer = history[*idx].clone(); }
                } else if !history.is_empty() {
                    *history_index = Some(history.len() - 1);
                    *input_buffer = history.last().unwrap().clone();
                }
            }
        }
        KeyCode::Down => {
            if !*search_mode {
                if let Some(idx) = history_index {
                    if *idx + 1 < history.len() { *idx += 1; *input_buffer = history[*idx].clone(); }
                    else { *history_index = None; input_buffer.clear(); }
                }
            }
        }
        KeyCode::PageUp => { *scroll_offset += visible_rows / 2; }
        KeyCode::PageDown => { *scroll_offset = scroll_offset.saturating_sub(visible_rows / 2); }
        KeyCode::Esc => {
            if *search_mode {
                *search_mode = false;
                *search_buffer = String::new();
                *search_result_index = None;
            } else { input_buffer.clear(); }
        }
        _ => {}
    }

    if *scroll_offset == 0 {
        redraw_notify.notify_one();
    }
}


// -------------------- FILE MANAGER TASK --------------------
async fn file_manager_task(
    mut rx: mpsc::Receiver<FileChunk>,
    chat_tx: mpsc::Sender<ChatLine>,
    file_transfers: FileTransfers,
    transfer_counter: TransferCounter,
    redraw_notify: Arc<Notify>,
) {
    let mut state: HashMap<u32, (Option<String>, Option<u32>, usize, HashMap<u32, Vec<u8>>)> = HashMap::new();
    let mut completed_files: HashSet<u32> = HashSet::new();
    let mut last_redraw = Instant::now();

    while let Some(chunk) = rx.recv().await {
        // Skip already completed files
        if completed_files.contains(&chunk.file_id) {
            continue;
        }

        let entry = state.entry(chunk.file_id)
            .or_insert((chunk.filename.clone(), chunk.total_chunks, 0usize, HashMap::new()));

        if entry.0.is_none() {
            entry.0 = chunk.filename.clone();
        }
        if entry.1.is_none() {
            entry.1 = chunk.total_chunks;
        }

        // Avoid double-counting duplicate chunks
        if entry.3.contains_key(&chunk.chunk_index) {
            continue;
        }

        entry.2 += chunk.payload.len();
        entry.3.insert(chunk.chunk_index, chunk.payload);

        let fname = entry.0.clone().unwrap_or_else(|| format!("received_file_{}.dat", chunk.file_id));
        let done = entry.3.len() as u64;
        let total = entry.1.unwrap_or(1) as u64;

        // Update file transfer state
        {
            let mut ft = file_transfers.lock().await;
            ft.insert(fname.clone(), (done, total, TransferDirection::Download, TransferState::InProgress));
        }

        // Only send periodic redraw messages (debounce)
        if last_redraw.elapsed() >= Duration::from_millis(100) {
            let _ = chat_tx.send(ChatLine::Transfer {
                ts: Local::now(),
                id: chunk.file_id,
                filename: fname.clone(),
                done,
                total,
                direction: TransferDirection::Download,
                state: TransferState::InProgress,
            }).await;
            redraw_notify.notify_one();
            last_redraw = Instant::now();
        }

        // Check if file is complete
        if let Some(expected) = entry.1 {
            if entry.3.len() as u32 == expected && (0..expected).all(|i| entry.3.contains_key(&i)) {
                let mut assembled = Vec::with_capacity(entry.2);
                for i in 0..expected {
                    if let Some(v) = entry.3.remove(&i) {
                        assembled.extend_from_slice(&v);
                    }
                }

                let filename = entry.0.clone().unwrap_or_else(|| format!("received_file_{}.dat", chunk.file_id));

                // Save file only once
                match tokio::fs::write(&filename, &assembled).await {
                    Ok(_) => {
                        completed_files.insert(chunk.file_id);

                        // Update transfer counter
                        {
                            let mut ctr = transfer_counter.lock().await;
                            if *ctr > 0 { *ctr -= 1; }
                        }

                        let mut ft = file_transfers.lock().await;
                        ft.insert(filename.clone(), (expected as u64, expected as u64, TransferDirection::Download, TransferState::Done));

                        let _ = chat_tx.send(ChatLine::Transfer {
                            ts: Local::now(),
                            id: chunk.file_id,
                            filename: filename.clone(),
                            done: expected as u64,
                            total: expected as u64,
                            direction: TransferDirection::Download,
                            state: TransferState::Done,
                        }).await;

                        let _ = chat_tx.send(ChatLine::Message {
                            ts: Local::now(),
                            msg: format!("Saved received file '{}' from {}", filename, chunk.src),
                        }).await;

                        redraw_notify.notify_one();
                    }
                    Err(e) => {
                        let mut ft = file_transfers.lock().await;
                        ft.insert(filename.clone(), (done, total, TransferDirection::Download, TransferState::Failed));

                        let _ = chat_tx.send(ChatLine::Transfer {
                            ts: Local::now(),
                            id: chunk.file_id,
                            filename: filename.clone(),
                            done,
                            total,
                            direction: TransferDirection::Download,
                            state: TransferState::Failed,
                        }).await;

                        eprintln!("Failed to write file {}: {}", filename, e);
                        completed_files.insert(chunk.file_id);
                        redraw_notify.notify_one();
                    }
                }

                // Remove from state
                state.remove(&chunk.file_id);
            }
        }
    }
}

// -------------------- SENDER: send_file uses broadcast receiver for ACKs --------------------
async fn send_file(
    socket: Arc<UdpSocket>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    path: String,
    ack_bcast: broadcast::Sender<(u32, u32, SocketAddr)>,
    file_id: u32,
    transfer_counter: TransferCounter,
    chat: ChatHistory,
    file_transfers: FileTransfers,
    ack_tracker: FileAckTracker,
    redraw_notify: Arc<Notify>,
    _sender_addr: Option<SocketAddr>,
) -> Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();

    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown_file".to_string());

    let chunk_size = (MAX_UDP_PAYLOAD - 128).min(512 * 1024);
    let total_chunks = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;

    {
        let mut ctr = transfer_counter.lock().await;
        *ctr += 1;
    }

    {
        let mut ft = file_transfers.lock().await;
        ft.insert(filename.clone(), (0, total_chunks as u64, TransferDirection::Upload, TransferState::InProgress));
    }

    // Initialize per-client ACK tracking
    let clients: Vec<SocketAddr> = {
        let targets_snapshot = targets.lock().await.clone();
        let mut tracker = ack_tracker.lock().await;
        let map = targets_snapshot
            .iter()
            .map(|&addr| (addr, HashSet::new()))
            .collect();
        tracker.insert(filename.clone(), map);
        targets_snapshot.into_iter().collect()
    };

    // Read all chunks into memory
    let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(total_chunks as usize);
    let mut buf = vec![0u8; chunk_size];

    for chunk_index in 0..total_chunks {
        let n = file.read(&mut buf).await?;
        if n == 0 { break; }

        let mut packet = Vec::with_capacity(n + 128);
        packet.extend_from_slice(&file_id.to_be_bytes());
        packet.extend_from_slice(&chunk_index.to_be_bytes());

        if chunk_index == 0 {
            // include filename & total_chunks
            packet.push(0);
            let fname_bytes = filename.as_bytes();
            packet.push(fname_bytes.len() as u8);
            packet.extend_from_slice(fname_bytes);
            packet.extend_from_slice(&total_chunks.to_be_bytes());
        }

        packet.extend_from_slice(&buf[..n]);
        chunks.push(packet);
    }

    // Per-file send/retry loop
    let mut retries: HashMap<SocketAddr, usize> = clients.iter().map(|&addr| (addr, 0)).collect();

    while retries.values().any(|&r| r <= MAX_RETRIES) {
        let mut remaining_clients: Vec<SocketAddr> = {
            let tracker = ack_tracker.lock().await;
            tracker.get(&filename)
                .unwrap()
                .iter()
                .filter(|(_, chunks_ack)| chunks_ack.len() < total_chunks as usize)
                .map(|(&addr, _)| addr)
                .collect()
        };

        if remaining_clients.is_empty() { break; }

        // Send all un-ACKed chunks to remaining clients
        for &addr in &remaining_clients {
            for (chunk_index, packet) in chunks.iter().enumerate() {
                let tracker = ack_tracker.lock().await;
                if !tracker.get(&filename).unwrap()[&addr].contains(&(chunk_index as u32)) {
                    let _ = socket.send_to(packet, addr).await;
                }
            }
        }

        // Wait for ACKs or timeout
        let mut ack_rx = ack_bcast.subscribe();
        let timeout = tokio::time::sleep(Duration::from_millis(ACK_TIMEOUT_MS));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Ok((fid, cid, client_addr)) = ack_rx.recv() => {
                    if fid == file_id {
                        let mut tracker = ack_tracker.lock().await;
                        if let Some(per_client) = tracker.get_mut(&filename) {
                            per_client.get_mut(&client_addr).map(|s| { s.insert(cid); });
                        }
                    }
                }
                _ = &mut timeout => { break; }
            }
        }

        // Increment retries for remaining clients
        for &addr in &remaining_clients {
            let counter = retries.get_mut(&addr).unwrap();
            *counter += 1;
            if *counter > MAX_RETRIES {
                let mut ft = file_transfers.lock().await;
                let (_, total, direction, _) = ft.get(&filename).unwrap().clone();
                ft.insert(filename.clone(), (total, total, direction, TransferState::Failed));
                redraw_notify.notify_one();
            }
        }

        // Update transfer progress
        let mut ft = file_transfers.lock().await;
        let mut max_done = 0;
        let tracker = ack_tracker.lock().await;
        if let Some(per_client) = tracker.get(&filename) {
            for chunks_ack in per_client.values() {
                max_done = max_done.max(chunks_ack.len());
            }
        }
        let (_, total, direction, _) = ft.get(&filename).unwrap().clone();
        ft.insert(filename.clone(), (max_done as u64, total, direction, TransferState::InProgress));
        redraw_notify.notify_one();
    }

    // Mark as done if all clients finished
    {
        let mut ft = file_transfers.lock().await;
        let (_, total, direction, state) = ft.get(&filename).unwrap().clone();
        if state != TransferState::Failed {
            ft.insert(filename.clone(), (total, total, direction, TransferState::Done));
        }
    }

    redraw_notify.notify_one();

    chat_push_cap(&chat, ChatLine::Message {
        ts: Local::now(),
        msg: format!("Finished sending '{}'", filename),
    }).await;

    {
        let mut ctr = transfer_counter.lock().await;
        if *ctr > 0 { *ctr -= 1; }
    }

    Ok(())
}




// -------------------- RECEIVER --------------------
fn spawn_receiver(
    socket: Arc<UdpSocket>,
    chat_tx: mpsc::Sender<ChatLine>,
    file_chunk_tx: mpsc::Sender<FileChunk>,
    ack_bcast: broadcast::Sender<(u32, u32, SocketAddr)>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    targets_tx: mpsc::Sender<SocketAddr>,
    server_mode: bool,
) {
    let seen_chunks: Arc<Mutex<HashMap<u32, HashSet<u32>>>> = Arc::new(Mutex::new(HashMap::new()));
    let seen_acks: Arc<Mutex<HashMap<u32, HashSet<u32>>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    // update targets
                    if server_mode {
                        let _ = targets.lock().await.insert(src);
                    } else {
                        let mut t = targets.lock().await;
                        if !t.contains(&src) { t.clear(); t.insert(src); }
                    }
                    let _ = targets_tx.try_send(src);

                    // ---------------- CHAT ----------------
                    if len >= 3 && &buf[..3] == MSG_PREFIX {
                        let msg = String::from_utf8_lossy(&buf[3..len]).to_string();
                        let _ = chat_tx.send(ChatLine::Message {
                            ts: Local::now(),
                            msg: format!("{} says: {}", src, msg),
                        }).await;

                        if server_mode {
                            let targets_snapshot = { targets.lock().await.clone() };
                            for &addr in &targets_snapshot {
                                if addr != src {
                                    let mut buf_to_send = Vec::with_capacity(3 + msg.len());
                                    buf_to_send.extend_from_slice(MSG_PREFIX);
                                    buf_to_send.extend_from_slice(msg.as_bytes());
                                    let _ = socket.send_to(&buf_to_send, addr).await;
                                }
                            }
                        }
                        continue;
                    }

                    // ---------------- ACK ----------------
                    if len >= 11 && &buf[..3] == ACK_PREFIX {
                        let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                        let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());

                        if server_mode {
                            let mut lock = seen_acks.lock().await;
                            let entry = lock.entry(file_id).or_default();
                            if entry.insert(chunk_index) {
                                let targets_snapshot = { targets.lock().await.clone() };
                                for &addr in &targets_snapshot {
                                    if addr != src {
                                        let _ = socket.send_to(&buf[..len], addr).await;
                                    }
                                }
                            }
                        }

                        // Broadcast ACK only for the originating client
                        let _ = ack_bcast.send((file_id, chunk_index, src));
                        continue;
                    }

                    // ---------------- FILE CHUNK ----------------
                    if len >= 9 {
                        let file_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                        let chunk_index = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                        let mut offset = 8usize;

                        let mut filename_opt = None;
                        let mut total_chunks_opt = None;

                        if chunk_index == 0 && offset < len {
                            offset += 1;
                            if offset < len {
                                let name_len = buf[offset] as usize;
                                offset += 1;
                                if offset + name_len + 4 <= len {
                                    filename_opt = Some(String::from_utf8_lossy(&buf[offset..offset+name_len]).to_string());
                                    offset += name_len;
                                    total_chunks_opt = Some(u32::from_be_bytes(buf[offset..offset+4].try_into().unwrap()));
                                    offset += 4;
                                }
                            }
                        }

                        if offset > len { continue; }
                        let payload = buf[offset..len].to_vec();

                        // server-side: only rebroadcast if new chunk
                        let mut seen_lock = seen_chunks.lock().await;
                        let file_entry = seen_lock.entry(file_id).or_default();
                        if file_entry.insert(chunk_index) && server_mode {
                            let targets_snapshot = { targets.lock().await.clone() };
                            for &addr in &targets_snapshot {
                                if addr != src {
                                    let _ = socket.send_to(&buf[..len], addr).await;
                                }
                            }
                        }
                        drop(seen_lock);

                        // send to processor
                        let chunk = FileChunk {
                            file_id,
                            chunk_index,
                            filename: filename_opt,
                            total_chunks: total_chunks_opt,
                            payload,
                            src,
                        };
                        let _ = file_chunk_tx.send(chunk).await;
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
}




// -------------------- SERVER & CLIENT RUN --------------------
async fn run_server(cli: Cli) -> Result<()> {
    let (chat_tx, chat_rx) = mpsc::channel::<ChatLine>(256);

    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(Notify::new());
    let clients: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let ack_tracker: FileAckTracker = Arc::new(Mutex::new(HashMap::new()));

    let (file_chunk_tx, file_chunk_rx) = mpsc::channel::<FileChunk>(1024);
    let (targets_tx, _targets_rx) = mpsc::channel::<SocketAddr>(256);
    let (ack_bcast_tx, _) = broadcast::channel::<(u32,u32, SocketAddr)>(1024);

    let secret_bytes = secret_to_bytes(&cli.secret);
    let mut current_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
    let mut socket = Arc::new(UdpSocket::bind(("0.0.0.0", current_port)).await?);

    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let terminal_chat_rx = Arc::new(Mutex::new(chat_rx));

    // Terminal args: pass ack_bcast so terminal can spawn send_file tasks with the same ack broadcaster
    let terminal_args = TerminalArgs {
        socket: socket.clone(),
        targets: clients.clone(),
        redraw_notify: redraw_notify.clone(),
        file_transfers: file_transfers.clone(),
        ack_bcast: ack_bcast_tx.clone(),
        transfer_counter: transfer_counter.clone(),
        last_client: Some(Arc::new(Mutex::new(None))),
        chat_rx: terminal_chat_rx.clone(),
        ack_tracker: ack_tracker.clone(),
    };

    tokio::spawn(async move {
        terminal_loop(terminal_args).await;
    });

    let fm_chat_tx = chat_tx.clone();
    let fm_file_transfers = file_transfers.clone();
    let fm_transfer_counter = transfer_counter.clone();
    let fm_redraw = redraw_notify.clone();
    tokio::spawn(async move {
        file_manager_task(file_chunk_rx, fm_chat_tx, fm_file_transfers, fm_transfer_counter, fm_redraw).await;
    });

    spawn_receiver(
        socket.clone(),
        chat_tx.clone(),
        file_chunk_tx.clone(),
        ack_bcast_tx.clone(),
        clients.clone(),
        targets_tx.clone(),
        true,
    );

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
        if new_port != current_port {
            drop(socket);
            socket = Arc::new(UdpSocket::bind(("0.0.0.0", new_port)).await?);
            current_port = new_port;

            spawn_receiver(
                socket.clone(),
                chat_tx.clone(),
                file_chunk_tx.clone(),
                ack_bcast_tx.clone(),
                clients.clone(),
                targets_tx.clone(),
                true,
            );
        }
    }
}

async fn run_client(cli: Cli, server: String) -> Result<()> {
    let (chat_tx, chat_rx) = mpsc::channel::<ChatLine>(256);
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(Notify::new());
    let secret_bytes = secret_to_bytes(&cli.secret);
    let ack_tracker: FileAckTracker = Arc::new(Mutex::new(HashMap::new()));

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let targets: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    {
        let ports = compute_possible_ports(&secret_bytes, cli.base_port, cli.port_range);
        let mut t = targets.lock().await;
        t.clear();
        for port in ports {
            t.insert(format!("{}:{}", server, port).parse::<SocketAddr>()?);
        }
    }

    for &addr in targets.lock().await.iter() {
        let mut buf = Vec::with_capacity(MSG_PREFIX.len() + 5);
        buf.extend_from_slice(MSG_PREFIX);
        buf.extend_from_slice(b"hello");
        let _ = socket.send_to(&buf, addr).await;
    }

    let (file_chunk_tx, file_chunk_rx) = mpsc::channel::<FileChunk>(1024);
    let (targets_tx, _targets_rx) = mpsc::channel::<SocketAddr>(256);
    let (ack_bcast_tx, _) = broadcast::channel::<(u32,u32, SocketAddr)>(1024);

    {
        let targets = targets.clone();
        let server = server.clone();
        let secret_bytes = secret_bytes.clone();
        tokio::spawn(async move {
            loop {
                let ports = compute_possible_ports(&secret_bytes, cli.base_port, cli.port_range);
                let mut t = targets.lock().await;
                t.clear();
                for port in ports {
                    t.insert(format!("{}:{}", server, port).parse::<SocketAddr>().unwrap());
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    let terminal_chat_rx = Arc::new(Mutex::new(chat_rx));
    let terminal_args = TerminalArgs {
        socket: socket.clone(),
        targets: targets.clone(),
        redraw_notify: redraw_notify.clone(),
        file_transfers: file_transfers.clone(),
        ack_bcast: ack_bcast_tx.clone(),
        transfer_counter: transfer_counter.clone(),
        last_client: Some(Arc::new(Mutex::new(None))),
        chat_rx: terminal_chat_rx.clone(),
        ack_tracker: ack_tracker.clone(),
    };

    tokio::spawn(async move {
        terminal_loop(terminal_args).await;
    });

    let fm_chat_tx = chat_tx.clone();
    let fm_file_transfers = file_transfers.clone();
    let fm_transfer_counter = transfer_counter.clone();
    let fm_redraw = redraw_notify.clone();
    tokio::spawn(async move {
        file_manager_task(file_chunk_rx, fm_chat_tx, fm_file_transfers, fm_transfer_counter, fm_redraw).await;
    });

    spawn_receiver(
        socket.clone(),
        chat_tx.clone(),
        file_chunk_tx.clone(),
        ack_bcast_tx.clone(),
        targets.clone(),
        targets_tx.clone(),
        false,
    );

    future::pending::<()>().await;
    Ok(())
}

// -------------------- TERMINAL LOOP --------------------
pub async fn terminal_loop(args: TerminalArgs) {
    let TerminalArgs {
        socket,
        targets,
        redraw_notify,
        file_transfers,
        ack_bcast,
        transfer_counter,
        last_client: _,
        chat_rx,
        ack_tracker,
    } = args;

    let _guard = TerminalGuard::new();
    let mut stdout = stdout();

    let mut input_buffer = String::new();
    let mut history: Vec<String> = Vec::new();
    let mut history_index: Option<usize> = None;
    let mut search_mode = false;
    let mut search_buffer = String::new();
    let mut search_result_index: Option<usize> = None;
    let chat_lines: ChatHistory = Arc::new(Mutex::new(Vec::new()));

    let mut desired_scroll_offset: usize = 0;
    let mut visible_scroll_offset: usize = 0;
    let scroll_step: usize = 1;
    let mut auto_scroll = true;

    let (_cols, rows) = size().unwrap_or((100, 30));
    let visible_rows = rows.saturating_sub(1) as usize;

    const HISTORY_LIMIT_TERMINAL: usize = 1000;

    loop {
        tokio::select! {
            Some(line) = async {
                let mut rx_lock = chat_rx.lock().await;
                rx_lock.recv().await
            } => {
                {
                    let mut chat_lock = chat_lines.lock().await;
                    chat_lock.push(line);
                    if chat_lock.len() > HISTORY_LIMIT_TERMINAL {
                        chat_lock.remove(0);
                    }
                }

                if auto_scroll {
                    desired_scroll_offset = 0;
                }

                redraw_notify.notify_one();
            }

            _ = redraw_notify.notified() => {
                if visible_scroll_offset > desired_scroll_offset {
                    visible_scroll_offset = visible_scroll_offset.saturating_sub(scroll_step);
                } else if visible_scroll_offset < desired_scroll_offset {
                    visible_scroll_offset += scroll_step;
                }

                let chat_snapshot = {
                    let chat_lock = chat_lines.lock().await;
                    chat_lock.clone()
                };
                redraw_terminal(
                    &mut stdout,
                    &chat_snapshot,
                    &file_transfers,
                    &input_buffer,
                    search_mode,
                    &search_buffer,
                    visible_scroll_offset,
                ).await;
            }

            res = tokio::task::spawn_blocking(|| event::poll(Duration::from_millis(50))) => {
                if let Ok(Ok(true)) = res {
                    if let Ok(Event::Key(key_event)) = event::read() {
                        match key_event.code {
                            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Up | KeyCode::Down => auto_scroll = false,
                            KeyCode::Esc => auto_scroll = true,
                            _ => {}
                        }

                        handle_key(
                            key_event,
                            &mut input_buffer,
                            &chat_lines,
                            &socket,
                            &targets,
                            &redraw_notify,
                            &ack_bcast,
                            &transfer_counter,
                            &file_transfers,
                            &None,
                            &mut history,
                            &mut history_index,
                            &mut search_mode,
                            &mut search_buffer,
                            &mut search_result_index,
                            &mut desired_scroll_offset,
                            visible_rows,
                            socket.clone(),
                            ack_bcast.clone(),
                            targets.clone(),
                            transfer_counter.clone(),
                            file_transfers.clone(),
                            chat_lines.clone(),
                            redraw_notify.clone(),
                            ack_tracker.clone(),
                        ).await;
                    }
                }
            }
        }
    }
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
