use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::signal::ctrl_c;
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
use std::future;
use std::fmt;
use std::collections::HashSet;

// -------------------- CONSTANTS --------------------
const MAX_UDP_PAYLOAD: usize = 65507;
const MSG_PREFIX: &[u8] = b"MSG";
const ACK_PREFIX: &[u8] = b"ACK";
const WINDOW_SIZE: usize = 32;
const ACK_TIMEOUT_MS: u64 = 500;
const MAX_RETRIES: usize = 10;
const HISTORY_LIMIT: usize = 50;

// -------------------- TYPES --------------------
type FileMap = Arc<Mutex<HashMap<u32, FileBuffer>>>;
type AckMap = Arc<Mutex<HashMap<(u32, u32), bool>>>;
type TransferCounter = Arc<Mutex<u32>>;
type ChatHistory = Arc<Mutex<Vec<ChatLine>>>;
type FileTransfers = Arc<Mutex<HashMap<String, (u64, u64, TransferDirection, TransferState)>>>;
type Targets = Arc<Mutex<HashSet<SocketAddr>>>;
type FileSenderMap = Arc<Mutex<HashMap<u32, SocketAddr>>>;



#[derive(Clone, Copy, Debug)]
enum TransferDirection { Upload, Download }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferState { InProgress, Done, Failed }

struct FileBuffer {
    chunks: HashMap<u32, Vec<u8>>,
    expected_chunks: Option<u32>,
    received_size: usize,
    filename: Option<String>,
}

#[derive(Clone)]
struct TerminalArgs {
    chat: ChatHistory,
    socket: Arc<UdpSocket>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    redraw_notify: Arc<tokio::sync::Notify>,
    file_transfers: FileTransfers,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    last_client: Option<Arc<Mutex<Option<SocketAddr>>>>,
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

// -------------------- Helpers --------------------
fn calculate_start_index(total_lines: usize, visible_rows: usize, scroll_offset: usize) -> usize {
    if total_lines <= visible_rows {
        0
    } else {
        let max_offset = total_lines - visible_rows;
        total_lines - visible_rows - scroll_offset.min(max_offset)
    }
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
    let (cols, rows) = size().unwrap_or((100, 30));
    let visible_rows = rows.saturating_sub(1) as usize; // leave last row for prompt
    let input_row = rows.saturating_sub(1);

    let mut lines = Vec::new();

    // --- Chat messages ---
    {
        let chat_lock = chat.lock().await;
        for entry in chat_lock.iter() {
            let ts = match entry {
                ChatLine::Message { ts, .. } | ChatLine::Transfer { ts, .. } => ts,
            };
            lines.push(format!("[{}] {}", ts.format("%H:%M:%S"), entry));
        }
    }

    // --- File transfers ---
    let ft_lock = file_transfers.lock().await;
    for (fname, &(done, total, direction, _)) in ft_lock.iter() {
        let dir_char = match direction {
            TransferDirection::Upload => "↑",
            TransferDirection::Download => "↓",
        };
        lines.push(format!(
            "[{}] {} {} {}/{}",
            Local::now().format("%H:%M:%S"),
            dir_char,
            fname,
            done,
            total
        ));
    }

    let start_idx = calculate_start_index(lines.len(), visible_rows, scroll_offset);

    // --- Draw visible lines ---
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

async fn handle_key(
    key_event: KeyEvent,
    input_buffer: &mut String,
    chat: &ChatHistory,
    socket: &Arc<UdpSocket>,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    redraw_notify: &Arc<Notify>,
    ack_map: &AckMap,
    transfer_counter: &TransferCounter,
    file_transfers: &FileTransfers,
    last_client: &Option<Arc<Mutex<Option<SocketAddr>>>>,
    history: &mut Vec<String>,
    history_index: &mut Option<usize>,
    search_mode: &mut bool,
    search_buffer: &mut String,
    search_result_index: &mut Option<usize>,
    scroll_offset: &mut usize,
    visible_rows: usize,
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
                    if input.starts_with("/send ") {
                        let path = input[6..].trim().to_string();
                        let file_id = {
                            let mut counter = transfer_counter.lock().await;
                            *counter += 1;
                            *counter
                        };

                        let socket_clone = socket.clone();
                        let targets_clone = targets.clone();
                        let ack_map_clone = ack_map.clone();
                        let chat_clone = chat.clone();
                        let file_transfers_clone = file_transfers.clone();
                        let redraw_notify_clone = redraw_notify.clone();
                        let transfer_counter_clone = transfer_counter.clone();

                        let sender_addr = socket_clone.local_addr().ok(); // ← pass this #TODO: Better than that!

                        tokio::spawn(async move {
                            if let Err(e) = send_file(
                                socket_clone,
                                targets_clone,
                                path,
                                ack_map_clone,
                                file_id,
                                transfer_counter_clone,
                                chat_clone,
                                file_transfers_clone,
                                redraw_notify_clone,
                                sender_addr, // ← original sender
                            ).await {
                                eprintln!("Failed to send file: {}", e);
                            }
                        });
                    }
                } else if input.starts_with("/quit"){
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

// -------------------- Terminal Loop --------------------
pub async fn terminal_loop(args: TerminalArgs) {

    let TerminalArgs { chat, socket, targets, redraw_notify, file_transfers, ack_map, transfer_counter, last_client } = args;
    let _guard = TerminalGuard::new();
    let mut stdout = stdout();

    let mut input_buffer = String::new();
    let mut history: Vec<String> = Vec::new();
    let mut history_index: Option<usize> = None;

    let mut search_mode = false;
    let mut search_buffer = String::new();
    let mut search_result_index: Option<usize> = None;

    // Smooth scroll state
    let mut desired_scroll_offset: usize = 0;
    let mut visible_scroll_offset: usize = 0;
    let scroll_step: usize = 1; // lines per redraw tick
    let mut auto_scroll = true;

    let (cols, rows) = size().unwrap_or((100, 30));
    let visible_rows = rows.saturating_sub(1) as usize;

    loop {
        tokio::select! {
            _ = redraw_notify.notified() => {
                // Auto-scroll unless user manually scrolled
                if auto_scroll {
                    desired_scroll_offset = 0; // new messages push scroll to bottom
                }

                // Smooth scroll: move visible toward desired
                if visible_scroll_offset > desired_scroll_offset {
                    visible_scroll_offset = visible_scroll_offset.saturating_sub(scroll_step);
                } else if visible_scroll_offset < desired_scroll_offset {
                    visible_scroll_offset += scroll_step;
                }

                redraw(&mut stdout, &chat, &file_transfers, &input_buffer, search_mode, &search_buffer, visible_scroll_offset).await;
            }

            res = tokio::task::spawn_blocking(|| event::poll(Duration::from_millis(50))) => {
                match res {
                    Ok(Ok(true)) => {
                        if let Ok(Event::Key(key_event)) = event::read() {
                            // Before handling keys, update auto_scroll if user scrolls manually
                            match key_event.code {
                                KeyCode::PageUp | KeyCode::PageDown | KeyCode::Up | KeyCode::Down => {
                                    auto_scroll = false;
                                }
                                KeyCode::Esc => {
                                    auto_scroll = true;
                                }
                                _ => {}
                            }

                            handle_key(
                                key_event,
                                &mut input_buffer,
                                &chat,
                                &socket,
                                &targets,
                                &redraw_notify,
                                &ack_map,
                                &transfer_counter,
                                &file_transfers,
                                &last_client,
                                &mut history,
                                &mut history_index,
                                &mut search_mode,
                                &mut search_buffer,
                                &mut search_result_index,
                                &mut desired_scroll_offset,
                                visible_rows,
                            ).await;
                        }
                    }
                    Ok(Ok(false)) => {}
                    Ok(Err(e)) => eprintln!("poll error: {:?}", e),
                    Err(e) => eprintln!("spawn_blocking join error: {:?}", e),
                }
            }
        }
    }
}

// -------------------- HELPER --------------------
async fn update_transfer_progress(
    chat: &ChatHistory,
    file_transfers: &FileTransfers,
    filename: &str,
    file_id: u32,
    done: u64,
    total: u64,
    direction: TransferDirection,
    state: TransferState,
) {
    file_transfers.lock().await.insert(
        filename.to_string(),
        (done, total, direction, state.clone()),
    );

    chat_push_cap(chat, ChatLine::Transfer {
        ts: Local::now(),
        id: file_id,
        filename: filename.to_string(),
        done,
        total,
        direction,
        state,
    }).await;
}

// -------------------- FILE CHUNK HANDLING --------------------
async fn handle_file_chunk(
    buf: &[u8],
    len: usize,
    src: SocketAddr,
    files: FileMap,
    file_senders: FileSenderMap,
    socket: Arc<UdpSocket>,
    transfer_counter: TransferCounter,
    chat: ChatHistory,
    file_transfers: FileTransfers,
    redraw_notify: Arc<tokio::sync::Notify>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    if len < 8 { return; }

    let file_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let chunk_index = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let mut offset = 8;

    let mut filename_opt = None;
    let mut total_chunks_opt = None;

    if chunk_index == 0 && offset < len {
        if buf.len() > offset { offset += 1; } // reserved
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

    if offset > len { return; }
    let payload = buf[offset..len].to_vec();

    let mut files_lock = files.lock().await;
    let entry = files_lock.entry(file_id).or_insert(FileBuffer {
        chunks: HashMap::new(),
        expected_chunks: total_chunks_opt,
        received_size: 0,
        filename: filename_opt.clone(),
    });

    if entry.filename.is_none() { entry.filename = filename_opt.clone(); }
    if entry.expected_chunks.is_none() { entry.expected_chunks = total_chunks_opt; }

    entry.received_size += payload.len();
    entry.chunks.insert(chunk_index, payload);

    // Track original sender
    file_senders.lock().await.entry(file_id).or_insert(src);

    // ACK
    let mut ack = Vec::with_capacity(11);
    ack.extend_from_slice(ACK_PREFIX);
    ack.extend_from_slice(&file_id.to_be_bytes());
    ack.extend_from_slice(&chunk_index.to_be_bytes());
    let _ = socket.send_to(&ack, src).await;

    // Broadcast to all except original sender
    let targets_snapshot = targets.lock().await.clone();
    let original_sender = file_senders.lock().await.get(&file_id).cloned();
    for addr in &targets_snapshot {
        if Some(*addr) != original_sender {
            let _ = socket.send_to(buf, *addr).await;
        }
    }

    // Update progress
    if let Some(fname) = &entry.filename {
        let done = entry.chunks.len() as u64;
        let total = entry.expected_chunks.unwrap_or(1) as u64;

        update_transfer_progress(
            &chat,
            &file_transfers,
            fname,
            file_id,
            done,
            total,
            TransferDirection::Download,
            TransferState::InProgress,
        ).await;
    }

    // Assemble file if complete
    if let Some(last_idx) = entry.expected_chunks {
        if entry.chunks.len() as u32 == last_idx && (0..last_idx).all(|i| entry.chunks.contains_key(&i)) {
            let mut assembled = Vec::with_capacity(entry.received_size);
            for i in 0..last_idx { assembled.extend_from_slice(&entry.chunks.remove(&i).unwrap()); }

            let filename = entry.filename.clone().unwrap_or_else(|| format!("received_file_{}.dat", file_id));
            if let Err(e) = tokio::fs::write(&filename, &assembled).await {
                eprintln!("Failed to write file {}: {}", filename, e);
            } else {
                let mut counter = transfer_counter.lock().await;
                if *counter > 0 { *counter -= 1; }

                update_transfer_progress(
                    &chat,
                    &file_transfers,
                    &filename,
                    file_id,
                    last_idx as u64,
                    last_idx as u64,
                    TransferDirection::Download,
                    TransferState::Done,
                ).await;

                chat_push_cap(&chat, ChatLine::Message {
                    ts: Local::now(),
                    msg: format!("Saved received file '{}' from {}", filename, src),
                }).await;
            }

            files_lock.remove(&file_id);
            file_senders.lock().await.remove(&file_id);
        }
    }

    redraw_notify.notify_one();
}

// -------------------- SEND FILE --------------------
async fn send_file(
    socket: Arc<UdpSocket>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    path: String,
    ack_map: AckMap,
    file_id: u32,
    transfer_counter: TransferCounter,
    chat: ChatHistory,
    file_transfers: FileTransfers,
    redraw_notify: Arc<tokio::sync::Notify>,
    sender: Option<SocketAddr>,
) -> Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let file_size = metadata.len();
    let buffer_size = (MAX_UDP_PAYLOAD - 512).max(1024);
    let mut buffer = vec![0u8; buffer_size];

    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or("unknown_file".to_string());

    let total_chunks = ((file_size + buffer_size as u64 - 1) / buffer_size as u64) as u32;

    *transfer_counter.lock().await += 1;

    update_transfer_progress(
        &chat,
        &file_transfers,
        &filename,
        file_id,
        0,
        total_chunks as u64,
        TransferDirection::Upload,
        TransferState::InProgress,
    ).await;

    let mut chunk_index: u32 = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 { break; }

        let mut packet = Vec::with_capacity(n + 128);
        packet.extend_from_slice(&file_id.to_be_bytes());
        packet.extend_from_slice(&chunk_index.to_be_bytes());

        if chunk_index == 0 {
            packet.push(0); // reserved
            let fname_bytes = filename.as_bytes();
            packet.push(fname_bytes.len() as u8);
            packet.extend_from_slice(fname_bytes);
            packet.extend_from_slice(&total_chunks.to_be_bytes());
        }

        packet.extend_from_slice(&buffer[..n]);

        let socket = Arc::clone(&socket);
        let targets = Arc::clone(&targets);
        let ack_map = Arc::clone(&ack_map);
        let chat = Arc::clone(&chat);
        let file_transfers = Arc::clone(&file_transfers);
        let redraw_notify = Arc::clone(&redraw_notify);
        let filename = filename.clone();
        let packet_clone = packet.clone();
        let chunk_id = chunk_index;
        let sender = sender.clone();

        tokio::spawn(async move {
            let mut attempt = 0;
            loop {
                attempt += 1;
                let targets_snapshot = targets.lock().await.clone();
                for addr in &targets_snapshot {
                    if Some(*addr) == sender { continue; }
                    let _ = socket.send_to(&packet_clone, *addr).await;
                }

                sleep(Duration::from_millis(ACK_TIMEOUT_MS)).await;

                let mut map = ack_map.lock().await;
                if map.remove(&(file_id, chunk_id)).is_some() {
                    // update progress
                    update_transfer_progress(
                        &chat,
                        &file_transfers,
                        &filename,
                        file_id,
                        chunk_id as u64 + 1,
                        total_chunks as u64,
                        TransferDirection::Upload,
                        TransferState::InProgress,
                    ).await;

                    redraw_notify.notify_one();
                    return;
                }

                if attempt > MAX_RETRIES {
                    update_transfer_progress(
                        &chat,
                        &file_transfers,
                        &filename,
                        file_id,
                        chunk_id as u64,
                        total_chunks as u64,
                        TransferDirection::Upload,
                        TransferState::Failed,
                    ).await;

                    redraw_notify.notify_one();
                    return;
                }
            }
        });

        chunk_index += 1;
    }

    // mark done
    update_transfer_progress(
        &chat,
        &file_transfers,
        &filename,
        file_id,
        total_chunks as u64,
        total_chunks as u64,
        TransferDirection::Upload,
        TransferState::Done,
    ).await;

    redraw_notify.notify_one();
    *transfer_counter.lock().await -= 1;

    chat_push_cap(&chat, ChatLine::Message {
        ts: Local::now(),
        msg: format!("Finished sending '{}'", filename),
    }).await;

    Ok(())
}


fn spawn_receiver(
    socket: Arc<UdpSocket>,
    chat: ChatHistory,
    files: FileMap,
    file_senders: FileSenderMap,
    ack_map: AckMap,
    transfer_counter: TransferCounter,
    file_transfers: FileTransfers,
    redraw_notify: Arc<tokio::sync::Notify>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    // Register new client
                    targets.lock().await.insert(src);

                    if len >= 3 && &buf[..3] == MSG_PREFIX {
                        // Chat message handling
                        let msg = String::from_utf8_lossy(&buf[3..len]).to_string();
                        chat_push_cap(&chat, ChatLine::Message {
                            ts: Local::now(),
                            msg: format!("{} says: {}", src, msg),
                        }).await;
                        redraw_notify.notify_one();

                        let targets_snapshot = targets.lock().await.clone();
                        for &addr in &targets_snapshot {
                            if addr != src {
                                let mut buf_to_send = Vec::with_capacity(3 + msg.len());
                                buf_to_send.extend_from_slice(MSG_PREFIX);
                                buf_to_send.extend_from_slice(msg.as_bytes());
                                let _ = socket.send_to(&buf_to_send, addr).await;
                            }
                        }
                    } else if len >= 11 && &buf[..3] == ACK_PREFIX {
                        let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                        let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                        ack_map.lock().await.insert((file_id, chunk_index), true);
                        redraw_notify.notify_one();
                    } else if len >= 9 {
                        handle_file_chunk(
                            &buf[..len],
                            len,
                            src,
                            files.clone(),
                            file_senders.clone(),
                            socket.clone(),
                            transfer_counter.clone(),
                            chat.clone(),
                            file_transfers.clone(),
                            redraw_notify.clone(),
                            targets.clone(),
                        ).await;
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
}

// -------------------- SERVER LOOP --------------------
async fn run_server(cli: Cli) -> Result<()> {
    // -------------------- Shared State --------------------
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(tokio::sync::Notify::new());
    let clients: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let file_senders = Arc::new(Mutex::new(HashMap::new()));

    let secret_bytes = secret_to_bytes(&cli.secret);
    let mut current_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", current_port)).await?);
    println!("Server listening on port {}", current_port);

    // -------------------- Terminal Loop --------------------
    tokio::spawn({
        let args = TerminalArgs {
            chat: chat_history.clone(),
            socket: socket.clone(),
            targets: clients.clone(),
            redraw_notify: redraw_notify.clone(),
            file_transfers: file_transfers.clone(),
            ack_map: ack_map.clone(),
            transfer_counter: transfer_counter.clone(),
            last_client: Some(last_client.clone()),
        };
        async move { terminal_loop(args).await }
    });

    // -------------------- Receiver --------------------
    spawn_receiver(
        socket.clone(),
        chat_history.clone(),
        files.clone(),
        file_senders.clone(),
        ack_map.clone(),
        transfer_counter.clone(),
        file_transfers.clone(),
        redraw_notify.clone(),
        clients.clone(),
    );

    // -------------------- Port Rotation --------------------
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
        if new_port != current_port {
            println!("Rotating server port: {} -> {}", current_port, new_port);
            let new_socket = Arc::new(UdpSocket::bind(("0.0.0.0", new_port)).await?);
            current_port = new_port;

            spawn_receiver(
                new_socket.clone(),
                chat_history.clone(),
                files.clone(),
                file_senders.clone(),
                ack_map.clone(),
                transfer_counter.clone(),
                file_transfers.clone(),
                redraw_notify.clone(),
                clients.clone(),
            );
        }
    }
}

// -------------------- CLIENT LOOP --------------------
async fn run_client(cli: Cli, server: String) -> Result<()> {
    let chat_history: ChatHistory = Arc::new(Mutex::new(Vec::new()));
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let files: FileMap = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: AckMap = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(tokio::sync::Notify::new());

    let secret_bytes = secret_to_bytes(&cli.secret);
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    println!("Client bound to {}", socket.local_addr()?);

    // Targets set will be updated with current server port
    let targets: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));

    // Spawn a task to update the server port periodically
    {
        let targets_clone = targets.clone();
        let server_ip = server.clone();
        tokio::spawn(async move {
            let mut current_port = 0u16;
            loop {
                let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range);
                if new_port != current_port {
                    current_port = new_port;
                    let addr: SocketAddr = format!("{}:{}", server_ip, current_port).parse().unwrap();
                    let mut t = targets_clone.lock().await;
                    t.clear();
                    t.insert(addr);
                    println!("Client now targeting server at {}", addr);
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    // Terminal loop
    tokio::spawn({
        let args = TerminalArgs {
            chat: chat_history.clone(),
            socket: socket.clone(),
            targets: targets.clone(),
            redraw_notify: redraw_notify.clone(),
            file_transfers: file_transfers.clone(),
            ack_map: ack_map.clone(),
            transfer_counter: transfer_counter.clone(),
            last_client: None,
        };
        async move { terminal_loop(args).await }
    });

    // Receiver loop
    tokio::spawn({
        let chat = chat_history.clone();
        let sock = socket.clone();
        let redraw = redraw_notify.clone();
        let files = files.clone();
        let file_senders = Arc::new(Mutex::new(HashMap::new()));
        let ack_map = ack_map.clone();
        let file_transfers = file_transfers.clone();
        let transfer_counter = transfer_counter.clone();
        let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None)); // dummy for client

        async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if len >= 3 && &buf[..3] == MSG_PREFIX {
                            let msg = String::from_utf8_lossy(&buf[3..len]).to_string();
                            chat_push_cap(&chat, ChatLine::Message {
                                ts: Local::now(),
                                msg: format!("{} says: {}", src, msg),
                            }).await;
                            redraw.notify_one();
                        } else if len >= 11 && &buf[..3] == ACK_PREFIX {
                            let file_id = u32::from_be_bytes(buf[3..7].try_into().unwrap());
                            let chunk_index = u32::from_be_bytes(buf[7..11].try_into().unwrap());
                            ack_map.lock().await.insert((file_id, chunk_index), true);
                            redraw.notify_one();
                        } else if len >= 9 {
                            handle_file_chunk(
                                &buf,
                                len,
                                src,
                                files.clone(),
                                file_senders.clone(),
                                sock.clone(),
                                transfer_counter.clone(),
                                chat.clone(),
                                file_transfers.clone(),
                                redraw.clone(),
                                targets.clone(),
                            ).await;
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        }
    });

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
