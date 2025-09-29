// Argument parsing
use clap::{Parser, Subcommand};

// Async runtime
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::UdpSocket,
    sync::{broadcast, Mutex, Notify},
    task,
    time::{sleep, Duration, Instant},
};

// Standard library
use std::{
    cmp::min,
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryInto,
    fmt,
    io::{stdout, Write},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::SystemTime,
};

// Cryptography
use sha1::{Digest, Sha1};

// Terminal UI
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode, size, Clear, ClearType},
};

// Error handling
use anyhow::Result;

// Time utilities
use chrono::Local;

// Progress bars
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

// Random utilities
use rand::{rngs::StdRng, Rng, SeedableRng};

// cryptography
use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::aead::{Aead};
use sha2::Sha256;


// -------------------- CONSTANTS --------------------
const MAX_UDP_PAYLOAD: usize = 65507;
const MSG_PREFIX: &[u8] = b"MSG";
const ACK_PREFIX: &[u8] = b"ACK";
const MAX_RETRIES: usize = 5;
const HISTORY_LIMIT: usize = 500;
const RECEIVE_TIMEOUT_MS: u64 =  1500;
const PORT_ROTATION_DELAY: u64 = 60; // secs
static mut WINDOW_SIZE:usize = MAX_UDP_PAYLOAD - 1000;

// cryptography constants
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 100_000;

// -------------------- TYPES --------------------
pub type TransferCounter = Arc<Mutex<u32>>;
pub type ChatHistory = Arc<Mutex<Vec<ChatLine>>>;
pub type FileTransfers = Arc<Mutex<HashMap<String, (u64, u64, TransferDirection, TransferState)>>>;
pub type Targets = Arc<Mutex<HashSet<SocketAddr>>>;
pub type FileAckTracker = Arc<Mutex<HashMap<String, HashMap<SocketAddr, HashSet<u32>>>>>;
// Server-side file forwarding map
pub type ForwardTracker = Arc<Mutex<HashMap<u32, HashMap<SocketAddr, HashSet<u32>>>>>;
pub type ChunkCache = Arc<Mutex<HashMap<u32, HashMap<u32, FileChunk>>>>;


#[derive(Clone, Copy, Debug)]
pub enum TransferDirection { Upload, Download
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferState { InProgress, Done, Failed
}

#[derive(Clone, Debug)]
pub enum ChatLine {
    Message {
        ts: chrono::DateTime<Local>,
        msg: String,
},
    Transfer {
        ts: chrono::DateTime<Local>,
        id: u32,
        filename: String,
        done: u64,
        total: u64,
        direction: TransferDirection,
        state: TransferState,
   
},

}

#[derive(Debug)]
pub struct FileProgress {
    pub pb: ProgressBar,
    pub total_chunks: u32,

}

impl FileProgress {
    fn new(name: &str, total_chunks: u32, multi: &MultiProgress) -> Self {
        let pb = multi.add(ProgressBar::new(total_chunks as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb.set_message(format!("Receiving {}", name));

        Self { pb, total_chunks }
    }
}


#[derive(Debug, Clone)]
pub struct AckPacket {
    pub file_id: u32,
    pub chunk_index: u32,
}

impl AckPacket {
    //fn new(file_id: u32, chunk_index: u32) -> Self {
    //    Self { file_id, chunk_index }
    //}

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.file_id.to_be_bytes());
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let file_id = u32::from_be_bytes(buf[0..4].try_into().ok()?);
        let chunk_index = u32::from_be_bytes(buf[4..8].try_into().ok()?);
        Some(Self { file_id, chunk_index })
    }
}

#[derive(Debug, Clone)]
pub struct FileAck {
    /// Map from client address -> set of chunk indices acknowledged
    pub per_client: HashMap<SocketAddr, HashSet<u32>>,
}

impl FileAck {
    /// Create a new empty FileAck
    fn new() -> Self {
        Self {
            per_client: HashMap::new(),
        }
    }

    /// Initialize tracking for a list of clients
    fn init_clients(&mut self, clients: &[SocketAddr]) {
        for &addr in clients {
            self.per_client.entry(addr).or_insert_with(HashSet::new);
        }
    }

    /// Record an ACK for a client and chunk index
    /// Returns true if this chunk was newly acknowledged
    fn acknowledge(&mut self, client: SocketAddr, chunk_index: u32) -> bool {
        let entry = self.per_client.entry(client).or_insert_with(HashSet::new);
        entry.insert(chunk_index)
    }

    /// Returns the minimum number of ACKed chunks among all clients
    fn min_acked(&self) -> usize {
        self.per_client.values().map(|s| s.len()).min().unwrap_or(0)
    }
}

impl Default for FileAck {
    fn default() -> Self {
        Self::new()
    }
}


/// Helper to render progress bars
fn render_progress(done: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return String::new();
    }

    let ratio = done as f64 / total as f64;
    let filled = (ratio * width as f64).round() as usize;
    let filled = filled.min(width);
    let bar = "#".repeat(filled) + &".".repeat(width - filled);

    format!("[{}] {}/{}", bar, done, total)
}


impl fmt::Display for ChatLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatLine::Message { ts, msg } => {
                write!(f, "[{}] {}", ts.format("%H:%M:%S"), msg)
            }

            ChatLine::Transfer {
                ts,
                filename,
                done,
                total,
                direction,
                state,
                ..
            } => {
                let dir = match direction {
                    TransferDirection::Upload => "↑",
                    TransferDirection::Download => "↓",
                };

                let st = match state {
                    TransferState::InProgress => "…",
                    TransferState::Done => "✔",
                    TransferState::Failed => "✘",
                };

                let bar = render_progress(*done, *total, 20);

                write!(
                    f,
                    "[{}] {} {} {} {}",
                    ts.format("%H:%M:%S"),
                    dir,
                    filename,
                    bar,
                    st
                )
            }
        }
    }
}


// Shared progress map: file_id → progress bar & total chunks
type FileProgressMap = Arc<Mutex<HashMap<u32, FileProgress>>>;

// ------------------- File State -------------------
#[derive(Clone)]
struct FileState {
    //file_id: u32,
    filename: String,
    total_chunks: Option<u32>,
    chunks: BTreeMap<u32, Vec<u8>>,
    last_seen: Instant,

}

// Message representing a received chunk to be processed by the file manager.
#[derive(Debug, Clone)]
pub struct FileChunk {
    file_id: u32,
    chunk_index: u32,
    total_chunks: Option<u32>,
    filename: Option<String>,
    payload: Vec<u8>,
    src: Option<SocketAddr>,

}

impl FileChunk {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.file_id.to_be_bytes());
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());

        if self.chunk_index == 0 {
            if let Some(name) = &self.filename {
                buf.push(name.len() as u8);
                buf.extend_from_slice(name.as_bytes());
            }
            if let Some(total) = self.total_chunks {
                buf.extend_from_slice(&total.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.payload);
        buf
    }

    fn from_bytes(buf: &[u8], src: SocketAddr) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        let file_id = u32::from_be_bytes(buf[0..4].try_into().ok()?);
        let chunk_index = u32::from_be_bytes(buf[4..8].try_into().ok()?);
        let mut offset = 8;

        let mut filename = None;
        let mut total_chunks = None;

        if chunk_index == 0 && offset < buf.len() {
            let name_len = buf[offset] as usize;
            offset += 1;
            if offset + name_len + 4 <= buf.len() {
                let raw_name = buf[offset..offset + name_len].to_vec();
                filename = Some(String::from_utf8(raw_name).unwrap());
                offset += name_len;
                total_chunks =
                    Some(u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?));
                offset += 4;
            }
        }

        if offset > buf.len() {
            return None;
        }

        let payload = buf[offset..].to_vec();

        Some(FileChunk {
            file_id,
            chunk_index,
            total_chunks,
            filename,
            payload,
            src: Some(src),
        })
    }
}


// -------------------- TERMINAL ARGs --------------------
struct TerminalArgs {
    pub socket: Arc<UdpSocket>,
    pub targets: Arc<Mutex<HashSet<SocketAddr>>>,
    pub redraw_notify: Arc<Notify>,
    pub file_transfers: FileTransfers,
    pub transfer_counter: TransferCounter,
    pub chat_rx: Arc<Mutex<broadcast::Receiver<ChatLine>>>,
    pub ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
    secret: String,
 }

async fn chat_push_cap(chat: &ChatHistory, line: ChatLine) {
    let mut c = chat.lock().await; // lock the mutex
    if c.len() >= HISTORY_LIMIT { c.remove(0);
}
    c.push(line);

}

// -------------------- CLI --------------------
#[derive(Parser, Clone)]
struct Cli {
    #[command(subcommand)]
    role: Role,
    #[arg(short, long, default_value = "1025")]
    base_port: u16,
    #[arg(short, long, default_value = "65535")]
    port_range: u16,
    #[arg(short, long)]
    secret: String,

}

#[derive(Subcommand, Clone)]
enum Role {
    Server,
    Client { #[arg(short, long, default_value = "127.0.0.1")] server: String},
}

// -------------------- UTILS --------------------
fn secret_to_bytes(secret: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()

}

fn compute_port(secret_bytes: &[u8], base_port: u16, port_range: u16, trigger: &mut SystemTime, current_port: u16, first_run: &mut bool) -> u16 {
    let should_i = SystemTime::now()
        .duration_since(*trigger)
        .unwrap()
        .as_secs();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if should_i >= PORT_ROTATION_DELAY || *first_run{
        let period_index = now / 60; // floor to minute

        let mut hasher = Sha1::new();
        hasher.update(secret_bytes);
        hasher.update(&period_index.to_be_bytes());
        let digest = hasher.finalize();
        let slice: [u8; 4] = digest[16..20].try_into().unwrap();
        let val = u32::from_be_bytes(slice);

        *trigger = SystemTime::now();

        if *first_run{
            * first_run = false;
        }

        return base_port + (val % port_range as u32) as u16
    }
    current_port
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

fn derive_key(password: &str) -> [u8; KEY_LEN] {
    // deterministically derive salt from password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let salt = &hash[..SALT_LEN];

    // PBKDF2 with fixed salt to get 32-byte key
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn derive_nonce(plaintext: &str) -> [u8; NONCE_LEN] {
    // deterministically derive nonce from plaintext
    let hash = Sha256::digest(plaintext.as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hash[..NONCE_LEN]);
    nonce
}

fn encrypt_string(password: &str, plaintext: &str) -> Result<String> {
    let key_bytes = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let nonce_bytes = derive_nonce(&(password.to_owned()+"batman"));//<--do better!
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(ciphertext))
}

fn decrypt_string(password: &str, ciphertext_b64: &str) -> Result<String> {
    let key_bytes = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let nonce_bytes = derive_nonce(&(password.to_owned()+"batman")); //<--do better!
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = general_purpose::URL_SAFE_NO_PAD.decode(ciphertext_b64)?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    Ok(String::from_utf8(plaintext)?)
}

// -------------------- TERMINAL --------------------
struct TerminalGuard;
impl TerminalGuard {
    fn new() -> Self { enable_raw_mode().unwrap(); TerminalGuard
}

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
        let _ts = match entry {
            ChatLine::Message { ts, .. } | ChatLine::Transfer { ts, .. } => ts,
        };
        lines.push(format!("{}", entry));
    }

    // --- File transfers ---
    let ft_snapshot = {
        let file_transfers_clone = file_transfers.clone();
        let ft_lock = file_transfers_clone.lock().await;
        ft_lock.clone() // clone the hashmap
    };

    for (fname, &(done, total, direction, state)) in ft_snapshot.iter() {
        let percent = if total > 0 {
            (done as f64 / total as f64 * 100.0).round() as u64
        } else {
            0
        };

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

// -------------------- KEY HANDLING --------------------
async fn handle_key(
    key_event: KeyEvent,
    input_buffer: &mut String,
    chat: &ChatHistory,
    socket: &Arc<UdpSocket>,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    redraw_notify: &Arc<Notify>,
    transfer_counter: &TransferCounter,
    history: &mut Vec<String>,
    history_index: &mut Option<usize>,
    search_mode: &mut bool,
    search_buffer: &mut String,
    search_result_index: &mut Option<usize>,
    scroll_offset: &mut usize,
    visible_rows: usize,
    socket_clone_for_send: Arc<UdpSocket>,
    targets_clone_for_send: Arc<Mutex<HashSet<SocketAddr>>>,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
    secret: String,
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
                *search_result_index =
                    history.iter().rposition(|entry| entry.contains(&*search_buffer));
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
                *search_result_index =
                    history.iter().rposition(|entry| entry.contains(&*search_buffer));
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

                    // Generate a unique file ID
                    let file_id = {
                        let mut ctr = transfer_counter.lock().await;
                        *ctr += 1;
                        *ctr
                    };

                    // Clone state needed for the async task
                    let socket_clone = socket_clone_for_send.clone();
                    let targets_clone = targets_clone_for_send.clone();
                    let ack_map_clone = ack_map.clone();

                    tokio::spawn(async move {
                        if let Err(e) = send_file(
                            socket_clone,
                            targets_clone,
                            path,
                            file_id,
                            ack_map_clone,
                        )
                        .await
                        {
                            eprintln!("Failed to send file: {}", e);
                        }
                    });
                } else if input.starts_with("/quit") {
                    let _ = disable_raw_mode();
                    let mut stdout = stdout();
                    let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
                    std::process::exit(0);
                } else {
					// ENCRYPT
					let encrypted = encrypt_string(&secret, &input).expect("ERROR: Encrupting message failed");
					
                    let targets_lock = targets.lock().await;
                    for &addr in targets_lock.iter() {
                        let _ = send_chat_message_to_target(socket.clone(), addr, &encrypted).await;
                    }
                    chat_push_cap(
                        chat,
                        ChatLine::Message {
                            ts: Local::now(),
                            msg: format!("You: {}", input),
                        },
                    )
                    .await;
                    redraw_notify.notify_one();
                }
            }
        }

        KeyCode::Up => {
            if !*search_mode {
                if let Some(idx) = history_index {
                    if *idx > 0 {
                        *idx -= 1;
                        *input_buffer = history[*idx].clone();
                    }
                } else if !history.is_empty() {
                    *history_index = Some(history.len() - 1);
                    *input_buffer = history.last().unwrap().clone();
                }
            }
        }

        KeyCode::Down => {
            if !*search_mode {
                if let Some(idx) = history_index {
                    if *idx + 1 < history.len() {
                        *idx += 1;
                        *input_buffer = history[*idx].clone();
                    } else {
                        *history_index = None;
                        input_buffer.clear();
                    }
                }
            }
        }

        KeyCode::PageUp => {
            *scroll_offset += visible_rows / 2;
        }

        KeyCode::PageDown => {
            *scroll_offset = scroll_offset.saturating_sub(visible_rows / 2);
        }

        KeyCode::Esc => {
            if *search_mode {
                *search_mode = false;
                *search_buffer = String::new();
                *search_result_index = None;
            } else {
                input_buffer.clear();
            }
        }

        _ => {}
    }

    if *scroll_offset == 0 {
        redraw_notify.notify_one();
    }
}



// ------------------- File Manager Task -------------------
async fn file_manager_task(
    mut rx: broadcast::Receiver<FileChunk>,
    chat_tx: broadcast::Sender<ChatLine>,
    file_transfers: FileTransfers,
    transfer_counter: TransferCounter,
    redraw_notify: Arc<Notify>,
    ack_tracker: FileAckTracker,
) {
    let state: Arc<Mutex<HashMap<u32, FileState>>> = Arc::new(Mutex::new(HashMap::new()));
    let completed_files = Arc::new(Mutex::new(HashSet::new()));

	loop{
		// === Stale transfer cleanup ===
		{
			let state = state.clone();
			let file_transfers = file_transfers.clone();
			let ack_tracker = ack_tracker.clone();

			tokio::spawn(async move {
				let timeout = Duration::from_millis(RECEIVE_TIMEOUT_MS);
				let mut interval = tokio::time::interval(Duration::from_secs(1));

				loop {
					interval.tick().await;
					let now = Instant::now();
					let mut stale_ids = Vec::new();

					{
						let state_guard = state.lock().await;
						for (&fid, entry) in state_guard.iter() {
							if now.duration_since(entry.last_seen) > timeout {
								stale_ids.push(fid);
							}
						}
					}

					for fid in stale_ids {
						if let Some(entry) = state.lock().await.remove(&fid) {
							let filename = entry.filename.clone();
							let done = entry.chunks.len() as u64;
							let total = entry.total_chunks.unwrap_or(done as u32) as u64;

							let mut ft = file_transfers.lock().await;
							ft.insert(
								filename.clone(),
								(
									done,
									total,
									TransferDirection::Download,
									TransferState::Failed,
								),
							);

							/*let _ = chat_tx
								.send(ChatLine::Transfer {
									ts: Local::now(),
									id: fid,
									filename: filename.clone(),
									done,
									total,
									direction: TransferDirection::Download,
									state: TransferState::Failed,
								})
								.await;

							let _ = chat_tx
								.send(ChatLine::Message {
									ts: Local::now(),
									msg: format!(
										"Transfer {} timed out - marked as failed",
										fid
									),
								})
								.await;
							
							redraw_notify_clone.notify_one();
							*/

							let mut at = ack_tracker.lock().await;
							at.remove(&filename);
						}
					}
				}
			});
		}

		let mut last_redraw = Instant::now();

		while let Ok(chunk) = rx.recv().await {
			// Skip completed files
			{
				let completed_guard = completed_files.lock().await;
				if completed_guard.contains(&chunk.file_id) {
					continue;
				}
			}

			// Insert or get file state
			let mut entry = {
				let mut state_guard = state.lock().await;
				state_guard
					.entry(chunk.file_id)
					.or_insert_with(|| FileState {
						//file_id: chunk.file_id,
						filename: chunk.filename.clone().unwrap_or_default(),
						total_chunks: chunk.total_chunks,
						chunks: BTreeMap::new(),
						last_seen: Instant::now(),
					})
					.clone()
			};

			entry.last_seen = Instant::now();

			// Skip duplicate chunks
			if entry.chunks.contains_key(&chunk.chunk_index) {
				continue;
			}

			// Buffer the chunk
			entry.chunks.insert(chunk.chunk_index, chunk.payload.clone());

			// Update state
			{
				let mut state_guard = state.lock().await;
				state_guard.insert(chunk.file_id, entry.clone());
			}

			// --- ACK tracker update ---
			{
				let mut at = ack_tracker.lock().await;
				at.entry(entry.filename.clone())
					.or_insert_with(HashMap::new)
					.entry(chunk.src.unwrap().clone())
					.or_insert_with(HashSet::new)
					.insert(chunk.chunk_index);
			}

			// --- Update UI periodically ---
			if last_redraw.elapsed() >= Duration::from_millis(100) {

				/*let _ = chat_tx
					.send(ChatLine::Transfer {
						ts: Local::now(),
						id: chunk.file_id,
						filename: entry.filename.clone(),
						done,
						total,
						direction: TransferDirection::Download,
						state: TransferState::InProgress,
					})
					.await;

				redraw_notify.notify_one();*/
				last_redraw = Instant::now();
			}

			// --- Check for completion ---
			if let Some(total) = entry.total_chunks {
				if entry.chunks.len() as u32 == total {
					completed_files.lock().await.insert(chunk.file_id);

					let filename = entry.filename.clone();
					let file_chunks = entry.chunks.clone();
					let file_transfers = file_transfers.clone();
					let chat_tx_clone = chat_tx.clone();
					let transfer_counter = transfer_counter.clone();
					let redraw_notify = redraw_notify.clone();

					tokio::spawn(async move {
						// Reassemble chunks and write to disk in blocking thread to avoid stalling tokio reactor
						let file_chunks_clone = file_chunks.clone();
						let filename_clone = filename.clone();
						let write_result = tokio::task::spawn_blocking(move || {
							// Assemble in blocking thread
							let mut file_data: Vec<u8> = Vec::new();
							for i in 0..total {
								if let Some(c) = file_chunks_clone.get(&i) {
									file_data.extend_from_slice(c);
								}
							}
							// Write synchronously in blocking thread
							std::fs::write(&filename_clone, &file_data)
						})
						.await;

						if let Ok(Ok(_)) = write_result {
							// Write succeeded
						} else {
							eprintln!("Failed to write file {}", filename);
						}

						// Update transfer info (back in async context)
						let mut ft = file_transfers.lock().await;
						ft.insert(
							filename.clone(),   (
								total as u64,
								total as u64,
								TransferDirection::Download,
								TransferState::Done,
							),
						);

						let mut ctr = transfer_counter.lock().await;
						if *ctr > 0 {
							*ctr -= 1;
						}

						let _ = chat_tx_clone
							.send(ChatLine::Transfer {
								ts: Local::now(),
								id: chunk.file_id,
								filename: filename.clone(),
								done: total as u64,
								total: total as u64,
								direction: TransferDirection::Download,
								state: TransferState::Done,
							});

						let _ = chat_tx_clone
							.send(ChatLine::Message {
								ts: Local::now(),
								msg: format!("Saved received file '{}'", filename),
							});

						redraw_notify.notify_one();
					});
				}
			}
		}
	}
}

// -------------------- SENDER: send_file uses broadcast receiver for ACKs --------------------
async fn send_file(
    socket: Arc<UdpSocket>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    path: String,
    file_id: u32,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
) -> anyhow::Result<()> {
    // Open file
    let mut file = File::open(&path).await?;
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    let filename = Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("file_{ }", file_id));

    unsafe {
        let chunk_size = WINDOW_SIZE;
        let total_chunks = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;

        // Read all chunks
        let mut chunks: Vec<FileChunk> = Vec::with_capacity(total_chunks as usize);
        let mut buf = vec![0u8; chunk_size];
        for chunk_index in 0..total_chunks {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;     
           
            }
            chunks.push(FileChunk {
                file_id,
                chunk_index,
                total_chunks: if chunk_index == 0 { 
                    Some(total_chunks)     
                
                } else { 
                    None     
                
                },
                filename: Some(filename.clone()),
                payload: buf[..n].to_vec(),
                src: None,
           
            });
       
        }

        // Initialize per-client ACK tracking
        let clients: Vec<SocketAddr> = {
            let t = targets.lock().await;
            t.iter().copied().collect()
       
        };
        {
            let mut ack_lock = ack_map.lock().await;
            let mut fa = FileAck::new();
            fa.init_clients(&clients);
            ack_lock.insert(file_id, fa);
       
        }

        // Main sending loop

        for client in clients{
            for chunk in &chunks {
				let mut maximum = MAX_RETRIES;
                loop{
                    let _ = socket.send_to(&chunk.to_bytes(), client).await;
                    
                    maximum -= 1;
                    
                    // Sleep briefly to wait for ACKs
					sleep(Duration::from_millis(50)).await;

                    if maximum == 0{
                        break;
                    }
                    
                    // Sleep briefly to wait for ACKs
                    sleep(Duration::from_millis(50)).await;

                }
            }
        }
    }
    Ok(())

}

/// Spawn a robust File Transfer Manager responsible for resending chunks,
/// tracking per-chunk retries, and removing peers that exceed retries.
/// This centralizes forward_cache + ack_map logic to avoid race conditions.
fn spawn_file_transfer_manager(
    socket: Arc<UdpSocket>,
    forward_cache: Arc<Mutex<HashMap<u32, HashMap<u32, FileChunk>>>>,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    tokio::spawn(async move {
        use std::collections::HashMap as StdHashMap;
        let mut retry_counts: StdHashMap<(u32, u32, SocketAddr), usize> = StdHashMap::new();

        loop {
            // snapshot targets
            let peers: Vec<SocketAddr> = {
                let tg = targets.lock().await;
                tg.iter().copied().collect()
            };

            // snapshot chunks
            let chunks: Vec<(u32, u32, FileChunk)> = {
                let cache = forward_cache.lock().await;
                cache
                    .iter()
                    .flat_map(|(&fid, inner)| {
                        inner.iter().map(move |(&idx, chunk)| (fid, idx, chunk.clone()))
                    })
                    .collect()
            };

            for (fid, idx, chunk) in chunks {
                // who has acked this chunk already?
                let acked_peers: Vec<SocketAddr> = {
					let map = ack_map.lock().await;
					map.get(&fid)
						.map(|ack| {
							ack.per_client.iter()
							   .filter_map(|(p, done)| if done.contains(&idx) { Some(*p) } else { None })
							   .collect()
						})
						.unwrap_or_default()
				};

                // send to peers who haven't acked
                for peer in peers.iter().filter(|p| !acked_peers.contains(p)) {
                    let key = (fid, idx, *peer);
                    let retries = retry_counts.get(&key).cloned().unwrap_or(0);

                    if retries < MAX_RETRIES {
                        let data = chunk.to_bytes();
                        let _ = socket.send_to(&data, peer).await;
                        retry_counts.insert(key, retries + 1);
                    } else {
                        //eprintln!(
                        //    "Dropping peer {} for file {} chunk {} after {} retries",
                        //    peer, fid, idx, MAX_RETRIES
                        //);
                    }
                }
            }

            // cleanup: drop fully acked chunks
            {
                let mut cache = forward_cache.lock().await;
                let map = ack_map.lock().await;
                for (&fid, chunks_map) in cache.iter_mut() {
                    chunks_map.retain(|&idx, _| {
                        if let Some(acks) = map.get(&fid) {
                            let all_done = peers.iter().all(|p| {
                                acks.per_client
                                    .get(p)
                                    .map(|s| s.contains(&idx))
                                    .unwrap_or(false)
                            });
                            !all_done
                        } else {
                            true
                        }
                    });
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
}

// -------------------- RECEIVER --------------------
async fn spawn_receiver(
    socket: Arc<UdpSocket>,
    chat_tx: broadcast::Sender<ChatLine>,
    file_chunk_tx: broadcast::Sender<FileChunk>,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
    progress_map: Arc<Mutex<HashMap<u32, FileProgress>>>,
    targets: Arc<Mutex<HashSet<SocketAddr>>>,
    targets_tx: broadcast::Sender<SocketAddr>,
    server_mode: bool,
    forward_cache: ChunkCache,
    secret: String,
) {
	
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            
    match socket.recv_from(&mut buf).await {
                
        Ok((len, src)) => {
            // update targets (chat & client list)
            update_targets(src, &targets, &targets_tx, server_mode).await;

            // handle chat
            try_handle_chat(&buf[..len], src, &chat_tx, &socket, &targets, server_mode, secret).await;

            // handle ACK
            try_handle_ack(&buf[..len], src, ack_map.clone(), progress_map.clone()).await;

            // handle file chunks with forwarding
            try_handle_file_chunk(
                &buf[..len],
                src,
                &socket,
                &file_chunk_tx,
                &targets,
                server_mode,
                &progress_map,
                &forward_cache,
                ack_map,
            ).await;
        }
        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
    }
}



// ---------------- Helper functions ----------------

// -------------------- TARGET UPDATE --------------------
async fn update_targets(
    src: SocketAddr,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    targets_tx: &broadcast::Sender<SocketAddr>,
    server_mode: bool,
) {
    if server_mode {
        // Add new client if in server mode
        let mut t = targets.lock().await;
        if !t.contains(&src) {
            t.insert(src);
        }

    } else {
        // In client mode, only keep the latest sender
        let mut t = targets.lock().await;
        if !t.contains(&src) {
            t.clear();
            t.insert(src);
        }
    }

    // Notify via channel (non-blocking)
    let _ = targets_tx.send(src);
}

async fn try_handle_chat(
    buf: &[u8],
    src: SocketAddr,
    chat_tx: &broadcast::Sender<ChatLine>,
    socket: &UdpSocket,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    server_mode: bool,
    secret: String,
) -> bool {
    if buf.len() < 3
        || &buf[..3] != MSG_PREFIX
        || &buf[..3] == ACK_PREFIX
    {
        return false;
    }
    // Interpret the buffer as UTF-8 chat message
    if let Ok(msg) = std::str::from_utf8(buf) {
        // DECRYPT
        let decrypted = decrypt_string(&secret, &msg[3..]).expect("ERROR: Decrypting the message failed!");
        
        let chat_line = ChatLine::Message {
            // timestamp is already part of msg (sender included it)
            ts: Local::now(),
            msg: decrypted,
        };
        let _ = chat_tx.send(chat_line);
        

        // Server should relay to all peers except original sender
        if server_mode {
            let peers = targets.lock().await.clone();
            for peer in peers {
                if peer != src {
                    let _ = socket.send_to(buf, peer).await;
                }
            }
        }
    }
    true
}

async fn try_handle_ack(
    ack_buf: &[u8],
    src_addr: SocketAddr,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
    progress_map: Arc<Mutex<HashMap<u32, FileProgress>>>,
) -> bool {

    if ack_buf.len() < 3
        || &ack_buf[..3] == MSG_PREFIX
        || &ack_buf[..3] != ACK_PREFIX
    {
        return false;
    }

    let ack = match AckPacket::from_bytes(&ack_buf[3..]) {
        Some(a) => a,
        None => return false,
    };

    let mut ack_lock = ack_map.lock().await;
    let file_acks = ack_lock.entry(ack.file_id).or_insert_with(FileAck::new);
    let is_new = file_acks.acknowledge(src_addr, ack.chunk_index);

    if !is_new {
        return false;
    }
	
    let total_chunks = {
        let progress_lock = progress_map.lock().await;
        progress_lock.get(&ack.file_id).map(|f| f.total_chunks).unwrap_or(0)
    };

    let mut progress_lock = progress_map.lock().await;
    if let Some(entry) = progress_lock.get_mut(&ack.file_id) {
        entry.pb.inc(1);
        if file_acks.min_acked() as u32 >= total_chunks {
            entry.pb.finish_with_message("Upload Completed");
        }
    }
    true
}


async fn try_handle_file_chunk(
    buf: &[u8],
    src: SocketAddr,
    socket: &Arc<UdpSocket>,
    file_chunk_tx: &broadcast::Sender<FileChunk>,
    targets: &Arc<Mutex<HashSet<SocketAddr>>>,
    server_mode: bool,
    progress_map: &FileProgressMap,
    forward_cache: &ChunkCache,
    ack_map: Arc<Mutex<HashMap<u32, FileAck>>>,
) -> bool {

    if buf.len() < 3
        || &buf[..3] == MSG_PREFIX
        || &buf[..3] == ACK_PREFIX
    {
        return false;
    }

    // Parse incoming chunk
    let chunk = match FileChunk::from_bytes(buf, src) {
        Some(c) => c,
        None => return false,
    };

    // Send ACK back to sender
    let ack = AckPacket {
        file_id: chunk.file_id,
        chunk_index: chunk.chunk_index,
    };
        
    let mut formated_ack = ACK_PREFIX.to_vec();
    formated_ack.extend(&ack.to_bytes());
     
    let _ = socket.send_to(&formated_ack, src).await;
    
    // Log the full packet in hex for debugging
	//eprintln!("Sent ACK packet: {:02X?}", formated_ack);

	// Optional: log human-readable info
	//eprintln!("ACK details: file_id={}, chunk_index={}", ack.file_id, ack.chunk_index);
    
    // Save chunk into forward_cache for later resends
    if server_mode {
        let mut cache_lock = forward_cache.lock().await;
        let file_chunks = cache_lock.entry(chunk.file_id).or_default();
        file_chunks.insert(chunk.chunk_index, chunk.clone());
        
        // Forward to other clients immediately if server mode        
		spawn_file_transfer_manager(
			socket.clone(),
			forward_cache.clone(),
			ack_map.clone(),
			targets.clone(),
		)
	}
	
    // Update progress bar
    update_progress(progress_map, &chunk).await;

    // Deliver downstream to other tasks
    let _ = file_chunk_tx.send(chunk);

    true
}

async fn update_progress(progress_map: &FileProgressMap, chunk: &FileChunk) {
    let mut progress_lock = progress_map.lock().await;
    let entry = progress_lock.entry(chunk.file_id).or_insert_with(|| FileProgress {
        pb: ProgressBar::hidden(),
        total_chunks: 0,
    });

    if entry.total_chunks == 0 {
        if let (Some(total_chunks), Some(name)) = (chunk.total_chunks, chunk.filename.clone()) {
            entry.total_chunks = total_chunks;
            let fp = FileProgress::new(&name.clone(), total_chunks.clone(), &MultiProgress::new());
            fp.pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            fp.pb.set_message(format!("Receiving {}", name));
            entry.pb = fp.pb;
        }
    }

    if entry.total_chunks > 0 {
        entry.pb.inc(1);
        if chunk.chunk_index + 1 == entry.total_chunks {
            entry.pb.finish_with_message("Completed");
        }
    }
}


// -------------------- TERMINAL LOOP --------------------
async fn terminal_loop(args: TerminalArgs) {
    let TerminalArgs {
        socket,
        targets,
        redraw_notify,
        file_transfers,
        transfer_counter,
        chat_rx,
        ack_map,
        secret,
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
            // ---- Chat messages ----
            res = async {
                let mut rx_lock = chat_rx.lock().await;
                rx_lock.recv().await
            } => {
                match res {
                    Ok(line) => {
                        let mut chat_lock = chat_lines.lock().await;
                        chat_lock.push(line);
                        if chat_lock.len() > HISTORY_LIMIT_TERMINAL {
                            chat_lock.remove(0);
                        }
                        if auto_scroll {
                            desired_scroll_offset = 0;
                        }
                        redraw_notify.notify_one();
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("Missed {} chat messages", n);
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        eprintln!("Chat channel closed");
                        break;
                    },
                }
            }

            // ---- Redraw terminal ----
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

            // ---- Key events ----
            res = task::spawn_blocking(|| event::poll(Duration::from_millis(50))) => {
                if let Ok(Ok(true)) = res {
                    if let Ok(Event::Key(key_event)) = event::read() {
                        match key_event.code {
                            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Up | KeyCode::Down => auto_scroll = false,
                            KeyCode::Esc => auto_scroll = true,
                            _ => {},
                        }

                        handle_key(key_event, &mut input_buffer, &chat_lines, &socket, &targets, &redraw_notify, &transfer_counter, &mut history, &mut search_result_index, &mut search_mode, &mut search_buffer, &mut history_index, &mut desired_scroll_offset, visible_rows, socket.clone(), targets.clone(), ack_map.clone(), secret.clone()).await;
                    }
                }
            }
        }
    }
}

// -------------------- SERVER & CLIENT RUN --------------------
async fn run_server(cli: Cli) -> anyhow::Result<()> {
    let (chat_tx, _) = broadcast::channel::<ChatLine>(256);

    // ---------------- Shared state ----------------
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(Notify::new());
    let clients: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let ack_tracker: FileAckTracker = Arc::new(Mutex::new(HashMap::new()));
    let forward_cache: ChunkCache = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: Arc<Mutex<HashMap<u32, FileAck>>> = Arc::new(Mutex::new(HashMap::new()));
    let progress_map: Arc<Mutex<HashMap<u32, FileProgress>>> = Arc::new(Mutex::new(HashMap::new()));

    // ---------------- Channels ----------------
    let (file_chunk_tx, _) = broadcast::channel::<FileChunk>(1024);
    let (targets_tx, _) = broadcast::channel::<SocketAddr>(256);

    let secret_bytes = secret_to_bytes(&cli.secret);

    let mut trigger = SystemTime::now();
    let mut first_run: bool = true;

    let mut current_port = compute_port(&secret_bytes, cli.base_port, cli.port_range, &mut trigger, cli.base_port, &mut first_run);
    let mut socket = Arc::new(UdpSocket::bind(("0.0.0.0", current_port)).await?);

    // ---------------- Terminal args ----------------
    let terminal_args = TerminalArgs {
        socket: socket.clone(),
        targets: clients.clone(),
        redraw_notify: redraw_notify.clone(),
        file_transfers: file_transfers.clone(),
        transfer_counter: transfer_counter.clone(),
        chat_rx: Arc::new(Mutex::new(chat_tx.subscribe())),
        ack_map: ack_map.clone(),
        secret: cli.secret.clone(),
    };

    // ---------------- Spawn terminal loop ----------------
    tokio::spawn(async move {
        terminal_loop(terminal_args).await;
    });

    let chat_tx_clone = chat_tx.clone();
    let file_chunk_rx_broadcast = file_chunk_tx.subscribe();
    // ---------------- Spawn file manager task ----------------
    tokio::spawn(async move {
        file_manager_task(
            file_chunk_rx_broadcast,
            chat_tx_clone,
            file_transfers.clone(),
            transfer_counter.clone(),
            redraw_notify.clone(),
            ack_tracker.clone(),
        )
        .await;
    });


    loop {

        let socket_clone = socket.clone();
        let chat_tx_broadcast_1= chat_tx.clone();
        let file_chunk_tx_broadcast = file_chunk_tx.clone();
        let ack_map_clone = ack_map.clone();
        let progress_map_clone = progress_map.clone();
        let clients_clone = clients.clone();
        let targets_tx_clone = targets_tx.clone();
        let forward_cache_clone = forward_cache.clone();
        let secret = cli.secret.clone();

        let _poll_result = task::spawn_blocking(|| {
                // This is blocking, safe inside spawn_blocking
                // ---------------- Spawn receiver ----------------
                tokio::spawn({
                    async move {
                        spawn_receiver(
                            socket_clone,
                            chat_tx_broadcast_1,
                            file_chunk_tx_broadcast,
                            ack_map_clone,
                            progress_map_clone,
                            clients_clone,
                            targets_tx_clone,
                            true,
                            forward_cache_clone,
                            secret,
                        )
                        .await;
                    }
                });
                event::poll(Duration::from_millis(50))
            })
            .await
            .expect("Blocking poll task panicked"); // Handle thread panics

            //if let Ok(true) = poll_result {

            //}
        

        // ---------------- Port rotation loop ----------------
        let new_port = compute_port(&secret_bytes, cli.base_port, cli.port_range, &mut trigger, current_port, &mut first_run);
        if new_port != current_port && new_port != cli.base_port{
            drop(socket);
            socket = Arc::new(UdpSocket::bind(("0.0.0.0", new_port)).await?);
            current_port = new_port;
        }

        //small delay to prevent tight loop
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_client(cli: Cli, server: String) {
    let (chat_tx, _) = broadcast::channel::<ChatLine>(256);

    // ---------------- Shared state ----------------
    let file_transfers: FileTransfers = Arc::new(Mutex::new(HashMap::new()));
    let transfer_counter: TransferCounter = Arc::new(Mutex::new(0));
    let redraw_notify = Arc::new(Notify::new());
    let ack_tracker: FileAckTracker = Arc::new(Mutex::new(HashMap::new()));
    let ack_map: Arc<Mutex<HashMap<u32, FileAck>>> = Arc::new(Mutex::new(HashMap::new()));
    let progress_map: Arc<Mutex<HashMap<u32, FileProgress>>> = Arc::new(Mutex::new(HashMap::new()));
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("ERROR: Couldn't bind he socket"));
    let targets: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let clients: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let forward_cache: ChunkCache = Arc::new(Mutex::new(HashMap::new()));

    // ---------------- Populate initial targets ----------------
    {
        let ports = compute_possible_ports(&secret_to_bytes(&cli.secret), cli.base_port, cli.port_range);
        let mut t = targets.lock().await;
        t.clear();
        for port in ports {
            t.insert(format!("{}:{}", server, port).parse::<SocketAddr>().expect("ERROR: couldn't parse the SocketAddr"));
        }
    }

    // ---------------- Send initial hello to server targets ----------------
    for &addr in targets.lock().await.iter() {
        let mut buf = Vec::with_capacity(MSG_PREFIX.len() + 5);
        buf.extend_from_slice(MSG_PREFIX);
        buf.extend_from_slice(b"hello");
        let encrypted_hello_bytes = encrypt_string(&cli.secret.clone(), &String::from_utf8(buf.clone()).expect("ERROR: invalid character in string")).expect("Error: Hello encryption failed").into_bytes();
        let _ = socket.send_to(&encrypted_hello_bytes, addr).await;
    }

    // ---------------- Channels ----------------
    let (file_chunk_tx, _) = broadcast::channel::<FileChunk>(1024);
    let (targets_tx, _) = broadcast::channel::<SocketAddr>(256);

    // ---------------- Periodically refresh target list ----------------
    {
        let targets = targets.clone();
        let server = server.clone();
        let secret_bytes = secret_to_bytes(&cli.secret);
        let shared_rng = Arc::new(Mutex::new(StdRng::from_entropy()));
        let rng_clone = shared_rng.clone();

        tokio::spawn(async move {
            loop {
                let mut rng = rng_clone.lock().await;
                
                let small_entropy = rng.gen_range(MAX_UDP_PAYLOAD-5000..MAX_UDP_PAYLOAD-1000);
                unsafe {
                    WINDOW_SIZE = min(small_entropy, MAX_UDP_PAYLOAD-1000)
                }

                let ports = compute_possible_ports(&secret_bytes, cli.base_port, cli.port_range);
                let mut t = targets.lock().await;
                t.clear();
                for port in ports {
                    t.insert(format!("{}:{}", server, port).parse::<SocketAddr>().unwrap());
                }

                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }

    // ---------------- Terminal args ----------------
    let terminal_args = TerminalArgs {
        socket: socket.clone(),
        targets: targets.clone(),
        redraw_notify: redraw_notify.clone(),
        file_transfers: file_transfers.clone(),
        transfer_counter: transfer_counter.clone(),
        chat_rx: Arc::new(Mutex::new(chat_tx.subscribe())),
        ack_map: ack_map.clone(),
        secret: cli.secret.clone(),
    };

    // ---------------- Spawn terminal loop ----------------
    tokio::spawn(async move { terminal_loop(terminal_args).await });

	let chat_tx_clone = chat_tx.clone();
    let file_chunk_rx_broadcast = file_chunk_tx.subscribe();
    // ---------------- Spawn file manager task ----------------
    tokio::spawn(async move {
        file_manager_task(
            file_chunk_rx_broadcast,
            chat_tx_clone,
            file_transfers.clone(),
            transfer_counter.clone(),
            redraw_notify.clone(),
            ack_tracker.clone(),
        )
        .await;
    });

    loop {
        let socket_clone = socket.clone();
        let chat_tx_broadcast_1= chat_tx.clone();
        let file_chunk_tx_broadcast = file_chunk_tx.clone();
        let ack_map_clone = ack_map.clone();
        let progress_map_clone = progress_map.clone();
        let clients_clone = clients.clone();
        let targets_tx_clone = targets_tx.clone();
        let forward_cache_clone = forward_cache.clone();
        let secret = cli.secret.clone();

        // Run the blocking poll without blocking the async runtime
        let _poll_result = task::spawn_blocking(|| {
            // This is blocking, safe inside spawn_blocking
            tokio::spawn({
                async move {
                    // ---------------- Spawn receiver ----------------
                    spawn_receiver(
                        socket_clone,
                        chat_tx_broadcast_1,
                        file_chunk_tx_broadcast,
                        ack_map_clone,
                        progress_map_clone,
                        clients_clone,
                        targets_tx_clone,
                        false,
                        forward_cache_clone,
                        secret,
                    )
                    .await;
                }
            });
            event::poll(Duration::from_millis(50))
        })
        .await
        .expect("Blocking poll task panicked"); // Handle thread panics

        //if let Ok(true) = poll_result {
            
        //}

        //small delay to prevent tight loop
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// -------------------- MAIN --------------------
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.role {
        Role::Server => {
            println!("Starting server...");
            run_server(cli.clone()).await?;
        }
        Role::Client { server } => {
            println!("Starting client connecting to {}...", server);
            run_client(cli.clone(), server.clone()).await;
        }
    }

    Ok(())
}
