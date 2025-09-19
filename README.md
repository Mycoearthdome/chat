# Rust UDP Chat & File Transfer with Port Rotation

A terminal-based UDP chat and file transfer application built in Rust using `tokio` and `crossterm`.  
Supports secure port rotation, live file transfer progress, and an interactive terminal interface.

---

## Features

- Terminal-based chat interface with scrollable history
- Reliable file transfer over UDP with live progress bars
- Server-side port rotation every minute for enhanced security
- Client automatically computes server port from shared secret
- Multiple concurrent transfers
- Cross-platform terminal interface using `crossterm`

---

## Dependencies

The project uses the following Rust crates:

- `clap` — Command-line argument parsing
- `tokio` — Async runtime, networking, and timers
- `sha1` — SHA-1 hashing for port calculation
- `crossterm` — Terminal input/output and styling
- `chrono` — Timestamp formatting
- `anyhow` — Error handling

---

## Installation

1. Ensure Rust is installed: [Install Rust](https://www.rust-lang.org/tools/install)
2. Clone the repository:

```bash
git clone https://github.com/yourusername/rust-udp-chat.git
cd rust-udp-chat

    Build the project:

cargo build --release

Usage
Server

cargo run --release -- server --secret "my_secret" --base-port 4000 --port-range 1000

    --secret: Shared secret used for port rotation

    --base-port: Base port number (default: 4000)

    --port-range: Range for port rotation (default: 1000)

The server will rotate its port every 60 seconds according to the secret.
Client

cargo run --release -- client --server 127.0.0.1 --secret "my_secret" --base-port 4000 --port-range 1000

    --server: IP address of the server

    --secret: Shared secret (must match the server)

    --base-port: Base port number (must match the server)

    --port-range: Port rotation range (must match the server)

The client will compute the current server port using the shared secret and automatically follow port rotation.
Commands

    /send <file_path> — Send a file to the last connected client

    Enter — Send typed chat message

    Backspace — Delete character in input

    Esc — Clear input

    Arrow Up/Down — Scroll chat history

    Page Up/Down — Scroll half-screen

    Ctrl+C — Exit

Architecture Overview

    Server/Client: Runs as either a server or client

    UDP Networking: Uses tokio::net::UdpSocket for async networking

    Port Rotation: Server computes a new port every 60 seconds based on secret

    File Transfer: Chunked file transfer with sliding window, ACKs, and retries

    Terminal: Live rendering with progress bars for file uploads/downloads

File Transfer Protocol

    Each file is split into UDP chunks

    First chunk contains filename and total chunks

    Subsequent chunks carry raw file data

    ACK packets are sent per chunk

    Retries and windowing ensure reliable delivery over UDP

License

CC0 License © 2025

Notes

    Both server and client must share the same secret, base port, and port range

    Designed for LAN or trusted network; additional encryption can be added

    Terminal interface is optimized for at least 80x24 terminals
