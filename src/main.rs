use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{ServerOptions, NamedPipeServer};

#[derive(Deserialize)]
struct Command {
    action: String,
    text: Option<String>,
    keys: Option<String>,
    submit: Option<bool>,
}

#[derive(Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
}

impl Response {
    fn ok() -> Self {
        Self {
            status: Some("sent".to_string()),
            error: None,
            running: None,
            socket: None,
            pid: None,
            bytes: None,
        }
    }

    fn error(msg: &str) -> Self {
        Self {
            status: None,
            error: Some(msg.to_string()),
            running: None,
            socket: None,
            pid: None,
            bytes: None,
        }
    }

    fn status(running: bool, socket: &str, pid: Option<u32>) -> Self {
        Self {
            status: None,
            error: None,
            running: Some(running),
            socket: Some(socket.to_string()),
            pid,
            bytes: None,
        }
    }
}

fn parse_escape_sequences(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('x') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte);
                    }
                }
                Some('r') => {
                    chars.next();
                    result.push(b'\r');
                }
                Some('n') => {
                    chars.next();
                    result.push(b'\n');
                }
                Some('t') => {
                    chars.next();
                    result.push(b'\t');
                }
                Some('\\') => {
                    chars.next();
                    result.push(b'\\');
                }
                _ => result.push(b'\\'),
            }
        } else {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            result.extend_from_slice(encoded.as_bytes());
        }
    }

    result
}

fn get_socket_path(session_id: &str) -> String {
    // If explicit socket path set, use it
    if let Ok(path) = std::env::var("CLAUDE_SOCKET") {
        return path;
    }

    #[cfg(unix)]
    {
        format!("/tmp/claudec-{}.sock", session_id)
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\claudec-{}", session_id)
    }
}

/// Get Claude projects base directory
/// Respects CLAUDE_CONFIG_DIR env var, defaults to ~/.claude
fn get_claude_projects_base() -> PathBuf {
    let base = if let Ok(config_dir) = std::env::var("CLAUDE_CONFIG_DIR") {
        PathBuf::from(config_dir)
    } else {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".claude")
    };
    base.join("projects")
}

/// Get Claude projects directory path based on current working directory
fn get_claude_projects_dir(cwd: &std::path::Path) -> PathBuf {
    let projects_base = get_claude_projects_base();

    // Convert cwd to Claude's folder naming: /Users/foo/bar -> -Users-foo-bar
    let cwd_str = cwd.to_string_lossy();
    let folder_name = cwd_str.replace('/', "-").replace('\\', "-");

    projects_base.join(folder_name)
}

/// Parse args to detect --resume or --continue flags
fn parse_session_args(args: &[String]) -> SessionMode {
    // Check for --resume <id> or -r <id>
    for (i, arg) in args.iter().enumerate() {
        if arg == "--resume" || arg == "-r" {
            if let Some(id) = args.get(i + 1) {
                // If it looks like a UUID, it's a session ID
                if id.contains('-') && id.len() > 30 {
                    return SessionMode::Resume(id.clone());
                }
            }
        }
        if let Some(id) = arg.strip_prefix("--resume=") {
            if id.contains('-') && id.len() > 30 {
                return SessionMode::Resume(id.to_string());
            }
        }
    }

    // Check for --continue or -c
    if args.iter().any(|a| a == "--continue" || a == "-c") {
        return SessionMode::Continue;
    }

    SessionMode::New
}

#[derive(Debug)]
enum SessionMode {
    New,
    Continue,
    Resume(String),
}

/// Find session file by ID across all project folders
fn find_session_by_id(session_id: &str) -> Option<PathBuf> {
    let projects_base = get_claude_projects_base();

    if let Ok(entries) = std::fs::read_dir(&projects_base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let session_file = path.join(format!("{}.jsonl", session_id));
                if session_file.exists() {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Find the most recently created session file after start_time
fn find_session_id(projects_dir: &std::path::Path, start_time: SystemTime) -> Option<String> {
    let entries = std::fs::read_dir(projects_dir).ok()?;

    let mut newest: Option<(String, SystemTime)> = None;

    for entry in entries.flatten() {
        let path = entry.path();

        // Only look at .jsonl files (not folders)
        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            if let Ok(metadata) = path.metadata() {
                // Use created time (birthtime on macOS/BSD, fallback to modified on Linux)
                let created = metadata.created().unwrap_or_else(|_| {
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH)
                });

                // Must be created after we started
                if created >= start_time {
                    // Extract UUID from filename (e.g., "abc123.jsonl" -> "abc123")
                    if let Some(stem) = path.file_stem() {
                        let id = stem.to_string_lossy().to_string();

                        // Keep track of the newest one
                        if newest.as_ref().map(|(_, t)| created > *t).unwrap_or(true) {
                            newest = Some((id, created));
                        }
                    }
                }
            }
        }
    }

    newest.map(|(id, _)| id)
}

/// Wait for Claude logo to appear, then find the session file
async fn wait_for_session_id(
    projects_dir: PathBuf,
    start_time: SystemTime,
    logo_detected: Arc<AtomicBool>,
) -> Option<String> {
    // First, wait for logo to appear (up to 60 seconds)
    for _ in 0..120 {
        if logo_detected.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if !logo_detected.load(Ordering::Relaxed) {
        return None; // Logo never appeared
    }

    // Give Claude a moment to finish writing session file
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now find the session file (poll for up to 10 seconds in case of delay)
    for _ in 0..20 {
        if let Some(id) = find_session_id(&projects_dir, start_time) {
            return Some(id);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

fn get_claude_cmd() -> String {
    std::env::var("CLAUDE_CMD").unwrap_or_else(|_| {
        which::which("claude")
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "claude".to_string())
    })
}

fn print_help() {
    eprintln!(
        r#"Claude Commander v{}

Run Claude Code with a socket API for programmatic command injection.

USAGE:
    claudec [OPTIONS] [-- CLAUDE_ARGS...]

OPTIONS:
    -h, --help       Show this help message
    -v, --version    Show version

All other arguments are passed directly to Claude Code.

SOCKET API:
    Unix:    /tmp/claudec-<SESSION_ID>.sock
    Windows: \\\\.\\pipe\\claudec-<SESSION_ID>

    Session ID is auto-detected from Claude's session file.
    Override socket path with CLAUDE_SOCKET env var.

EXAMPLES:
    claudec                         # Start Claude Code
    claudec -d /path/to/project     # Start in specific directory
    claudec --help                  # This help

SEND COMMANDS:
    echo '{{"action":"send","text":"Hello"}}' | nc -U /tmp/claude.sock

For more info: https://github.com/sstraus/claude-commander"#,
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Handle our own flags
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "-v" || a == "--version") {
        eprintln!("claudec {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // Record start time to find session file created after this
    let start_time = SystemTime::now();
    let cwd = std::env::current_dir()?;
    let claude_cmd = get_claude_cmd();

    // Determine projects dir - check if --resume has explicit session ID
    let session_mode = parse_session_args(&args);
    let projects_dir = match &session_mode {
        SessionMode::Resume(session_id) => {
            // If resuming a known session, find its project folder
            find_session_by_id(session_id).unwrap_or_else(|| get_claude_projects_dir(&cwd))
        }
        _ => get_claude_projects_dir(&cwd),
    };

    // Set up PTY
    let pty_system = native_pty_system();
    let (cols, rows) = term_size::dimensions().unwrap_or((80, 24));

    let pair = pty_system.openpty(PtySize {
        rows: rows as u16,
        cols: cols as u16,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    // Build command
    let mut cmd = CommandBuilder::new(&claude_cmd);
    cmd.cwd(std::env::current_dir()?);
    for arg in &args {
        cmd.arg(arg);
    }

    // Spawn claude in PTY
    let mut child = pair.slave.spawn_command(cmd)?;
    let child_pid = child.process_id();
    drop(pair.slave);

    let pty_writer = Arc::new(Mutex::new(pair.master.take_writer()?));
    let mut pty_reader = pair.master.try_clone_reader()?;

    // Channel for PTY writes from socket handler
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    // Set terminal to raw mode (guard restores on drop)
    let _raw_mode_guard = RawModeGuard::new();

    // Handle terminal resize
    #[cfg(unix)]
    {
        let pty_master = Arc::new(Mutex::new(pair.master));

        // Force initial resize to ensure correct size
        if let Some((cols, rows)) = term_size::dimensions() {
            let _ = pty_master.lock().unwrap().resize(PtySize {
                rows: rows as u16,
                cols: cols as u16,
                pixel_width: 0,
                pixel_height: 0,
            });
        }

        let pty_master_resize = Arc::clone(&pty_master);

        tokio::spawn(async move {
            let mut signals = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .expect("Failed to create signal handler");

            while signals.recv().await.is_some() {
                if let Some((cols, rows)) = term_size::dimensions() {
                    let _ = pty_master_resize.lock().unwrap().resize(PtySize {
                        rows: rows as u16,
                        cols: cols as u16,
                        pixel_width: 0,
                        pixel_height: 0,
                    });
                }
            }
        });
    }

    #[cfg(windows)]
    let _ = pair.master; // Keep master alive on Windows

    // Flag to signal when Claude logo is detected
    let logo_detected = Arc::new(AtomicBool::new(false));
    let logo_detected_writer = Arc::clone(&logo_detected);

    // PTY reader -> stdout (also detects Claude logo)
    let stdout_handle = std::thread::spawn(move || {
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        let mut output_buffer = String::new();
        let logo_pattern = "Claude Code v";

        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();

                    // Check for logo if not yet detected
                    if !logo_detected_writer.load(Ordering::Relaxed) {
                        if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                            output_buffer.push_str(text);
                            // Keep buffer reasonably sized
                            if output_buffer.len() > 4096 {
                                output_buffer = output_buffer.split_off(output_buffer.len() - 2048);
                            }
                            if output_buffer.contains(logo_pattern) {
                                logo_detected_writer.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // stdin -> PTY
    let pty_writer_stdin = Arc::clone(&pty_writer);
    let _stdin_handle = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1024];

        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut writer) = pty_writer_stdin.lock() {
                        let _ = writer.write_all(&buf[..n]);
                        let _ = writer.flush();
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Channel receiver -> PTY
    let pty_writer_channel = Arc::clone(&pty_writer);
    tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Ok(mut writer) = pty_writer_channel.lock() {
                let _ = writer.write_all(&data);
                let _ = writer.flush();
            }
        }
    });

    // Wait for Claude logo, then find session ID
    // This works for all modes: new session, --continue, --resume (with or without ID)
    let session_id = match wait_for_session_id(projects_dir, start_time, logo_detected).await {
        Some(id) => id,
        None => {
            eprintln!("Error: Could not detect Claude session ID");
            std::process::exit(1);
        }
    };

    let socket_path = get_socket_path(&session_id);

    // Clean up stale socket (Unix only)
    #[cfg(unix)]
    let _ = std::fs::remove_file(&socket_path);

    eprintln!("claudec socket: {}", socket_path);

    // Socket server
    #[cfg(unix)]
    {
        let listener = UnixListener::bind(&socket_path)?;
        let socket_path_clone = socket_path.clone();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let tx = tx.clone();
                    let socket_path = socket_path_clone.clone();
                    let pid = child_pid;

                    tokio::spawn(async move {
                        let (reader, mut writer) = stream.into_split();
                        let mut reader = BufReader::new(reader);
                        let mut line = String::new();

                        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                            let response = match serde_json::from_str::<Command>(&line) {
                                Ok(cmd) => handle_command(cmd, &tx, &socket_path, pid).await,
                                Err(_) => Response::error("Invalid JSON"),
                            };

                            let json = serde_json::to_string(&response).unwrap() + "\n";
                            let _ = writer.write_all(json.as_bytes()).await;
                            let _ = writer.flush().await;
                            line.clear();
                        }
                    });
                }
            }
        });
    }

    #[cfg(windows)]
    {
        let socket_path_clone = socket_path.clone();

        tokio::spawn(async move {
            loop {
                let server = match ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&socket_path_clone)
                {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if server.connect().await.is_ok() {
                    let tx = tx.clone();
                    let socket_path = socket_path_clone.clone();
                    let pid = child_pid;

                    tokio::spawn(async move {
                        let (reader, mut writer) = tokio::io::split(server);
                        let mut reader = BufReader::new(reader);
                        let mut line = String::new();

                        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                            let response = match serde_json::from_str::<Command>(&line) {
                                Ok(cmd) => handle_command(cmd, &tx, &socket_path, pid).await,
                                Err(_) => Response::error("Invalid JSON"),
                            };

                            let json = serde_json::to_string(&response).unwrap() + "\n";
                            let _ = writer.write_all(json.as_bytes()).await;
                            let _ = writer.flush().await;
                            line.clear();
                        }
                    });
                }
            }
        });
    }

    // Wait for child to exit
    let exit_status = child.wait()?;

    // Cleanup socket (Unix only)
    #[cfg(unix)]
    let _ = std::fs::remove_file(&socket_path);

    // Wait for stdout thread
    let _ = stdout_handle.join();

    // _raw_mode_guard drops here, restoring terminal
    std::process::exit(exit_status.exit_code() as i32);
}

async fn handle_command(
    cmd: Command,
    tx: &mpsc::Sender<Vec<u8>>,
    socket_path: &str,
    pid: Option<u32>,
) -> Response {
    match cmd.action.as_str() {
        "send" => {
            let text = match cmd.text {
                Some(t) => t,
                None => return Response::error("text field required"),
            };

            let submit = cmd.submit.unwrap_or(true);

            if tx.send(text.into_bytes()).await.is_err() {
                return Response::error("Failed to send");
            }

            if submit {
                tokio::task::yield_now().await;
                if tx.send(vec![b'\r']).await.is_err() {
                    return Response::error("Failed to send enter");
                }
            }

            Response::ok()
        }

        "keys" => {
            let keys = match cmd.keys {
                Some(k) => k,
                None => return Response::error("keys field required"),
            };

            let parsed = parse_escape_sequences(&keys);
            let len = parsed.len();

            if tx.send(parsed).await.is_err() {
                return Response::error("Failed to send");
            }

            Response {
                status: Some("sent".to_string()),
                bytes: Some(len),
                ..Response::ok()
            }
        }

        "status" => Response::status(true, socket_path, pid),

        _ => Response::error("Unknown action. Use: send, keys, status"),
    }
}

// Unix raw mode handling
#[cfg(unix)]
struct RawModeGuard {
    original: libc::termios,
}

#[cfg(unix)]
impl RawModeGuard {
    fn new() -> Option<Self> {
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) != 0 {
                return None;
            }

            let original = termios;

            libc::cfmakeraw(&mut termios);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);

            Some(Self { original })
        }
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.original);
            print!("\x1b[?25h");
            print!("\x1b[0m");
            let _ = std::io::stdout().flush();
        }
    }
}

// Windows raw mode handling
#[cfg(windows)]
struct RawModeGuard {
    original_mode: u32,
}

#[cfg(windows)]
impl RawModeGuard {
    fn new() -> Option<Self> {
        use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
        use winapi::um::processenv::GetStdHandle;
        use winapi::um::winbase::STD_INPUT_HANDLE;
        use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_INPUT;

        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut original_mode: u32 = 0;

            if GetConsoleMode(handle, &mut original_mode) == 0 {
                return None;
            }

            let raw_mode = ENABLE_VIRTUAL_TERMINAL_INPUT;
            SetConsoleMode(handle, raw_mode);

            Some(Self { original_mode })
        }
    }
}

#[cfg(windows)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        use winapi::um::consoleapi::SetConsoleMode;
        use winapi::um::processenv::GetStdHandle;
        use winapi::um::winbase::STD_INPUT_HANDLE;

        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            SetConsoleMode(handle, self.original_mode);
            print!("\x1b[?25h");
            print!("\x1b[0m");
            let _ = std::io::stdout().flush();
        }
    }
}
