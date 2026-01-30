# Claude Commander

Run [Claude Code](https://claude.ai/code) with a socket API for programmatic command injection.

## Features

- **Full TUI**: See Claude Code's interactive UI in your terminal
- **Socket API**: Send prompts via Unix socket / Windows named pipe
- **Zero overhead**: Native Rust binary, ~600KB
- **Cross-platform**: macOS, Linux, Windows

## Installation

### Download binary

Download from [Releases](https://github.com/sstraus/claude-commander/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/sstraus/claude-commander/releases/latest/download/claudec-macos-arm64 -o claudec
chmod +x claudec

# macOS (Intel)
curl -L https://github.com/sstraus/claude-commander/releases/latest/download/claudec-macos-x64 -o claudec
chmod +x claudec

# Linux (x64)
curl -L https://github.com/sstraus/claude-commander/releases/latest/download/claudec-linux-x64 -o claudec
chmod +x claudec

# Linux (ARM64)
curl -L https://github.com/sstraus/claude-commander/releases/latest/download/claudec-linux-arm64 -o claudec
chmod +x claudec
```

### Build from source

```bash
cargo install --git https://github.com/sstraus/claude-commander
```

## Usage

### Start Claude Commander

```bash
claudec

# With arguments for Claude Code
claudec -d /path/to/project
```

This will:
1. Launch Claude Code TUI
2. Detect the session ID from Claude's session file (after logo appears)
3. Start socket server at `/tmp/claudec-<SESSION_ID>.sock` (Unix) or `\\.\pipe\claudec-<SESSION_ID>` (Windows)
4. You can interact via keyboard AND socket API

### Send commands

**Using the Node.js client:**

```bash
node client/claude-send.js send "Hello Claude"
node client/claude-send.js ping
node client/claude-send.js status
```

**Using netcat (Unix):**

```bash
# Replace <SESSION_ID> with the actual session ID shown by claudec
echo '{"action":"send","text":"Hello Claude"}' | nc -U /tmp/claudec-<SESSION_ID>.sock
```

**Using Node.js:**

```js
const net = require('net');

function send(sessionId, cmd) {
  const sock = process.platform === 'win32'
    ? `\\\\.\\pipe\\claudec-${sessionId}`
    : `/tmp/claudec-${sessionId}.sock`;

  return new Promise((resolve, reject) => {
    const c = net.createConnection(sock, () => c.write(JSON.stringify(cmd) + '\n'));
    c.on('data', d => { resolve(JSON.parse(d.toString())); c.end(); });
    c.on('error', reject);
  });
}

await send('abc123-def456', { action: 'send', text: 'Hello Claude' });
```

## API

All commands are JSON objects, newline-delimited.

### send

Send text to Claude Code.

```json
{"action": "send", "text": "Hello Claude"}
{"action": "send", "text": "partial", "submit": false}
```

### keys

Send raw key sequences.

```json
{"action": "keys", "keys": "\\x0d"}
```

Common keys:
- `\x0d` - Enter
- `\x03` - Ctrl+C
- `\x1b` - Escape
- `\x1b[A` - Up arrow

### status

Get session status.

```json
{"action": "status"}
```

## Using from Claude Code Hooks

Hooks receive session info via stdin JSON. Extract `session_id` to build the socket path:

```bash
#!/bin/bash
# Example hook: ~/.claude/hooks/my-hook.sh

# Read hook input from stdin
INPUT=$(cat)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id')

# Build socket path
SOCKET="/tmp/claudec-${SESSION_ID}.sock"

# Send command to claudec
echo '{"action":"send","text":"Hello from hook!"}' | nc -U "$SOCKET"
```

The hook stdin JSON contains:
```json
{
  "session_id": "abc123-def456-...",
  "cwd": "/path/to/project",
  ...
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_SOCKET` | `/tmp/claudec-<SESSION_ID>.sock` | Override socket path |
| `CLAUDE_CMD` | `claude` | Claude Code command |
| `CLAUDE_CONFIG_DIR` | `~/.claude` | Claude config directory |

## License

MIT
