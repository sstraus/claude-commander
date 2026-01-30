#!/usr/bin/env node
// Minimal Claude Commander client - zero latency on socket down

const net = require('net');
const fs = require('fs');

const SOCK = process.platform === 'win32'
  ? '\\\\.\\pipe\\claude-api'
  : (process.env.CLAUDE_SOCKET || '/tmp/claude.sock');

function send(cmd) {
  return new Promise((resolve, reject) => {
    if (process.platform !== 'win32') {
      try {
        if (!fs.statSync(SOCK).isSocket()) return reject(new Error('down'));
      } catch { return reject(new Error('down')); }
    }
    const c = net.createConnection(SOCK, () => c.write(JSON.stringify(cmd) + '\n'));
    c.on('data', d => { resolve(JSON.parse(d.toString())); c.end(); });
    c.on('error', () => reject(new Error('down')));
  });
}

function isUp() {
  return new Promise(r => {
    if (process.platform !== 'win32') {
      try { if (!fs.statSync(SOCK).isSocket()) return r(false); }
      catch { return r(false); }
    }
    const c = net.createConnection(SOCK, () => { c.end(); r(true); });
    c.on('error', () => r(false));
  });
}

async function main() {
  const [,, action, ...rest] = process.argv;

  if (!action || action === '-h' || action === '--help') {
    console.log(`Usage: claude-send <action> [args]

Actions:
  ping              Check if socket is up (exit 0/1)
  status            Get session status
  send <text>       Send text and submit
  send -n <text>    Send without submitting
  keys <seq>        Send raw key sequence

Examples:
  claude-send ping
  claude-send send "Hello Claude"
  claude-send keys "\\x0d"`);
    process.exit(0);
  }

  try {
    if (action === 'ping') {
      const up = await isUp();
      console.log(up ? 'up' : 'down');
      process.exit(up ? 0 : 1);
    }

    if (action === 'status') {
      console.log(JSON.stringify(await send({ action: 'status' })));
      process.exit(0);
    }

    if (action === 'send') {
      const noSubmit = rest[0] === '-n';
      const text = noSubmit ? rest.slice(1).join(' ') : rest.join(' ');
      if (!text) { console.error('text required'); process.exit(1); }
      console.log(JSON.stringify(await send({ action: 'send', text, submit: !noSubmit })));
      process.exit(0);
    }

    if (action === 'keys') {
      if (!rest[0]) { console.error('keys required'); process.exit(1); }
      console.log(JSON.stringify(await send({ action: 'keys', keys: rest[0] })));
      process.exit(0);
    }

    console.error(`Unknown action: ${action}`);
    process.exit(1);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}

main();
