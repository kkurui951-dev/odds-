const express = require('express');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const TelegramBot = require('node-telegram-bot-api');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// ── Config ──
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_CHAT_ID = parseInt(process.env.ADMIN_CHAT_ID, 10);
const JWT_SECRET = process.env.JWT_SECRET || 'legitodds-secret-change-me';
const DATA_DIR = process.env.DATA_DIR || '.';

if (!BOT_TOKEN || !ADMIN_CHAT_ID || isNaN(ADMIN_CHAT_ID)) {
  console.error('❌ Missing or invalid BOT_TOKEN or ADMIN_CHAT_ID.');
  process.exit(1);
}

// ── Database ──
const dbPath = path.join(DATA_DIR, 'legitodds.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total INTEGER NOT NULL,
    payment_message TEXT,
    status TEXT DEFAULT 'pending',
    odds_delivered TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

console.log(`📦 Database at: ${dbPath}`);

// ── Express ──
const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static(__dirname));

// ── Auth middleware ──
function authRequired(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    req.phone = payload.phone;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── API: Register ──
app.post('/api/register', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
  const cleanPhone = phone.replace(/\s/g, '');
  if (!/^(\+?254|0)?7\d{8}$/.test(cleanPhone) && !/^(\+?254|0)?1\d{8}$/.test(cleanPhone)) {
    return res.status(400).json({ error: 'Invalid phone. Use: 07XXXXXXXX' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(cleanPhone);
  if (existing) return res.status(409).json({ error: 'Phone already registered' });

  const hash = await bcrypt.hash(password, 10);
  const info = db.prepare('INSERT INTO users (phone, password_hash) VALUES (?, ?)').run(cleanPhone, hash);
  const token = jwt.sign({ userId: info.lastInsertRowid, phone: cleanPhone }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, phone: cleanPhone });
});

// ── API: Login ──
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
  const cleanPhone = phone.replace(/\s/g, '');

  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(cleanPhone);
  if (!user) return res.status(401).json({ error: 'Invalid phone or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid phone or password' });

  const token = jwt.sign({ userId: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, phone: user.phone });
});

// ── API: Get user info ──
app.get('/api/me', authRequired, (req, res) => {
  const user = db.prepare('SELECT phone, created_at FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ phone: user.phone, createdAt: user.created_at });
});

// ── API: Create Order ──
app.post('/api/create-order', authRequired, (req, res) => {
  const { items, paymentMessage } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'Cart is empty' });
  if (!paymentMessage) return res.status(400).json({ error: 'Payment message required' });

  const total = items.reduce((s, i) => s + i.price, 0);
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let orderId = '';
  for (let i = 0; i < 6; i++) orderId += chars[Math.floor(Math.random() * chars.length)];

  db.prepare('INSERT INTO orders (user_id, items, total, payment_message, status) VALUES (?, ?, ?, ?, ?)')
    .run(req.userId, JSON.stringify(items), total, paymentMessage.substring(0, 4000), 'pending');

  const orderObj = { orderId, userId: req.userId, phone: req.phone, items, total, ws: null, createdAt: Date.now() };
  activeOrders.set(orderId, orderObj);

  // ── Telegram message with INLINE BUTTON ──
  const itemsText = items.map(i => `  • ${i.label} (${i.category}) — KSh ${i.price}`).join('\n');
  const adminMsg =
    `🆕 NEW ORDER: ${orderId}\n` +
    `━━━━━━━━━━━━━━━━━\n` +
    `Customer: ${req.phone}\n` +
    `Items:\n${itemsText}\n` +
    `━━━━━━━━━━━━━━━━━\n` +
    `Total: KSh ${total.toLocaleString()}\n` +
    `━━━━━━━━━━━━━━━━━\n` +
    `💬 Payment Message:\n${paymentMessage.substring(0, 3000)}\n` +
    `━━━━━━━━━━━━━━━━━`;

  const keyboard = {
    inline_keyboard: [[
      { text: '📤 Send Odds', callback_data: `send_odds:${orderId}` }
    ]]
  };

  bot.sendMessage(ADMIN_CHAT_ID, adminMsg, { reply_markup: keyboard }).catch(err =>
    console.error('Failed to notify admin:', err.message)
  );

  res.json({ orderId, total });
});

// ── WebSocket ──
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const activeOrders = new Map();
const ORDER_TTL_MS = 30 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [id, order] of activeOrders) {
    if (now - order.createdAt > ORDER_TTL_MS) {
      if (order.ws && order.ws.readyState === WebSocket.OPEN) {
        order.ws.send(JSON.stringify({ type: 'expired', orderId: id }));
        order.ws.close(1000);
      }
      activeOrders.delete(id);
    }
  }
}, 60 * 1000);

wss.on('connection', (ws) => {
  let boundOrderId = null;
  ws.on('message', (data) => {
    try {
      const { orderId } = JSON.parse(data.toString());
      if (activeOrders.has(orderId)) {
        const order = activeOrders.get(orderId);
        if (order.ws && order.ws !== ws && order.ws.readyState === WebSocket.OPEN) order.ws.close(1000);
        order.ws = ws;
        boundOrderId = orderId;
      }
    } catch {}
  });
  ws.on('close', () => {
    if (boundOrderId && activeOrders.has(boundOrderId)) {
      const order = activeOrders.get(boundOrderId);
      if (order.ws === ws) order.ws = null;
    }
  });
  ws.on('error', () => {
    if (boundOrderId && activeOrders.has(boundOrderId)) {
      const order = activeOrders.get(boundOrderId);
      if (order.ws === ws) order.ws = null;
    }
  });
});

// ── Telegram Bot ──
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// Track which orders the admin is about to type odds for
const awaitingOdds = new Map(); // chatId -> orderId

bot.on('callback_query', (query) => {
  if (query.from.id !== ADMIN_CHAT_ID) return;

  const data = query.data;
  if (!data.startsWith('send_odds:')) return;

  const orderId = data.split(':')[1];
  const order = activeOrders.get(orderId);

  if (!order) {
    bot.answerCallbackQuery(query.id, { text: '❌ Order already delivered or expired', show_alert: true });
    return;
  }

  // Tell admin to type the odds
  awaitingOdds.set(ADMIN_CHAT_ID, orderId);

  bot.answerCallbackQuery(query.id, { text: '✅ Ready! Type the odds below.' });
  bot.sendMessage(ADMIN_CHAT_ID,
    `✍️ Type the odds for order ${orderId} and send it here.\n\n` +
    `Example: 45\n` +
    `Or for multiple: 2.1 x 1.8 x 3.4`
  );
});

bot.on('message', (msg) => {
  if (msg.from.id !== ADMIN_CHAT_ID) return;

  const text = (msg.text || '').trim();

  // If admin is awaiting odds input
  if (awaitingOdds.has(ADMIN_CHAT_ID)) {
    const orderId = awaitingOdds.get(ADMIN_CHAT_ID);
    awaitingOdds.delete(ADMIN_CHAT_ID);

    if (!text) {
      bot.sendMessage(ADMIN_CHAT_ID, '⚠️ Empty message. Please type the odds and send again.');
      return;
    }

    const order = activeOrders.get(orderId);
    if (!order) {
      bot.sendMessage(ADMIN_CHAT_ID, `❌ Order ${orderId} no longer exists.`);
      return;
    }

    const odds = text;

    // Push to user's browser
    if (order.ws && order.ws.readyState === WebSocket.OPEN) {
      order.ws.send(JSON.stringify({
        type: 'result',
        orderId,
        odds,
        items: order.items,
        total: order.total
      }));
    } else {
      bot.sendMessage(ADMIN_CHAT_ID, `⚠️ Order ${orderId} — user's connection is lost. Odds: ${odds}`);
    }

    // Update DB
    db.prepare("UPDATE orders SET status = 'delivered', odds_delivered = ? WHERE id = (SELECT id FROM orders WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1)")
      .run(odds, order.userId);

    bot.sendMessage(ADMIN_CHAT_ID,
      `✅ Order ${orderId} delivered to ${order.phone}\n` +
      `📊 Odds sent: ${odds}\n` +
      `💰 Total: KSh ${order.total.toLocaleString()}`
    );

    activeOrders.delete(orderId);
    return;
  }

  // Fallback: manual ORDERID ODDS format still works
  const parts = text.split(/\s+/);
  if (parts.length >= 2 && activeOrders.has(parts[0])) {
    const order = activeOrders.get(parts[0]);
    const odds = parts.slice(1).join(' ');

    if (order.ws && order.ws.readyState === WebSocket.OPEN) {
      order.ws.send(JSON.stringify({ type: 'result', orderId: parts[0], odds, items: order.items, total: order.total }));
    }

    db.prepare("UPDATE orders SET status = 'delivered', odds_delivered = ? WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1")
      .run(odds, order.userId);

    bot.sendMessage(ADMIN_CHAT_ID, `✅ Order ${parts[0]} delivered to ${order.phone}\nOdds: ${odds}`);
    activeOrders.delete(parts[0]);
  } else if (text === '/start') {
    bot.sendMessage(msg.chat.id,
      '👋 LegitOdds Admin Bot\n\n' +
      'When an order comes in, click the 📤 Send Odds button.\n' +
      'Then type the odds and send.\n\n' +
      'Or manually: ORDERID odds\nExample: K7X2FA 45'
    );
  }
});

// ── Health ──
app.get('/healthz', (_req, res) => res.sendStatus(200));

// ── SPA fallback ──
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Shutdown ──
process.on('SIGTERM', () => {
  console.log('SIGTERM. Shutting down...');
  server.close(() => {
    wss.clients.forEach(ws => ws.close(1001));
    bot.stopPolling();
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
});

server.listen(PORT, () => {
  console.log(`✅ LegitOdds v2 running on port ${PORT}`);
  console.log(`🤖 Bot polling (admin: ${ADMIN_CHAT_ID})`);
  console.log(`📦 DB: ${dbPath}`);
});   
