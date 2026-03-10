const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: 'super_secret_chat_key_change_me_2',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
});

app.use(sessionMiddleware);

const io = new Server(server);
io.engine.use(sessionMiddleware);

app.use(express.static(__dirname));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

const usersFile = path.join(__dirname, 'users.json');
const messagesFile = path.join(__dirname, 'messages.json');
const pinnedFile = path.join(__dirname, 'pinned.json');

let users = [];
let messages = [];
let pinnedMessageId = null;
const onlineUsers = new Set();
const typingUsers = new Set();

function readJsonSafe(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

users = readJsonSafe(usersFile, []);
messages = readJsonSafe(messagesFile, []);
pinnedMessageId = readJsonSafe(pinnedFile, null);

function saveUsers() {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

function saveMessages() {
  fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2), 'utf8');
}

function savePinned() {
  fs.writeFileSync(pinnedFile, JSON.stringify(pinnedMessageId, null, 2), 'utf8');
}

function getUserByLogin(login) {
  return users.find(u => u.login.toLowerCase() === String(login).toLowerCase());
}

function authRequired(req, res, next) {
  if (!req.session.userLogin) {
    return res.status(401).json({ error: 'Нужно войти' });
  }
  next();
}

function pageAuthRequired(req, res, next) {
  if (!req.session.userLogin) {
    return res.redirect('/auth.html');
  }
  next();
}

function makeId() {
  return crypto.randomBytes(8).toString('hex');
}

function currentPinnedMessage() {
  return messages.find(m => m.id === pinnedMessageId) || null;
}

function publicUser(u) {
  return {
    login: u.login,
    role: u.role,
    avatar: u.avatar || '',
    bio: u.bio || '',
    mutedUntil: u.mutedUntil || 0,
    online: onlineUsers.has(u.login)
  };
}

function emitUsers() {
  io.emit('users update', users.map(publicUser));
}

function emitTyping() {
  io.emit('typing update', Array.from(typingUsers));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^\w.\-]/g, '_');
    cb(null, Date.now() + '-' + safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.get('/', (req, res) => {
  if (req.session.userLogin) return res.redirect('/chat.html');
  return res.redirect('/auth.html');
});

app.get('/go-chat', (req, res) => {
  if (req.session.userLogin) return res.redirect('/chat.html');
  return res.redirect('/auth.html');
});

app.get('/chat.html', pageAuthRequired, (req, res) => {
  res.sendFile(path.join(__dirname, 'chat.html'));
});

app.get('/profile.html', pageAuthRequired, (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.post('/api/register', async (req, res) => {
  const login = String(req.body.login || '').trim();
  const password = String(req.body.password || '').trim();
  const remember = !!req.body.remember;

  if (login.length < 3 || login.length > 20) {
    return res.status(400).json({ error: 'Логин 3-20 символов' });
  }

  if (password.length < 4 || password.length > 50) {
    return res.status(400).json({ error: 'Пароль 4-50 символов' });
  }

  if (!/^[a-zA-Zа-яА-ЯёЁ0-9_]+$/.test(login)) {
    return res.status(400).json({ error: 'Логин: буквы, цифры, _' });
  }

  if (getUserByLogin(login)) {
    return res.status(400).json({ error: 'Такой логин уже есть' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const role = users.length === 0 ? 'creator' : 'user';

  users.push({
    login,
    passwordHash,
    role,
    mutedUntil: 0,
    avatar: '',
    bio: ''
  });

  saveUsers();

  req.session.userLogin = login;

  if (remember) {
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
  } else {
    req.session.cookie.expires = false;
  }

  return res.json({ ok: true, login, role });
});

app.post('/api/login', async (req, res) => {
  const login = String(req.body.login || '').trim();
  const password = String(req.body.password || '').trim();
  const remember = !!req.body.remember;

  const user = getUserByLogin(login);
  if (!user) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }

  req.session.userLogin = user.login;

  if (remember) {
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
  } else {
    req.session.cookie.expires = false;
  }

  return res.json({ ok: true, login: user.login, role: user.role });
});

app.post('/api/logout', (req, res) => {
  if (req.session.userLogin) {
    onlineUsers.delete(req.session.userLogin);
    typingUsers.delete(req.session.userLogin);
    emitUsers();
    emitTyping();
  }

  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    return res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userLogin) {
    return res.json({ loggedIn: false });
  }

  const user = getUserByLogin(req.session.userLogin);
  if (!user) {
    return res.json({ loggedIn: false });
  }

  return res.json({
    loggedIn: true,
    login: user.login,
    role: user.role,
    mutedUntil: user.mutedUntil || 0,
    avatar: user.avatar || '',
    bio: user.bio || ''
  });
});

app.post('/api/profile', authRequired, (req, res) => {
  const user = getUserByLogin(req.session.userLogin);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  user.bio = String(req.body.bio || '').trim().slice(0, 120);
  saveUsers();
  emitUsers();

  return res.json({ ok: true, bio: user.bio });
});

app.post('/api/avatar', authRequired, upload.single('avatar'), (req, res) => {
  const user = getUserByLogin(req.session.userLogin);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Файл не загружен' });
  }

  if (!req.file.mimetype.startsWith('image/')) {
    return res.status(400).json({ error: 'Аватар должен быть картинкой' });
  }

  user.avatar = '/uploads/' + req.file.filename;
  saveUsers();
  emitUsers();

  return res.json({ ok: true, avatar: user.avatar });
});

app.post('/api/upload', authRequired, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Файл не загружен' });
  }

  const isImage = req.file.mimetype.startsWith('image/');
  const isVideo = req.file.mimetype.startsWith('video/');

  if (!isImage && !isVideo) {
    return res.status(400).json({ error: 'Можно только фото или видео' });
  }

  return res.json({
    ok: true,
    url: '/uploads/' + req.file.filename,
    kind: isImage ? 'image' : 'video'
  });
});

app.post('/api/mute', authRequired, (req, res) => {
  const currentUser = getUserByLogin(req.session.userLogin);
  if (!currentUser || currentUser.role !== 'creator') {
    return res.status(403).json({ error: 'Только создатель может мутить' });
  }

  const target = getUserByLogin(String(req.body.login || '').trim());
  const minutes = Number(req.body.minutes || 0);

  if (!target) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  if (target.role === 'creator') {
    return res.status(400).json({ error: 'Создателя мутить нельзя' });
  }

  if (minutes <= 0 || minutes > 10080) {
    return res.status(400).json({ error: 'Минуты: от 1 до 10080' });
  }

  target.mutedUntil = Date.now() + minutes * 60 * 1000;
  saveUsers();
  emitUsers();
  io.emit('system message', `${target.login} получил мут на ${minutes} мин.`);

  return res.json({ ok: true });
});

app.post('/api/unmute', authRequired, (req, res) => {
  const currentUser = getUserByLogin(req.session.userLogin);
  if (!currentUser || currentUser.role !== 'creator') {
    return res.status(403).json({ error: 'Только создатель может снимать мут' });
  }

  const target = getUserByLogin(String(req.body.login || '').trim());
  if (!target) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  target.mutedUntil = 0;
  saveUsers();
  emitUsers();
  io.emit('system message', `${target.login} больше не в муте.`);

  return res.json({ ok: true });
});

io.on('connection', (socket) => {
  const sessionData = socket.request.session;

  if (!sessionData || !sessionData.userLogin) {
    return socket.disconnect();
  }

  const user = getUserByLogin(sessionData.userLogin);
  if (!user) {
    return socket.disconnect();
  }

  onlineUsers.add(user.login);
  emitUsers();

  socket.emit('load messages', messages);
  socket.emit('pinned update', currentPinnedMessage());

  socket.on('typing', (isTyping) => {
    if (isTyping) typingUsers.add(user.login);
    else typingUsers.delete(user.login);
    emitTyping();
  });

  socket.on('chat message', (data) => {
    const freshUser = getUserByLogin(sessionData.userLogin);
    if (!freshUser) return;

    if (freshUser.mutedUntil && freshUser.mutedUntil > Date.now()) {
      socket.emit('chat error', 'У тебя мут');
      return;
    }

    if (!data || typeof data !== 'object') return;

    const msg = {
      id: makeId(),
      login: freshUser.login,
      avatar: freshUser.avatar || '',
      time: Date.now(),
      edited: false,
      likes: [],
      replyTo: null
    };

    if (data.replyTo) {
      const original = messages.find(m => m.id === data.replyTo);
      if (original) {
        msg.replyTo = {
          id: original.id,
          login: original.login,
          text:
            original.type === 'text'
              ? original.text
              : original.type === 'image'
                ? '[фото]'
                : '[видео]'
        };
      }
    }

    if (data.type === 'text') {
      const cleanText = String(data.text || '').trim().slice(0, 1000);
      if (!cleanText) return;
      msg.type = 'text';
      msg.text = cleanText;
    } else if (data.type === 'image' || data.type === 'video') {
      msg.type = data.type;
      msg.url = String(data.url || '');
      if (!msg.url.startsWith('/uploads/')) return;
    } else {
      return;
    }

    messages.push(msg);

    if (messages.length > 500) {
      messages = messages.slice(-500);
    }

    saveMessages();
    io.emit('chat message', msg);
  });

  socket.on('edit message', ({ id, text }) => {
    const msg = messages.find(m => m.id === id);
    if (!msg || msg.login !== user.login || msg.type !== 'text') return;

    const cleanText = String(text || '').trim().slice(0, 1000);
    if (!cleanText) return;

    msg.text = cleanText;
    msg.edited = true;
    saveMessages();
    io.emit('message updated', msg);
  });

  socket.on('toggle like', (id) => {
    const msg = messages.find(m => m.id === id);
    if (!msg) return;

    if (!Array.isArray(msg.likes)) msg.likes = [];

    const idx = msg.likes.indexOf(user.login);
    if (idx >= 0) msg.likes.splice(idx, 1);
    else msg.likes.push(user.login);

    saveMessages();
    io.emit('message updated', msg);
  });

  socket.on('delete message', (id) => {
    const currentUser = getUserByLogin(sessionData.userLogin);
    const index = messages.findIndex(m => m.id === id);

    if (index === -1) return;

    const msg = messages[index];
    if (msg.login !== user.login && currentUser.role !== 'creator') return;

    messages.splice(index, 1);

    if (pinnedMessageId === id) {
      pinnedMessageId = null;
      savePinned();
      io.emit('pinned update', null);
    }

    saveMessages();
    io.emit('message deleted', id);
  });

  socket.on('pin message', (id) => {
    const currentUser = getUserByLogin(sessionData.userLogin);
    if (!currentUser || currentUser.role !== 'creator') return;

    const msg = messages.find(m => m.id === id) || null;
    pinnedMessageId = msg ? msg.id : null;
    savePinned();
    io.emit('pinned update', msg);
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(user.login);
    typingUsers.delete(user.login);
    emitUsers();
    emitTyping();
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
