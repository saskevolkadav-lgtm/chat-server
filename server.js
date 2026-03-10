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
  secret: 'super_secret_chat_key_change_me_3',
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
const conversationsFile = path.join(__dirname, 'conversations.json');
const messagesFile = path.join(__dirname, 'messages.json');

function readJsonSafe(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

let users = readJsonSafe(usersFile, []);
let conversations = readJsonSafe(conversationsFile, []);
let messages = readJsonSafe(messagesFile, []);

function saveUsers() {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

function saveConversations() {
  fs.writeFileSync(conversationsFile, JSON.stringify(conversations, null, 2), 'utf8');
}

function saveMessages() {
  fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2), 'utf8');
}

function makeId() {
  return crypto.randomBytes(10).toString('hex');
}

function getUserByLogin(login) {
  return users.find(u => u.login.toLowerCase() === String(login).toLowerCase());
}

function publicUser(u) {
  return {
    login: u.login,
    role: u.role,
    avatar: u.avatar || '',
    bio: u.bio || ''
  };
}

function ensureGeneralConversation() {
  let general = conversations.find(c => c.isDefault === true);
  if (!general) {
    general = {
      id: 'general',
      type: 'group',
      name: 'Общий чат',
      members: users.map(u => u.login),
      createdBy: 'system',
      createdAt: Date.now(),
      isDefault: true
    };
    conversations.unshift(general);
    saveConversations();
  } else {
    const allLogins = users.map(u => u.login);
    let changed = false;
    for (const login of allLogins) {
      if (!general.members.includes(login)) {
        general.members.push(login);
        changed = true;
      }
    }
    if (changed) saveConversations();
  }
}

ensureGeneralConversation();

function addUserToGeneral(login) {
  const general = conversations.find(c => c.id === 'general');
  if (!general) return;
  if (!general.members.includes(login)) {
    general.members.push(login);
    saveConversations();
  }
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

function canAccessConversation(login, conversation) {
  if (!conversation) return false;
  return Array.isArray(conversation.members) && conversation.members.includes(login);
}

function getConversationForUser(conversation, myLogin) {
  if (!conversation) return null;

  let title = conversation.name || 'Чат';

  if (conversation.type === 'private') {
    const otherLogin = conversation.members.find(m => m !== myLogin) || myLogin;
    const otherUser = getUserByLogin(otherLogin);
    title = otherUser ? otherUser.login : otherLogin;
  }

  return {
    id: conversation.id,
    type: conversation.type,
    name: title,
    members: conversation.members || [],
    createdBy: conversation.createdBy,
    createdAt: conversation.createdAt,
    isDefault: !!conversation.isDefault
  };
}

function getConversationMessages(conversationId) {
  return messages
    .filter(m => m.conversationId === conversationId)
    .slice(-200);
}

function getPrivateConversation(loginA, loginB) {
  return conversations.find(c =>
    c.type === 'private' &&
    c.members.length === 2 &&
    c.members.includes(loginA) &&
    c.members.includes(loginB)
  );
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

  const user = {
    login,
    passwordHash,
    role,
    avatar: '',
    bio: ''
  };

  users.push(user);
  saveUsers();

  addUserToGeneral(login);

  req.session.userLogin = login;
  if (remember) {
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
  } else {
    req.session.cookie.expires = false;
  }

  io.emit('users changed');

  return res.json({
    ok: true,
    login: user.login,
    role: user.role
  });
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

  return res.json({
    ok: true,
    login: user.login,
    role: user.role
  });
});

app.post('/api/logout', (req, res) => {
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
    avatar: user.avatar || '',
    bio: user.bio || ''
  });
});

app.post('/api/profile', authRequired, (req, res) => {
  const user = getUserByLogin(req.session.userLogin);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

  user.bio = String(req.body.bio || '').trim().slice(0, 120);
  saveUsers();

  io.emit('users changed');

  return res.json({ ok: true, bio: user.bio });
});

app.post('/api/avatar', authRequired, upload.single('avatar'), (req, res) => {
  const user = getUserByLogin(req.session.userLogin);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  if (!req.file.mimetype.startsWith('image/')) {
    return res.status(400).json({ error: 'Аватар должен быть картинкой' });
  }

  user.avatar = '/uploads/' + req.file.filename;
  saveUsers();

  io.emit('users changed');

  return res.json({ ok: true, avatar: user.avatar });
});

app.get('/api/search-users', authRequired, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const myLogin = req.session.userLogin;

  if (!q) return res.json([]);

  const found = users
    .filter(u => u.login.toLowerCase().includes(q))
    .filter(u => u.login !== myLogin)
    .slice(0, 20)
    .map(publicUser);

  return res.json(found);
});

app.get('/api/conversations', authRequired, (req, res) => {
  const myLogin = req.session.userLogin;

  const list = conversations
    .filter(c => canAccessConversation(myLogin, c))
    .map(c => {
      const publicConv = getConversationForUser(c, myLogin);
      const lastMessage = [...messages].reverse().find(m => m.conversationId === c.id) || null;

      return {
        ...publicConv,
        lastMessage: lastMessage
          ? {
              login: lastMessage.login,
              text: lastMessage.type === 'text'
                ? lastMessage.text
                : lastMessage.type === 'image'
                  ? '[фото]'
                  : '[видео]',
              time: lastMessage.time
            }
          : null
      };
    })
    .sort((a, b) => {
      const at = a.lastMessage ? a.lastMessage.time : a.createdAt;
      const bt = b.lastMessage ? b.lastMessage.time : b.createdAt;
      return bt - at;
    });

  return res.json(list);
});

app.get('/api/conversations/:id/messages', authRequired, (req, res) => {
  const myLogin = req.session.userLogin;
  const conversation = conversations.find(c => c.id === req.params.id);

  if (!conversation || !canAccessConversation(myLogin, conversation)) {
    return res.status(404).json({ error: 'Чат не найден' });
  }

  return res.json(getConversationMessages(conversation.id));
});

app.post('/api/conversations/private/:login', authRequired, (req, res) => {
  const myLogin = req.session.userLogin;
  const targetLogin = String(req.params.login || '').trim();

  if (!targetLogin) {
    return res.status(400).json({ error: 'Логин не указан' });
  }

  if (targetLogin === myLogin) {
    return res.status(400).json({ error: 'Нельзя создать личку с собой' });
  }

  const target = getUserByLogin(targetLogin);
  if (!target) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  let conv = getPrivateConversation(myLogin, target.login);

  if (!conv) {
    conv = {
      id: makeId(),
      type: 'private',
      name: '',
      members: [myLogin, target.login],
      createdBy: myLogin,
      createdAt: Date.now()
    };
    conversations.push(conv);
    saveConversations();
  }

  return res.json({
    ok: true,
    conversation: getConversationForUser(conv, myLogin)
  });
});

app.post('/api/groups', authRequired, (req, res) => {
  const myLogin = req.session.userLogin;
  const name = String(req.body.name || '').trim().slice(0, 40);
  const members = Array.isArray(req.body.members) ? req.body.members : [];

  if (!name) {
    return res.status(400).json({ error: 'Название группы пустое' });
  }

  const cleanMembers = [...new Set(
    members
      .map(v => String(v || '').trim())
      .filter(Boolean)
      .filter(login => !!getUserByLogin(login))
      .filter(login => login !== myLogin)
  )];

  const conv = {
    id: makeId(),
    type: 'group',
    name,
    members: [myLogin, ...cleanMembers],
    createdBy: myLogin,
    createdAt: Date.now()
  };

  conversations.push(conv);
  saveConversations();

  return res.json({
    ok: true,
    conversation: getConversationForUser(conv, myLogin)
  });
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

const onlineUsers = new Set();
const userSockets = new Map();
const typingMap = new Map();

function emitPresence() {
  io.emit('presence update', Array.from(onlineUsers));
}

io.on('connection', socket => {
  const sessionData = socket.request.session;

  if (!sessionData || !sessionData.userLogin) {
    return socket.disconnect();
  }

  const myLogin = sessionData.userLogin;
  const user = getUserByLogin(myLogin);

  if (!user) {
    return socket.disconnect();
  }

  if (!userSockets.has(myLogin)) userSockets.set(myLogin, new Set());
  userSockets.get(myLogin).add(socket.id);
  onlineUsers.add(myLogin);
  emitPresence();

  socket.on('join conversation', ({ conversationId }) => {
    const conversation = conversations.find(c => c.id === conversationId);
    if (!conversation || !canAccessConversation(myLogin, conversation)) return;

    socket.join('conversation:' + conversationId);
  });

  socket.on('leave conversation', ({ conversationId }) => {
    socket.leave('conversation:' + conversationId);
  });

  socket.on('typing', ({ conversationId, isTyping }) => {
    const conversation = conversations.find(c => c.id === conversationId);
    if (!conversation || !canAccessConversation(myLogin, conversation)) return;

    const key = `${conversationId}:${myLogin}`;

    if (isTyping) {
      typingMap.set(key, { conversationId, login: myLogin });
    } else {
      typingMap.delete(key);
    }

    const currentTyping = Array.from(typingMap.values())
      .filter(v => v.conversationId === conversationId)
      .map(v => v.login);

    io.to('conversation:' + conversationId).emit('typing update', {
      conversationId,
      users: currentTyping
    });
  });

  socket.on('chat message', data => {
    const freshUser = getUserByLogin(myLogin);
    if (!freshUser) return;
    if (!data || typeof data !== 'object') return;

    const conversationId = String(data.conversationId || '');
    const conversation = conversations.find(c => c.id === conversationId);

    if (!conversation || !canAccessConversation(myLogin, conversation)) return;

    const msg = {
      id: makeId(),
      conversationId,
      login: freshUser.login,
      avatar: freshUser.avatar || '',
      time: Date.now(),
      type: 'text'
    };

    if (data.type === 'text') {
      const text = String(data.text || '').trim().slice(0, 1000);
      if (!text) return;
      msg.type = 'text';
      msg.text = text;
    } else if (data.type === 'image' || data.type === 'video') {
      const url = String(data.url || '');
      if (!url.startsWith('/uploads/')) return;
      msg.type = data.type;
      msg.url = url;
    } else {
      return;
    }

    messages.push(msg);

    if (messages.length > 5000) {
      messages = messages.slice(-5000);
    }

    saveMessages();

    io.to('conversation:' + conversationId).emit('chat message', msg);
    io.emit('conversation updated', { conversationId });
  });

  socket.on('disconnect', () => {
    const set = userSockets.get(myLogin);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        userSockets.delete(myLogin);
        onlineUsers.delete(myLogin);
      }
    }

    for (const [key, value] of typingMap.entries()) {
      if (value.login === myLogin) typingMap.delete(key);
    }

    emitPresence();
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
