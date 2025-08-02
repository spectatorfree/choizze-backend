const express = require('express');
const db = require('./config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const auth = require('./middleware/auth');

const app = express();
const port = 3000;

const jwtSecret = process.env.JWT_SECRET; 

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Привет, мир! Это наш первый сервер для CHOIZZE!');
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Пожалуйста, заполните все поля.' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = await db.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );

    await db.query(
      'INSERT INTO user_stats (user_id) VALUES ($1)',
      [newUser.rows[0].id]
    );

    res.status(201).json({ 
      message: 'Пользователь успешно зарегистрирован',
      user: newUser.rows[0] 
    });

  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Пользователь с таким именем или email уже существует.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Пожалуйста, заполните все поля.' });
    }

    const userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      jwtSecret,
      { expiresIn: '1h' }
    );

    res.status(200).json({ 
      message: 'Авторизация прошла успешно',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const { rows } = await db.query(
      'SELECT u.id, u.username, u.email, p.avatar_url, p.birth_date, p.gender, p.city FROM users AS u LEFT JOIN user_profiles AS p ON u.id = p.user_id WHERE u.id = $1', 
      [id]
    );

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Пользователь не найден' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/user/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.id !== parseInt(id)) {
      return res.status(403).json({ error: 'Доступ запрещен.' });
    }

    const { username, email } = req.body;
    
    if (!username || !email) {
      return res.status(400).json({ error: 'Имя пользователя и Email обязательны.' });
    }

    const updatedUser = await db.query(
      'UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING id, username, email',
      [username, email, id]
    );

    if (updatedUser.rows.length > 0) {
      res.json({ 
        message: 'Данные пользователя успешно обновлены',
        user: updatedUser.rows[0] 
      });
    } else {
      res.status(404).json({ message: 'Пользователь не найден' });
    }
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Пользователь с таким именем или email уже существует.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/user/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.id !== parseInt(id)) {
      return res.status(403).json({ error: 'Доступ запрещен.' });
    }
    
    const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length > 0) {
      res.json({ message: 'Пользователь успешно удален' });
    } else {
      res.status(404).json({ message: 'Пользователь не найден' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/friends/request', auth, async (req, res) => {
  try {
    const senderId = req.user.id;
    const { receiverId } = req.body;

    if (senderId === receiverId) {
      return res.status(400).json({ error: 'Вы не можете отправить запрос самому себе.' });
    }

    const existingRequest = await db.query(
      'SELECT * FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
      [senderId, receiverId]
    );

    if (existingRequest.rows.length > 0) {
      return res.status(409).json({ error: 'Запрос на дружбу уже существует.' });
    }

    await db.query(
      'INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, $3)',
      [senderId, receiverId, 'pending']
    );

    res.status(201).json({ message: 'Запрос на дружбу отправлен.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/friends/accept', auth, async (req, res) => {
  try {
    const receiverId = req.user.id;
    const { senderId } = req.body;

    const result = await db.query(
      'UPDATE friends SET status = $1 WHERE user_id = $2 AND friend_id = $3 AND status = $4 RETURNING *',
      ['accepted', senderId, receiverId, 'pending']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Запрос на дружбу не найден.' });
    }
    
    await db.query(
      'INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, $3)',
      [receiverId, senderId, 'accepted']
    );

    res.json({ message: 'Запрос на дружбу принят.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/friends', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await db.query(
      'SELECT u.id, u.username, u.email FROM friends AS f JOIN users AS u ON f.friend_id = u.id WHERE f.user_id = $1 AND f.status = $2',
      [userId, 'accepted']
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/messages', auth, async (req, res) => {
  try {
    const senderId = req.user.id;
    const { receiverId, messageText } = req.body;

    if (!messageText) {
      return res.status(400).json({ error: 'Сообщение не может быть пустым.' });
    }

    const areFriends = await db.query(
      'SELECT * FROM friends WHERE user_id = $1 AND friend_id = $2 AND status = $3',
      [senderId, receiverId, 'accepted']
    );

    if (areFriends.rows.length === 0) {
      return res.status(403).json({ error: 'Вы не можете отправлять сообщения этому пользователю.' });
    }

    await db.query(
      'INSERT INTO messages (sender_id, receiver_id, message_text) VALUES ($1, $2, $3)',
      [senderId, receiverId, messageText]
    );

    res.status(201).json({ message: 'Сообщение отправлено.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/messages/:friendId', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { friendId } = req.params;

    const areFriends = await db.query(
      'SELECT * FROM friends WHERE user_id = $1 AND friend_id = $2 AND status = $3',
      [userId, friendId, 'accepted']
    );

    if (areFriends.rows.length === 0) {
      return res.status(403).json({ error: 'Вы не можете просматривать переписку с этим пользователем.' });
    }

    const { rows } = await db.query(
      'SELECT * FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1) ORDER BY created_at ASC',
      [userId, friendId]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/stats', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const { rows } = await db.query('SELECT lives, ban_tokens, trial_time_spent FROM user_stats WHERE user_id = $1', [userId]);

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Статистика пользователя не найдена' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/profiles', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { avatarUrl, birthDate, gender, city } = req.body;

    const profile = await db.query('SELECT * FROM user_profiles WHERE user_id = $1', [userId]);

    if (profile.rows.length > 0) {
      const updatedProfile = await db.query(
        'UPDATE user_profiles SET avatar_url = $1, birth_date = $2, gender = $3, city = $4 WHERE user_id = $5 RETURNING *',
        [avatarUrl, birthDate, gender, city, userId]
      );
      res.json({ message: 'Профиль успешно обновлен.', profile: updatedProfile.rows[0] });
    } else {
      const newProfile = await db.query(
        'INSERT INTO user_profiles (user_id, avatar_url, birth_date, gender, city) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [userId, avatarUrl, birthDate, gender, city]
      );
      res.status(201).json({ message: 'Профиль успешно создан.', profile: newProfile.rows[0] });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/news', auth, async (req, res) => {
  try {
    const authorId = req.user.id;
    const { contentType, contentUrl, contentText } = req.body;

    const newPost = await db.query(
      'INSERT INTO news_feed (author_id, content_type, content_url, content_text) VALUES ($1, $2, $3, $4) RETURNING *',
      [authorId, contentType, contentUrl, contentText]
    );

    res.status(201).json({ message: 'Пост успешно добавлен в ленту.', post: newPost.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/news', auth, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT n.id, n.author_id, u.username, n.content_type, n.content_url, n.content_text, n.created_at FROM news_feed AS n JOIN users AS u ON n.author_id = u.id ORDER BY n.created_at DESC LIMIT 50'
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/reports', auth, async (req, res) => {
  try {
    const reporterId = req.user.id;
    const { reportedId, reportReason } = req.body;

    if (reporterId === reportedId) {
      return res.status(400).json({ error: 'Вы не можете пожаловаться на самого себя.' });
    }
    
    const userStats = await db.query('SELECT ban_tokens FROM user_stats WHERE user_id = $1', [reporterId]);
    if (userStats.rows.length === 0 || userStats.rows[0].ban_tokens <= 0) {
      return res.status(403).json({ error: 'Недостаточно "фишек для бана" для отправки жалобы.' });
    }

    await db.query(
      'INSERT INTO reports (reporter_id, reported_id, report_reason) VALUES ($1, $2, $3)',
      [reporterId, reportedId, reportReason]
    );

    await db.query('UPDATE user_stats SET ban_tokens = ban_tokens - 1 WHERE user_id = $1', [reporterId]);

    res.status(201).json({ message: 'Жалоба успешно отправлена.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/match', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const { rows } = await db.query(
      'SELECT u.id, u.username, u.email, p.avatar_url, p.birth_date, p.gender, p.city FROM users AS u ' +
      'LEFT JOIN user_profiles AS p ON u.id = p.user_id ' +
      'WHERE u.id != $1 AND u.id NOT IN (SELECT friend_id FROM friends WHERE user_id = $1 AND status = $2) ' +
      'ORDER BY RANDOM() LIMIT 1',
      [userId, 'accepted']
    );

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Собеседник не найден. Попробуйте позже.' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/subscribe', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const newTransaction = await db.query(
      'INSERT INTO transactions (user_id, type, amount, status) VALUES ($1, $2, $3, $4) RETURNING id',
      [userId, 'subscription_purchase', 9.99, 'completed']
    );

    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 30);
    
    const newSubscription = await db.query(
      'INSERT INTO subscriptions (user_id, transaction_id, end_date) VALUES ($1, $2, $3) RETURNING *',
      [userId, newTransaction.rows[0].id, endDate]
    );

    res.status(201).json({ message: 'Подписка успешно оформлена.', subscription: newSubscription.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/subscriptions', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await db.query(
      'SELECT * FROM subscriptions WHERE user_id = $1 AND status = $2 AND end_date > CURRENT_TIMESTAMP ORDER BY end_date DESC LIMIT 1',
      [userId, 'active']
    );

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: 'Активная подписка не найдена.' });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.listen(port, () => {
  console.log(`Сервер запущен по адресу http://localhost:${port}`);
});