const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const jwtSecret = process.env.JWT_SECRET;
const connectionString = process.env.DATABASE_URL;

const db = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());

// Middleware для проверки токена
function auth(req, res, next) {
  try {
    const token = req.headers.authorization.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Авторизация не пройдена, отсутствует токен.' });
    }
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Авторизация не пройдена, неверный токен.' });
  }
}

app.get('/', (req, res) => {
  res.send('Привет, мир! Это наш сервер для CHOIZZE!');
});

// Маршрут для регистрации
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

    res.status(201).json({
      message: 'Пользователь успешно зарегистрирован',
      user: newUser.rows[0]
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Пользователь с таким email или именем уже существует.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Маршрут для авторизации
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await db.query('SELECT * FROM users WHERE username = $1', [username]);

    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный логин или пароль.' });
    }

    const isMatch = await bcrypt.compare(password, user.rows[0].password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: 'Неверный логин или пароль.' });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, username: user.rows[0].username },
      jwtSecret,
      { expiresIn: '1h' }
    );

    res.status(200).json({ token, user: { id: user.rows[0].id, username: user.rows[0].username, email: user.rows[0].email } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Маршрут для получения данных пользователя по ID
app.get('/api/user/:id', async (req, res) => {
    const userId = req.params.id;
    try {
        const result = await db.query('SELECT id, username, email FROM users WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ message: 'Пользователь не найден' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Маршрут для получения профиля
app.get('/api/profile', auth, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await db.query(
            'SELECT full_name, bio, profile_picture_url FROM user_profiles WHERE user_id = $1',
            [userId]
        );
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ message: 'Профиль не найден.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршрут для обновления профиля
app.put('/api/profile/:id', auth, async (req, res) => {
    const userId = req.user.id;
    const { fullName, bio, profilePictureUrl } = req.body;

    try {
        await db.query(
            `INSERT INTO user_profiles (user_id, full_name, bio, profile_picture_url)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id) DO UPDATE SET
             full_name = EXCLUDED.full_name,
             bio = EXCLUDED.bio,
             profile_picture_url = EXCLUDED.profile_picture_url`,
            [userId, fullName, bio, profilePictureUrl]
        );
        res.status(200).json({ message: 'Профиль успешно обновлен' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршрут для отправки запроса в друзья
app.post('/friends/request', auth, async (req, res) => {
    const { senderId, receiverId } = req.body;
    const userId = req.user.id;

    if (userId !== senderId) {
      return res.status(403).json({ error: 'Вы не можете отправить запрос от имени другого пользователя.' });
    }

    if (senderId === receiverId) {
      return res.status(400).json({ error: 'Нельзя отправлять запрос в друзья самому себе.' });
    }

    try {
        const friendRequest = await db.query(
          `INSERT INTO friends (sender_id, receiver_id, status)
           VALUES ($1, $2, 'pending')
           RETURNING *`,
          [senderId, receiverId]
        );
        res.status(201).json({ message: 'Запрос в друзья успешно отправлен', request: friendRequest.rows[0] });
      } catch (err) {
        if (err.code === '23505') {
          return res.status(409).json({ error: 'Запрос в друзья уже существует.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
      }
});

// Маршрут для принятия запроса в друзья
app.post('/friends/accept', auth, async (req, res) => {
    const { friendRequestId } = req.body;
    const userId = req.user.id;

    try {
        const result = await db.query(
            `UPDATE friends
             SET status = 'accepted'
             WHERE id = $1 AND receiver_id = $2
             RETURNING *`,
            [friendRequestId, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Запрос в друзья не найден или вы не являетесь получателем запроса.' });
        }

        res.status(200).json({ message: 'Запрос в друзья успешно принят' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршрут для получения списка друзей
app.get('/friends', auth, async (req, res) => {
    const userId = req.user.id;

    try {
        const friends = await db.query(
            `SELECT
                 CASE
                    WHEN sender_id = $1 THEN receiver_id
                    ELSE sender_id
                 END as friend_id
             FROM friends
             WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'`,
            [userId]
        );

        res.status(200).json({ friends: friends.rows.map(row => row.friend_id) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});


app.listen(port, () => {
  console.log(`Сервер запущен по адресу http://localhost:${port}`);
});