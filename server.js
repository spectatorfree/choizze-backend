const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const auth = require('./middleware/auth');

const app = express();
const port = process.env.PORT || 3000;

const jwtSecret = process.env.JWT_SECRET;
const connectionString = process.env.DATABASE_URL;

const db = new Pool({
  connectionString,
});

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

    res.status(201).json({ message: 'Пользователь успешно зарегистрирован.', user: newUser.rows[0] });
  } catch (err) {
    if (err.code === '23505') { 
        return res.status(409).json({ error: 'Пользователь с таким email уже существует.' });
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
    
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Неверный email или пароль.' });
        }
    
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
    
        res.status(200).json({ message: 'Авторизация успешна.', token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/profile', auth, (req, res) => {
  res.json({ message: 'Доступ к защищенному маршруту.', user: req.user });
});

// Маршрут для получения данных пользователя из таблицы 'users'
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
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Новый маршрут для получения данных профиля из таблицы 'user_profiles'
app.get('/api/profile/:id', async (req, res) => {
    const userId = req.params.id;
    try {
        const result = await db.query('SELECT full_name, bio, profile_picture_url FROM user_profiles WHERE user_id = $1', [userId]);
        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ message: 'Профиль пользователя не найден' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});