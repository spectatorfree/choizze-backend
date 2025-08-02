const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'choizze_db',
  password: '2378',
  port: 5432,
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};