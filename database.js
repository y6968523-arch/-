const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, 'platform.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    phone TEXT,
    stage TEXT DEFAULT 'secondary',
    grade TEXT DEFAULT '3',
    role TEXT DEFAULT 'student',
    is_active INTEGER DEFAULT 1,
    enrolled_course_ids TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    type TEXT DEFAULT 'course',
    stage TEXT DEFAULT 'secondary',
    grade TEXT DEFAULT '3',
    is_free INTEGER DEFAULT 1,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER,
    unit_title TEXT,
    title TEXT,
    video_url TEXT,
    pdf_url TEXT,
    is_preview INTEGER DEFAULT 0,
    order_index INTEGER DEFAULT 1,
    description TEXT,
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    exam_type TEXT DEFAULT 'lesson',
    stage TEXT DEFAULT 'secondary',
    grade TEXT DEFAULT '3',
    duration_minutes INTEGER DEFAULT 30,
    passing_score INTEGER DEFAULT 50,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id INTEGER,
    question_text TEXT,
    option_a TEXT,
    option_b TEXT,
    option_c TEXT,
    option_d TEXT,
    correct_option TEXT,
    explanation TEXT,
    marks INTEGER DEFAULT 1,
    FOREIGN KEY(exam_id) REFERENCES exams(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS student_exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    exam_id INTEGER,
    score INTEGER,
    total_marks INTEGER,
    status TEXT,
    answers_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // Seed default admin if not exists
  const adminEmail = 'admin@sayedchemistry.com';
  db.get('SELECT id FROM users WHERE email = ?', [adminEmail], async (err, row) => {
    if (!row) {
      const hashed = await bcrypt.hash('SayedAdmin@2026', 10);
      db.run('INSERT INTO users (name, email, password, role, stage, grade, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)',
        ['أ. سيد حسن (الإدارة)', adminEmail, hashed, 'admin', 'secondary', '3', 1]);
    }
  });
});

module.exports = db;
