const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sayed_hassan_chemistry_secure_secret_key_2026_🧪';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', limiter);

// Middleware
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'غيرحاصل على اذن بالدخول، يرجى تسجيل الدخول' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'جلسة غير صالحة' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'صلاحيات إدارية مطلوبة' });
    next();
  });
}

// Routes - Views
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/student', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Auth APIs
app.post('/api/register', async (req, res) => {
  const { name, email, password, phone, stage, grade } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'جميع الحقول الأساسية مطلوبة' });
  if (password.length < 8) return res.status(400).json({ message: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name, email, password, phone, stage, grade, role, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, email, hashed, phone || '', stage || 'secondary', grade || '3', 'student', 1],
      function(err) {
        if (err) return res.status(400).json({ message: 'البريد الإلكتروني مستخدم من قبل أو بيانات غير صالحة' });
        const user = { id: this.lastID, name, email, role: 'student', stage: stage || 'secondary', grade: grade || '3' };
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ message: 'تم إنشاء الحساب بنجاح', user });
      }
    );
  } catch (e) {
    res.status(500).json({ message: 'حدث خطأ في الخادم' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    if (!user.is_active) return res.status(403).json({ message: 'هذا الحساب موقوف حالياً من الإدارة' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

    const payload = { id: user.id, name: user.name, email: user.email, role: user.role, stage: user.stage, grade: user.grade };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: 'تم تسجيل الدخول بنجاح', user: payload });
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'تم تسجيل الخروج بنجاح' });
});

app.get('/api/me', authenticateToken, (req, res) => {
  db.get('SELECT id, name, email, phone, stage, grade, role, is_active, enrolled_course_ids FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ message: 'المستخدم غير موجود' });
    res.json({ user });
  });
});

app.get('/api/social', (req, res) => {
  db.get('SELECT value FROM settings WHERE key = ?', ['social_links'], (err, row) => {
    const links = row ? JSON.parse(row.value) : {};
    res.json({ links });
  });
});

// Student APIs
app.get('/api/student/courses', authenticateToken, (req, res) => {
  const grade = req.user.grade;
  db.all('SELECT * FROM courses WHERE grade = ? ORDER BY id DESC', [grade], (err, courses) => {
    if (err) return res.status(500).json({ message: 'خطأ في جلب الكورسات' });
    res.json({ courses });
  });
});

app.get('/api/student/courses/:id/lessons', authenticateToken, (req, res) => {
  const courseId = req.params.id;
  db.get('SELECT * FROM courses WHERE id = ?', [courseId], (err, course) => {
    if (err || !course) return res.status(404).json({ message: 'الكورس غير موجود' });
    db.all('SELECT id, course_id, unit_title, title, pdf_url, order_index FROM lessons WHERE course_id = ? ORDER BY order_index ASC', [courseId], (err, lessons) => {
      res.json({ course, lessons });
    });
  });
});

app.get('/api/student/lessons/:id/watch', authenticateToken, (req, res) => {
  const lessonId = req.params.id;
  db.get('SELECT * FROM lessons WHERE id = ?', [lessonId], (err, lesson) => {
    if (err || !lesson) return res.status(404).json({ message: 'الدرس غير موجود' });
    res.json({ lesson });
  });
});

app.get('/api/student/exams', authenticateToken, (req, res) => {
  const grade = req.user.grade;
  const userId = req.user.id;
  db.all(`
    SELECT e.*, 
      (SELECT MAX(score) FROM student_exams WHERE user_id = ? AND exam_id = e.id) as best_score
    FROM exams e WHERE e.grade = ? ORDER BY e.id DESC
  `, [userId, grade], (err, exams) => {
    if (err) return res.status(500).json({ message: 'خطأ في جلب الامتحانات' });
    res.json({ exams });
  });
});

app.get('/api/student/exams/:id/start', authenticateToken, (req, res) => {
  const examId = req.params.id;
  db.get('SELECT * FROM exams WHERE id = ?', [examId], (err, exam) => {
    if (err || !exam) return res.status(404).json({ message: 'الامتحان غير موجود' });
    db.all('SELECT id, question_text, option_a, option_b, option_c, option_d, marks FROM questions WHERE exam_id = ?', [examId], (err, questions) => {
      res.json({ exam, questions });
    });
  });
});

app.post('/api/student/exams/:id/submit', authenticateToken, (req, res) => {
  const examId = req.params.id;
  const userId = req.user.id;
  const { answers } = req.body; // { qId: 'a', ... }

  db.get('SELECT * FROM exams WHERE id = ?', [examId], (err, exam) => {
    if (err || !exam) return res.status(404).json({ message: 'الامتحان غير موجود' });
    db.all('SELECT * FROM questions WHERE exam_id = ?', [examId], (err, questions) => {
      let score = 0;
      let totalMarks = 0;
      const review = [];

      questions.forEach(q => {
        totalMarks += q.marks || 1;
        const chosen = answers[q.id];
        const isCorrect = chosen === q.correct_option;
        if (isCorrect) score += q.marks || 1;
        review.push({
          question_text: q.question_text,
          chosen,
          correct_option: q.correct_option,
          is_correct: isCorrect,
          explanation: q.explanation
        });
      });

      const status = (score / totalMarks) * 100 >= exam.passing_score ? 'passed' : 'failed';
      db.run('INSERT INTO student_exams (user_id, exam_id, score, total_marks, status, answers_json) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, examId, score, totalMarks, status, JSON.stringify(answers)]);

      res.json({ score, totalMarks, status, review });
    });
  });
});

// Admin APIs
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  db.get('SELECT COUNT(*) as count FROM users WHERE role = ?', ['student'], (err, r1) => {
    db.get('SELECT COUNT(*) as count FROM courses', (err, r2) => {
      db.get('SELECT COUNT(*) as count FROM lessons', (err, r3) => {
        db.get('SELECT COUNT(*) as count FROM exams', (err, r4) => {
          res.json({
            stats: {
              students: r1.count,
              courses: r2.count,
              lessons: r3.count,
              exams: r4.count
            }
          });
        });
      });
    });
  });
});

app.get('/api/admin/students', requireAdmin, (req, res) => {
  db.all('SELECT id, name, email, phone, stage, grade, is_active, enrolled_course_ids FROM users WHERE role = ? ORDER BY id DESC', ['student'], (err, students) => {
    res.json({ students });
  });
});

app.patch('/api/admin/students/:id', requireAdmin, (req, res) => {
  const { grade, is_active } = req.body;
  if (grade !== undefined) {
    db.run('UPDATE users SET grade = ? WHERE id = ?', [grade, req.params.id]);
  }
  if (is_active !== undefined) {
    db.run('UPDATE users SET is_active = ? WHERE id = ?', [is_active, req.params.id]);
  }
  res.json({ message: 'تم تحديث بيانات الطالب بنجاح' });
});

app.get('/api/admin/courses', requireAdmin, (req, res) => {
  db.all('SELECT * FROM courses ORDER BY id DESC', (err, courses) => {
    res.json({ courses });
  });
});

app.post('/api/admin/courses', requireAdmin, (req, res) => {
  const { title, type, stage, grade, description } = req.body;
  db.run('INSERT INTO courses (title, type, stage, grade, description) VALUES (?, ?, ?, ?, ?)',
    [title, type || 'course', stage || 'secondary', grade || '3', description || ''],
    function(err) {
      if (err) return res.status(500).json({ message: 'خطأ في إنشاء الكورس' });
      res.json({ message: 'تم إنشاء الكورس بنجاح', id: this.lastID });
    }
  );
});

app.delete('/api/admin/courses/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM courses WHERE id = ?', [id], () => {
    db.run('DELETE FROM lessons WHERE course_id = ?', [id]);
    res.json({ message: 'تم حذف الكورس ودروسه' });
  });
});

app.get('/api/admin/lessons', requireAdmin, (req, res) => {
  db.all(`
    SELECT l.*, c.title as course_title FROM lessons l 
    JOIN courses c ON l.course_id = c.id ORDER BY l.id DESC
  `, (err, lessons) => {
    res.json({ lessons });
  });
});

app.post('/api/admin/lessons', requireAdmin, (req, res) => {
  const { course_id, unit_title, title, video_url, pdf_url, order_index, description } = req.body;
  db.run('INSERT INTO lessons (course_id, unit_title, title, video_url, pdf_url, order_index, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [course_id, unit_title, title, video_url, pdf_url || '', order_index || 1, description || ''],
    function(err) {
      if (err) return res.status(500).json({ message: 'خطأ في إضافة الدرس' });
      res.json({ message: 'تم إضافة الدرس بنجاح', id: this.lastID });
    }
  );
});

app.delete('/api/admin/lessons/:id', requireAdmin, (req, res) => {
  db.run('DELETE FROM lessons WHERE id = ?', [req.params.id], () => {
    res.json({ message: 'تم حذف الدرس' });
  });
});

app.get('/api/admin/exams', requireAdmin, (req, res) => {
  db.all(`
    SELECT e.*, (SELECT COUNT(*) FROM questions WHERE exam_id = e.id) as questions_count 
    FROM exams e ORDER BY e.id DESC
  `, (err, exams) => {
    res.json({ exams });
  });
});

app.post('/api/admin/exams', requireAdmin, (req, res) => {
  const { title, exam_type, stage, grade, duration_minutes, passing_score } = req.body;
  db.run('INSERT INTO exams (title, exam_type, stage, grade, duration_minutes, passing_score) VALUES (?, ?, ?, ?, ?, ?)',
    [title, exam_type || 'lesson', stage || 'secondary', grade || '3', duration_minutes || 30, passing_score || 50],
    function(err) {
      if (err) return res.status(500).json({ message: 'خطأ في إنشاء الامتحان' });
      res.json({ message: 'تم إنشاء الامتحان بنجاح', id: this.lastID });
    }
  );
});

app.post('/api/admin/exams/:id/questions', requireAdmin, (req, res) => {
  const examId = req.params.id;
  const { question_text, option_a, option_b, option_c, option_d, correct_option, explanation, marks } = req.body;
  db.run('INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_option, explanation, marks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [examId, question_text, option_a, option_b, option_c, option_d, correct_option, explanation || '', marks || 1],
    function(err) {
      if (err) return res.status(500).json({ message: 'خطأ في إضافة السؤال' });
      res.json({ message: 'تمت إضافة السؤال بنجاح' });
    }
  );
});

app.delete('/api/admin/exams/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM exams WHERE id = ?', [id], () => {
    db.run('DELETE FROM questions WHERE exam_id = ?', [id]);
    res.json({ message: 'تم حذف الامتحان' });
  });
});

app.put('/api/admin/social', requireAdmin, (req, res) => {
  const { links } = req.body;
  db.run('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['social_links', JSON.stringify(links)], (err) => {
    if (err) return res.status(500).json({ message: 'خطأ في حفظ الروابط' });
    res.json({ message: 'تم حفظ روابط التواصل بنجاح' });
  });
});


app.get('/api/admin/results', requireAdmin, (req, res) => {
  db.all(`
    SELECT se.*, u.name as student_name, u.email as student_email, e.title as exam_title
    FROM student_exams se
    JOIN users u ON se.user_id = u.id
    JOIN exams e ON se.exam_id = e.id
    ORDER BY se.id DESC
  `, (err, results) => {
    if (err) return res.status(500).json({ message: 'خطأ في جلب درجات الطلاب' });
    res.json({ results });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
