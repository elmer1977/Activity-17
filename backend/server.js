const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

const SECRET = "secretkey";

// ================= FILE UPLOAD =================
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ================= DB =================
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'color_api'
});

// ================= EMAIL =================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your_email@gmail.com',
    pass: 'your_app_password'
  }
});

// ================= AUTH MIDDLEWARE =================
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

// ================= REGISTER =================
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const token = uuidv4();

  db.query(
    "INSERT INTO users (email, password, verification_token) VALUES (?, ?, ?)",
    [email, hashedPassword, token],
    (err) => {
      if (err) return res.status(500).json(err);

      const link = `http://localhost:5000/api/verify/${token}`;

      transporter.sendMail({
        to: email,
        subject: "Verify your account",
        html: `<a href="${link}">Click to verify</a>`
      });

      res.json({ message: "Registered. Check email to verify." });
    }
  );
});

// ================= VERIFY EMAIL =================
app.get('/api/verify/:token', (req, res) => {
  const { token } = req.params;

  db.query(
    "UPDATE users SET is_verified=1 WHERE verification_token=?",
    [token],
    (err) => {
      if (err) return res.status(500).json(err);
      res.send("Account verified! You can now login.");
    }
  );
});

// ================= LOGIN =================
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, results) => {
    if (results.length === 0) return res.status(400).json({ message: "User not found" });

    const user = results[0];

    if (!user.is_verified)
      return res.status(403).json({ message: "Verify your email first" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token });
  });
});

// ================= FORGOT PASSWORD =================
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  const token = uuidv4();
  const expires = Date.now() + 3600000;

  db.query(
    "UPDATE users SET reset_token=?, reset_expires=? WHERE email=?",
    [token, expires, email],
    () => {
      const link = `http://localhost:3000/reset-password/${token}`;

      transporter.sendMail({
        to: email,
        subject: "Reset Password",
        html: `<a href="${link}">Reset Password</a>`
      });

      res.json({ message: "Reset link sent" });
    }
  );
});

// ================= RESET PASSWORD =================
app.post('/api/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  const hashed = await bcrypt.hash(password, 10);

  db.query(
    "UPDATE users SET password=? WHERE reset_token=? AND reset_expires > ?",
    [hashed, token, Date.now()],
    () => {
      res.json({ message: "Password reset successful" });
    }
  );
});

// ================= PROFILE =================
app.put('/api/profile', auth, upload.single('image'), (req, res) => {
  const { email } = req.body;
  const image = req.file ? req.file.filename : null;

  db.query(
    "UPDATE users SET email=?, profile_image=? WHERE id=?",
    [email, image, req.user.id],
    () => {
      res.json({ message: "Profile updated" });
    }
  );
});

// ================= COLORS CRUD WITH IMAGE =================

// CREATE
app.post('/api/colors', auth, upload.single('image'), (req, res) => {
  const { color_name, hex_code } = req.body;
  const image = req.file ? req.file.filename : null;

  db.query(
    "INSERT INTO colors (color_name, hex_code, image) VALUES (?, ?, ?)",
    [color_name, hex_code, image],
    () => res.json({ message: "Color added" })
  );
});

// GET
app.get('/api/colors', (req, res) => {
  db.query("SELECT * FROM colors", (err, results) => {
    res.json(results);
  });
});

// UPDATE
app.put('/api/colors/:id', auth, upload.single('image'), (req, res) => {
  const { color_name, hex_code } = req.body;
  const image = req.file ? req.file.filename : null;

  db.query(
    "UPDATE colors SET color_name=?, hex_code=?, image=? WHERE id=?",
    [color_name, hex_code, image, req.params.id],
    () => res.json({ message: "Updated" })
  );
});

// DELETE
app.delete('/api/colors/:id', auth, (req, res) => {
  db.query("DELETE FROM colors WHERE id=?", [req.params.id], () => {
    res.json({ message: "Deleted" });
  });
});

app.listen(5000, () => console.log("Server running on 5000"));