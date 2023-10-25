const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const FLAG_VALUE = process.env.FLAG_VALUE;
const HARDCODED_HASHED_PASSWORD = process.env.ADMIN_HASH;

const HARDCODED_USERNAME = "admin";

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === HARDCODED_USERNAME && bcrypt.compareSync(password, HARDCODED_HASHED_PASSWORD)) {
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('auth_token', token);
      res.send({ success: true, message: "Logged in successfully." });
  } else {
      res.status(401).send({ success: false, message: "Invalid credentials." });
  }
});


app.get('/flag', (req, res) => {
    const token = req.cookies.auth_token;
    if (!token) {
        return res.status(403).send({ success: false, message: "No token provided." });
    }

    try {
        jwt.verify(token, JWT_SECRET);
        res.send({ success: true, flag: FLAG_VALUE });
    } catch (err) {
        res.status(403).send({ success: false, message: "Invalid token." });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
