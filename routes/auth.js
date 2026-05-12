const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  if (User.findByUsername(username)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const user = await User.create({ username, password });
  const token = jwt.sign({ id: user.id, username: user.username }, 'your-secret-key', { expiresIn: '1h' });

  res.json({ token, user: { id: user.id, username: user.username } });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = User.findByUsername(username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, 'your-secret-key', { expiresIn: '1h' });

  res.json({ token, user: { id: user.id, username: user.username } });
});

module.exports = router;