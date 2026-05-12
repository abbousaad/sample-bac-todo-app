const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const path = require('path');

const app = express();

app.use(bodyParser.json());
app.use(passport.initialize());

const USE_VULNERABLE = process.env.VULNERABLE !== 'false';

let todoRoutes;
if (USE_VULNERABLE) {
  console.log('⚠️ Running VULNERABLE version (IDOR/BAC enabled)');
  todoRoutes = require('./routes/todos.vulnerable');
} else {
  console.log('🔒 Running PATCHED version (Secure)');
  todoRoutes = require('./routes/todos.patched');
}

require('./config/passport')(passport);

const authRoutes = require('./routes/auth');

app.use('/api/auth', authRoutes);
app.use('/api/todos', todoRoutes);

app.get('/', (req, res) => {
  res.json({ 
    message: 'Todo API running',
    vulnerable: USE_VULNERABLE
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;