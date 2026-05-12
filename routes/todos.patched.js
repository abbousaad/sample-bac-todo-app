const express = require('express');
const passport = require('passport');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId TEXT NOT NULL,
    title TEXT NOT NULL,
    completed INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

const router = express.Router();

router.use(passport.authenticate('jwt', { session: false }));

router.get('/', (req, res) => {
  db.all('SELECT * FROM todos WHERE userId = ?', [req.user.id], (err, todos) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(todos);
  });
});

router.get('/:id', (req, res) => {
  db.get('SELECT * FROM todos WHERE id = ?', [req.params.id], (err, todo) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!todo) return res.status(404).json({ message: 'Todo not found' });
    if (todo.userId !== req.user.id) {
      return res.status(403).json({ message: 'Access denied' });
    }
    res.json(todo);
  });
});

router.post('/', (req, res) => {
  const { title } = req.body;
  if (!title) {
    return res.status(400).json({ message: 'Title required' });
  }
  
  db.run('INSERT INTO todos (userId, title, completed) VALUES (?, ?, ?)', 
    [req.user.id, title, 0],
    function(err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.status(201).json({ 
        id: this.lastID.toString(), 
        userId: req.user.id, 
        title, 
        completed: false 
      });
    }
  );
});

router.put('/:id', (req, res) => {
  const { title, completed } = req.body;
  
  db.get('SELECT * FROM todos WHERE id = ?', [req.params.id], (err, todo) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!todo) return res.status(404).json({ message: 'Todo not found' });
    
    if (todo.userId !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You can only modify your own todos' });
    }
    
    db.run('UPDATE todos SET title = ?, completed = ? WHERE id = ?', 
      [title, completed ? 1 : 0, req.params.id],
      function(err) {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json({ id: req.params.id, title, completed });
      }
    );
  });
});

router.delete('/:id', (req, res) => {
  db.get('SELECT * FROM todos WHERE id = ?', [req.params.id], (err, todo) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!todo) return res.status(404).json({ message: 'Todo not found' });
    
    if (todo.userId !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You can only delete your own todos' });
    }
    
    db.run('DELETE FROM todos WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Todo deleted' });
    });
  });
});

module.exports = router;
module.exports.db = db;