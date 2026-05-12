const express = require('express');
const passport = require('passport');
const Todo = require('../models/Todo');

const router = express.Router();

router.use(passport.authenticate('jwt', { session: false }));

router.get('/', (req, res) => {
  const todos = Todo.findByUserId(req.user.id);
  res.json(todos);
});

router.post('/', (req, res) => {
  const { title } = req.body;
  if (!title) {
    return res.status(400).json({ message: 'Title required' });
  }
  const todo = Todo.create({ userId: req.user.id, title });
  res.status(201).json(todo);
});

router.put('/:id', (req, res) => {
  const todo = Todo.findById(req.params.id);
  if (!todo || todo.userId !== req.user.id) {
    return res.status(404).json({ message: 'Todo not found' });
  }
  const updated = Todo.update(req.params.id, req.body);
  res.json(updated);
});

router.delete('/:id', (req, res) => {
  const todo = Todo.findById(req.params.id);
  if (!todo || todo.userId !== req.user.id) {
    return res.status(404).json({ message: 'Todo not found' });
  }
  Todo.delete(req.params.id);
  res.json({ message: 'Todo deleted' });
});

module.exports = router;