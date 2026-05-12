const todos = [];

const Todo = {
  findByUserId: (userId) => todos.filter(t => t.userId === userId),
  findById: (id) => todos.find(t => t.id === id),
  create: (todo) => {
    const newTodo = {
      id: Date.now().toString(),
      userId: todo.userId,
      title: todo.title,
      completed: false,
      createdAt: new Date()
    };
    todos.push(newTodo);
    return newTodo;
  },
  update: (id, updates) => {
    const todo = todos.find(t => t.id === id);
    if (todo) {
      Object.assign(todo, updates);
    }
    return todo;
  },
  delete: (id) => {
    const index = todos.findIndex(t => t.id === id);
    if (index > -1) {
      todos.splice(index, 1);
      return true;
    }
    return false;
  }
};

module.exports = Todo;