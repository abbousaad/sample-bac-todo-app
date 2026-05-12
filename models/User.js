const bcrypt = require('bcryptjs');

const users = [];

const User = {
  findByUsername: (username) => users.find(u => u.username === username),
  findById: (id) => users.find(u => u.id === id),
  create: async (user) => {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser = {
      id: Date.now().toString(),
      username: user.username,
      password: hashedPassword
    };
    users.push(newUser);
    return newUser;
  }
};

module.exports = User;