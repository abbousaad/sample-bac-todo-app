const request = require('supertest');

describe('Todo Security Unit Tests', () => {
  let app;
  let user1Token;
  let user2Token;
  let user2TodoId;

  beforeAll(async () => {
    app = require('../server');

    const suffix = Date.now();

    const res1 = await request(app)
      .post('/api/auth/register')
      .send({ username: `secure-user1-${suffix}`, password: 'password1' });
    user1Token = res1.body.token;

    const res2 = await request(app)
      .post('/api/auth/register')
      .send({ username: `secure-user2-${suffix}`, password: 'password2' });
    user2Token = res2.body.token;

    const todo2 = await request(app)
      .post('/api/todos')
      .set('Authorization', `Bearer ${user2Token}`)
      .send({ title: 'User2 Private Todo' });

    user2TodoId = todo2.body.id;
  });

  test('should deny reading another users todo by id', async () => {
    const response = await request(app)
      .get(`/api/todos/${user2TodoId}`)
      .set('Authorization', `Bearer ${user1Token}`);

    expect(response.status).toBe(403);
  });

  test('should deny updating another users todo by id', async () => {
    const response = await request(app)
      .put(`/api/todos/${user2TodoId}`)
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ title: 'Hacked Title', completed: true });

    expect(response.status).toBe(403);
  });

  test('should deny deleting another users todo by id', async () => {
    const response = await request(app)
      .delete(`/api/todos/${user2TodoId}`)
      .set('Authorization', `Bearer ${user1Token}`);

    expect(response.status).toBe(403);
  });
});
