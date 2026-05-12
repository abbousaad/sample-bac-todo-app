const request = require('supertest');
const jwt = require('jsonwebtoken');

const ASVS_CONTROL_IDOR_4_4_1 = 'V4.4.1';
const ASVS_CONTROL_IDOR_4_4_2 = 'V4.4.2';
const ASVS_CONTROL_BAC_4_1 = 'V4.1';
const ASVS_CONTROL_BAC_4_2 = 'V4.2';

describe('OWASP ASVS IDOR & BAC Security Tests', () => {
  let app;
  let user1Token, user2Token, user1Id, user2Id;
  let user1TodoId, user2TodoId;

  beforeAll(async () => {
    app = require('../server');
    
    const res1 = await request(app)
      .post('/api/auth/register')
      .send({ username: 'user1', password: 'password1' });
    user1Token = res1.body.token;
    user1Id = res1.body.user.id;

    const res2 = await request(app)
      .post('/api/auth/register')
      .send({ username: 'user2', password: 'password2' });
    user2Token = res2.body.token;
    user2Id = res2.body.user.id;

    const todo1 = await request(app)
      .post('/api/todos')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ title: 'User1 Private Todo' });
    user1TodoId = todo1.body.id;

    const todo2 = await request(app)
      .post('/api/todos')
      .set('Authorization', `Bearer ${user2Token}`)
      .send({ title: 'User2 Private Todo' });
    user2TodoId = todo2.body.id;
  });

  afterAll(async () => {
    if (app && app.close) {
      await app.close();
    }
  });

  describe(`${ASVS_CONTROL_IDOR_4_4_1} - Direct Object Reference Prevention`, () => {
    test('User1 should NOT be able to UPDATE User2s todo (IDOR)', async () => {
      const response = await request(app)
        .put(`/api/todos/${user2TodoId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ title: 'Hacked Title' });

      expect(response.status).toBe(403);
      expect(response.body.message).toMatch(/unauthorized|access denied|forbidden|not found/i);
    });

    test('User1 should NOT be able to DELETE User2s todo (IDOR)', async () => {
      const response = await request(app)
        .delete(`/api/todos/${user2TodoId}`)
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(403);
      expect(response.body.message).toMatch(/unauthorized|access denied|forbidden|not found/i);
    });

    test('User1 should NOT be able to READ User2s todo via direct reference', async () => {
      const allTodos = await request(app)
        .get('/api/todos')
        .set('Authorization', `Bearer ${user1Token}`);

      const user2Todo = allTodos.body.find(t => t.id === user2TodoId);
      expect(user2Todo).toBeUndefined();
    });
  });

  describe(`${ASVS_CONTROL_IDOR_4_4_2} - Cross-Tenant Access Prevention`, () => {
    test('Should prevent access to other users resources through parameter manipulation', async () => {
      const tamperedToken = jwt.sign(
        { id: user1Id, username: 'user1' },
        'your-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .put(`/api/todos/${user2TodoId}`)
        .set('Authorization', `Bearer ${tamperedToken}`)
        .send({ title: 'Parameter Tampering Attempt' });

      expect(response.status).toBe(403);
    });

    test('Should validate ownership before any mutation operation', async () => {
      const response = await request(app)
        .patch(`/api/todos/${user2TodoId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ completed: true });

      expect(response.status).toBe(403);
    });
  });

  describe(`${ASVS_CONTROL_BAC_4_1} - Access Control Cannot Be Manipulated`, () => {
    test('Authorization logic should be enforced server-side', async () => {
      const response = await request(app)
        .delete(`/api/todos/${user2TodoId}?admin=true`)
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(403);
    });

    test('User role should not be manipulable via request headers', async () => {
      const response = await request(app)
        .put(`/api/todos/${user2TodoId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .set('X-User-Role', 'admin')
        .send({ title: 'Role Manipulation' });

      expect(response.status).toBe(403);
    });
  });

  describe(`${ASVS_CONTROL_BAC_4_2} - Server-Side Authorization Enforcement`, () => {
    test('All entities should require authorization verification', async () => {
      const testIds = [
        user2TodoId,
        '99999999',
        'invalid-id',
        'null'
      ];

      for (const id of testIds) {
        const response = await request(app)
          .get(`/api/todos/${id}`)
          .set('Authorization', `Bearer ${user1Token}`);
        
        expect([404, 403]).toContain(response.status);
      }
    });

    test('Authorization should fail securely (deny by default)', async () => {
      const response = await request(app)
        .get('/api/todos/non-existent-id')
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(404);
    });
  });

  describe('Positive Access Control Tests (Authorized Operations)', () => {
    test('User should be able to CRUD their own todos', async () => {
      const create = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ title: 'My Todo' });
      expect(create.status).toBe(201);
      const todoId = create.body.id;

      const read = await request(app)
        .get(`/api/todos/${todoId}`)
        .set('Authorization', `Bearer ${user1Token}`);
      expect(read.status).toBe(200);

      const update = await request(app)
        .put(`/api/todos/${todoId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ title: 'Updated Todo', completed: true });
      expect(update.status).toBe(200);

      const del = await request(app)
        .delete(`/api/todos/${todoId}`)
        .set('Authorization', `Bearer ${user1Token}`);
      expect(del.status).toBe(200);
    });
  });
});

describe('Vulnerable Endpoints with IDOR', () => {
  let app;
  let user1Token, user2Token, user1Id, user2Id;
  let user1TodoId;

  beforeAll(async () => {
    app = require('../server');
    
    const res1 = await request(app)
      .post('/api/auth/register')
      .send({ username: 'user1_vuln', password: 'password1' });
    user1Token = res1.body.token;
    user1Id = res1.body.user.id;

    const res2 = await request(app)
      .post('/api/auth/register')
      .send({ username: 'user2_vuln', password: 'password2' });
    user2Token = res2.body.token;
    user2Id = res2.body.user.id;

    const todo1 = await request(app)
      .post('/api/todos')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ title: 'User1 Private Todo' });
    user1TodoId = todo1.body.id;
  });

  describe('IDOR Vulnerability Tests (Should FAIL in vulnerable code)', () => {
    test('VULNERABLE: User2 can UPDATE User1s todo without ownership check', async () => {
      const response = await request(app)
        .put(`/api/todos/${user1TodoId}`)
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'Hacked by User2' });

      if (response.status === 200) {
        console.log('⚠️ VULNERABILITY DETECTED: IDOR allows updating other users todos');
      }
      expect(response.status).toBe(200);
    });

    test('VULNERABLE: User2 can DELETE User1s todo', async () => {
      const response = await request(app)
        .delete(`/api/todos/${user1TodoId}`)
        .set('Authorization', `Bearer ${user2Token}`);

      if (response.status === 200) {
        console.log('⚠️ VULNERABILITY DETECTED: IDOR allows deleting other users todos');
      }
      expect(response.status).toBe(200);
    });
  });
});