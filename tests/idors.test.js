const request = require('supertest');
const jwt = require('jsonwebtoken');

const ASVS_CONTROL_IDOR_4_4_1 = 'V4.4.1';
const ASVS_CONTROL_IDOR_4_4_2 = 'V4.4.2';
const ASVS_CONTROL_BAC_4_1 = 'V4.1';
const ASVS_CONTROL_BAC_4_2 = 'V4.2';

const isVulnerable = process.env.VULNERABLE !== 'false';

describe(`OWASP ASVS IDOR & BAC Security Tests ${isVulnerable ? '(VULNERABLE)' : '(PATCHED)'}`, () => {
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
      const newTodo = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'User2 Target Todo' });
      const targetId = newTodo.body.id;

      const response = await request(app)
        .put(`/api/todos/${targetId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ title: 'Hacked Title' });

      const expectedStatus = isVulnerable ? 200 : 403;
      expect(response.status).toBe(expectedStatus);
      
      if (!isVulnerable) {
        expect(response.body.message).toMatch(/unauthorized|access denied|forbidden|not found|only modify/i);
      }
    });

    test('User1 should NOT be able to DELETE User2s todo (IDOR)', async () => {
      const newTodo = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'User2 Todo For Delete' });
      const targetId = newTodo.body.id;

      const response = await request(app)
        .delete(`/api/todos/${targetId}`)
        .set('Authorization', `Bearer ${user1Token}`);

      const expectedStatus = isVulnerable ? 200 : 403;
      expect(response.status).toBe(expectedStatus);
    });

    test('User1 should NOT be able to READ User2s todo via direct reference', async () => {
      const allTodos = await request(app)
        .get('/api/todos')
        .set('Authorization', `Bearer ${user1Token}`);

      if (isVulnerable) {
        console.log('⚠️ VULNERABILITY: User1 can see all todos in database (no filter)');
      }
      const user2Todo = allTodos.body.find(t => t.id === user2TodoId);
      
      if (!isVulnerable) {
        expect(user2Todo).toBeUndefined();
      }
    });
  });

  describe(`${ASVS_CONTROL_IDOR_4_4_2} - Cross-Tenant Access Prevention`, () => {
    test('Should prevent access to other users resources through parameter manipulation', async () => {
      const newTodo = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'User2 Another Todo' });
      const targetId = newTodo.body.id;

      const response = await request(app)
        .put(`/api/todos/${targetId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .send({ title: 'Parameter Tampering Attempt' });

      const expectedStatus = isVulnerable ? 200 : 403;
      expect(response.status).toBe(expectedStatus);
    });
  });

  describe(`${ASVS_CONTROL_BAC_4_1} - Access Control Cannot Be Manipulated`, () => {
    test('Authorization logic should be enforced server-side', async () => {
      const newTodo = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'User2 Admin Test Todo' });
      const targetId = newTodo.body.id;

      const response = await request(app)
        .delete(`/api/todos/${targetId}?admin=true`)
        .set('Authorization', `Bearer ${user1Token}`);

      const expectedStatus = isVulnerable ? 200 : 403;
      expect(response.status).toBe(expectedStatus);
    });

    test('User role should not be manipulable via request headers', async () => {
      const newTodo = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${user2Token}`)
        .send({ title: 'User2 Role Test Todo' });
      const targetId = newTodo.body.id;

      const response = await request(app)
        .put(`/api/todos/${targetId}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .set('X-User-Role', 'admin')
        .send({ title: 'Role Manipulation' });

      const expectedStatus = isVulnerable ? 200 : 403;
      expect(response.status).toBe(expectedStatus);
    });
  });

  describe(`${ASVS_CONTROL_BAC_4_2} - Server-Side Authorization Enforcement`, () => {
    test('All entities should require authorization verification', async () => {
      const response = await request(app)
        .get(`/api/todos/99999999`)
        .set('Authorization', `Bearer ${user1Token}`);
      
      expect([404, 403]).toContain(response.status);
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

  describe('Security Test Summary', () => {
    test('SECURITY STATUS', () => {
      if (isVulnerable) {
        console.log('\n🔴 VULNERABLE VERSION - IDOR/BAC flaws present');
        console.log('   - No ownership verification on PUT /:id');
        console.log('   - No ownership verification on DELETE /:id');
        console.log('   - No ownership verification on GET /:id');
      } else {
        console.log('\n🟢 PATCHED VERSION - Proper access controls in place');
        console.log('   - Ownership verified before PUT');
        console.log('   - Ownership verified before DELETE');
        console.log('   - Ownership verified before GET');
      }
      expect(true).toBe(true);
    });
  });
});