# Todo API - IDOR and BAC Security Lab

This project is a small Express.js + Passport JWT + SQLite lab for learning:

- IDOR: Insecure Direct Object Reference
- BAC: Broken Access Control
- how security regression tests catch these bugs

The same app can run in two modes:

- `VULNERABLE=true`: intentionally insecure for training
- `VULNERABLE=false`: patched with ownership checks

## Learning Goal

Students should be able to:

1. Run the vulnerable API.
2. Create two users.
3. Create a todo for one user.
4. Access that todo from the other user by changing the ID in the URL.
5. Switch to the patched mode.
6. Repeat the same requests and observe that the API now blocks them.
7. Run the security regression test and see that it fails on the vulnerable mode and passes on the patched mode.

## Project Layout

```text
todo-api/
├── server.js
├── Dockerfile
├── docker-compose.yml
├── database.sqlite
├── package.json
├── config/
│   └── passport.js
├── models/
│   ├── Todo.js
│   └── User.js
├── routes/
│   ├── auth.js
│   ├── todos.vulnerable.js
│   └── todos.patched.js
└── tests/
    └── todos.unit.security.test.js
```

## Requirements

Install these first:

1. Node.js 18+
2. npm 9+
3. Git
4. Docker Desktop or Docker Engine if you want to use containers

## Setup Locally

### 1. Clone Or Open The Project

```bash
git clone <your-repo-url>
cd todo-api
```

If you already have the folder, open a terminal in the project root.

### 2. Install Dependencies

```bash
npm install
```

### 3. Understand How Mode Switching Works

You do not need separate branches to switch between insecure and secure behavior.

Use the `VULNERABLE` environment variable:

- `VULNERABLE=true` runs `routes/todos.vulnerable.js`
- `VULNERABLE=false` runs `routes/todos.patched.js`

Important:

- if you do not set `VULNERABLE`, the app starts in vulnerable mode
- the default local port is `3000`

## Run The App Locally

### Vulnerable Mode

```bash
VULNERABLE=true npm start
```

Expected startup output:

```text
Running VULNERABLE version (IDOR/BAC enabled)
Server running on port 3000
```

Base URL:

```text
http://localhost:3000
```

### Patched Mode

Stop the running server with `Ctrl+C`, then start:

```bash
VULNERABLE=false npm start
```

Expected startup output:

```text
Running PATCHED version (Secure)
Server running on port 3000
```

Base URL:

```text
http://localhost:3000
```

### Run On Another Port

If port `3000` is already in use:

```bash
PORT=4000 VULNERABLE=true npm start
```

Then replace `3000` with `4000` in the examples below.

## API Endpoints

### Auth Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a user |
| POST | `/api/auth/login` | Log in and get a JWT |

### Todo Endpoints

All todo endpoints require:

```text
Authorization: Bearer <token>
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/todos` | List todos for the logged-in user |
| GET | `/api/todos/:id` | Get one todo |
| POST | `/api/todos` | Create a todo |
| PUT | `/api/todos/:id` | Update a todo |
| DELETE | `/api/todos/:id` | Delete a todo |

## Student Walkthrough

This walkthrough shows the vulnerability first, then the fix.

### Part 1: Observe The Vulnerability

#### 1. Start The Vulnerable App

```bash
VULNERABLE=true npm start
```

#### 2. Register User A

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```

Example response:

```json
{
  "token": "<alice-token>",
  "user": {
    "id": "1712345678901",
    "username": "alice"
  }
}
```

Save the token value as `ALICE_TOKEN`.

#### 3. Register User B

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"secret123"}'
```

Save the token value as `BOB_TOKEN`.

#### 4. Create A Todo As User B

```bash
curl -X POST http://localhost:3000/api/todos \
  -H "Authorization: Bearer <BOB_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Bob private todo"}'
```

Example response:

```json
{
  "id": "1",
  "userId": "1712345678902",
  "title": "Bob private todo",
  "completed": false
}
```

Save the todo ID as `BOB_TODO_ID`.

#### 5. Confirm Bob Can Read His Own Todo

```bash
curl http://localhost:3000/api/todos/<BOB_TODO_ID> \
  -H "Authorization: Bearer <BOB_TOKEN>"
```

#### 6. Try Reading Bob's Todo As Alice

```bash
curl http://localhost:3000/api/todos/<BOB_TODO_ID> \
  -H "Authorization: Bearer <ALICE_TOKEN>"
```

In vulnerable mode, this incorrectly succeeds.

Expected vulnerable result:

```text
HTTP 200 OK
```

#### 7. Try Updating Bob's Todo As Alice

```bash
curl -X PUT http://localhost:3000/api/todos/<BOB_TODO_ID> \
  -H "Authorization: Bearer <ALICE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Alice changed Bobs todo","completed":true}'
```

In vulnerable mode, this incorrectly succeeds.

Expected vulnerable result:

```text
HTTP 200 OK
```

#### 8. Try Deleting Bob's Todo As Alice

```bash
curl -X DELETE http://localhost:3000/api/todos/<BOB_TODO_ID> \
  -H "Authorization: Bearer <ALICE_TOKEN>"
```

In vulnerable mode, this incorrectly succeeds.

Expected vulnerable result:

```text
HTTP 200 OK
```

This is the IDOR and broken access control issue the lab is meant to teach.

### Part 2: Observe The Fix

#### 1. Stop The Vulnerable App

Press `Ctrl+C` in the terminal.

#### 2. Start The Patched App

```bash
VULNERABLE=false npm start
```

#### 3. Register Two Fresh Users

Use different usernames because the in-memory user store resets when the server restarts.

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice2","password":"secret123"}'
```

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob2","password":"secret123"}'
```

Save the new tokens as `ALICE2_TOKEN` and `BOB2_TOKEN`.

#### 4. Create A Todo As User B Again

```bash
curl -X POST http://localhost:3000/api/todos \
  -H "Authorization: Bearer <BOB2_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Bob2 private todo"}'
```

Save the returned ID as `BOB2_TODO_ID`.

#### 5. Retry The Same Cross-User Requests

Read attempt:

```bash
curl http://localhost:3000/api/todos/<BOB2_TODO_ID> \
  -H "Authorization: Bearer <ALICE2_TOKEN>"
```

Update attempt:

```bash
curl -X PUT http://localhost:3000/api/todos/<BOB2_TODO_ID> \
  -H "Authorization: Bearer <ALICE2_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Attempted attack","completed":true}'
```

Delete attempt:

```bash
curl -X DELETE http://localhost:3000/api/todos/<BOB2_TODO_ID> \
  -H "Authorization: Bearer <ALICE2_TOKEN>"
```

In patched mode, each request should be rejected.

Expected patched result:

```text
HTTP 403 Forbidden
```

## Run The Security Regression Test

The regression suite is in `tests/todos.unit.security.test.js`.

It enforces this secure contract:

1. a user must not read another user's todo by ID
2. a user must not update another user's todo by ID
3. a user must not delete another user's todo by ID

### Run It Against The Vulnerable App Logic

```bash
VULNERABLE=true npm run test:security
```

Expected result:

```text
FAIL
```

This failure is intentional. It proves the vulnerability exists.

### Run It Against The Patched App Logic

```bash
VULNERABLE=false npm run test:security
```

Expected result:

```text
PASS
```

This proves the fix satisfies the security contract.

### Run The Default Test Command

```bash
VULNERABLE=false npm test
```

This runs the same Jest suite and should pass in patched mode.

### Run Coverage

```bash
VULNERABLE=false npm run test:coverage
```

If you run coverage in vulnerable mode, expect the suite to fail for the same reason.

## Run With Docker

### Start Both App Modes

```bash
docker-compose up --build
```

This starts:

1. vulnerable API at `http://localhost:3001`
2. patched API at `http://localhost:3002`

You can repeat the same curl walkthrough above by changing the port:

- use `3001` for vulnerable mode
- use `3002` for patched mode

### Run Tests In Docker

Vulnerable-mode test run:

```bash
docker-compose run todo-tests
```

Expected result:

```text
FAIL
```

This is intentional because the container runs with `VULNERABLE=true`.

Patched-mode test run:

```bash
docker-compose run -e VULNERABLE=false todo-tests
```

Expected result:

```text
PASS
```

### Stop Docker Services

```bash
docker-compose down
```

## Vulnerable Vs Patched Behavior

### Vulnerable Mode

In `VULNERABLE=true` mode:

1. `GET /api/todos/:id` does not verify ownership
2. `PUT /api/todos/:id` does not verify ownership
3. `DELETE /api/todos/:id` does not verify ownership

That means one authenticated user can act on another user's todo by changing the object ID.

### Patched Mode

In `VULNERABLE=false` mode, the API checks that the todo belongs to the authenticated user before reading, updating, or deleting it.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP server port |
| `VULNERABLE` | `true` | `true` runs insecure routes, `false` runs patched routes |

## Notes For Students

1. Users are stored in memory, so restarting the server resets registered users.
2. Todos are stored in SQLite, so todo records can remain in `database.sqlite` between runs.
3. If test runs behave strangely, stop any running server before executing Jest.
4. If usernames already exist, register new usernames such as `alice3` and `bob3`.

## Troubleshooting

### Port Already In Use

Run the app on another port:

```bash
PORT=4000 VULNERABLE=false npm start
```

### Tests Fail In Vulnerable Mode

That is expected for the regression suite. The tests are supposed to fail when the app is insecure.

### Docker Does Not Start

Make sure Docker is running, then retry:

```bash
docker-compose up --build
```

## License

ISC - Educational Use Only
