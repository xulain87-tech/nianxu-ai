#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { spawn, spawnSync } = require('node:child_process');

const project = path.resolve(__dirname, '..');
const counts = { slow: 0, fast: 0, empty: 0 };
let slowTimer;

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}

async function waitForHealth(baseUrl, child) {
  for (let i = 0; i < 60; i++) {
    if (child.exitCode !== null) throw new Error(`server.js exited early (${child.exitCode})`);
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return response.json();
    } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('server.js did not become healthy within 6 seconds');
}

(async () => {
  const upstream = http.createServer((req, res) => {
    const name = req.url.slice(1);
    if (!(name in counts)) return json(res, 404, { error: 'not found' });
    counts[name]++;
    req.resume();
    if (name === 'slow') {
      slowTimer = setTimeout(() => json(res, 200, {
        choices: [{ message: { content: '慢接口答案' }, finish_reason: 'stop' }]
      }), 1200);
      res.on('close', () => clearTimeout(slowTimer));
      return;
    }
    if (name === 'empty') {
      return json(res, 200, { choices: [{ message: { content: null }, finish_reason: 'stop' }] });
    }
    return setTimeout(() => json(res, 200, {
      choices: [{ message: { content: '快速接口答案' }, finish_reason: 'stop' }]
    }), 60);
  });

  let app;
  let dataDir;
  try {
    const upstreamPort = await listen(upstream);
    const appPortServer = http.createServer();
    const appPort = await listen(appPortServer);
    await new Promise(resolve => appPortServer.close(resolve));
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'astrion-smoke-'));
    const adminPassword = `smoke-${Date.now()}-password`;
    const missingSecrets = spawnSync(process.execPath, ['server.js'], {
      cwd: project, encoding: 'utf8', timeout: 3000,
      env: { ...process.env, PORT: '0', DATA_DIR: dataDir, ADMIN_ID: '', ADMIN_PASSWORD: '' }
    });
    assert.equal(missingSecrets.status, 1, 'server should refuse to start without private login secrets');
    assert.match(missingSecrets.stderr, /Private login secrets are missing/);
    assert.doesNotMatch(missingSecrets.stderr, /smokeadmin|smoke-.*password/);
    app = spawn(process.execPath, ['server.js'], {
      cwd: project,
      env: {
        ...process.env,
        PORT: String(appPort),
        DATA_DIR: dataDir,
        NODE_ENV: 'test',
        ADMIN_ID: 'smokeadmin',
        ADMIN_PASSWORD: adminPassword,
        TRUST_PROXY_HOPS: '0'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let logs = '';
    app.stdout.on('data', chunk => { logs += chunk.toString(); });
    app.stderr.on('data', chunk => { logs += chunk.toString(); });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    const health = await waitForHealth(baseUrl, app);
    assert.equal(health.status, 'ok');
    assert.equal(health.version, '1.1.7');

    const unauthorized = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: 'test' }] })
    });
    assert.equal(unauthorized.status, 401, 'chat endpoint must require login');

    const login = await fetch(`${baseUrl}/api/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'smokeadmin', password: adminPassword })
    });
    assert.equal(login.status, 200, 'privileged login should succeed');
    const loginData = await login.json();
    assert.equal(loginData.userId, 'ASTRION', 'login must not return the configured account ID');
    assert.equal(loginData.displayName, 'ASTRION', 'login must use a neutral display name');
    const cookie = login.headers.get('set-cookie')?.split(';')[0];
    assert.ok(cookie, 'login should issue an HttpOnly session cookie');
    const adminSessionResponse = await fetch(`${baseUrl}/api/session`, { headers: { cookie } });
    const adminSession = await adminSessionResponse.json();
    assert.equal(adminSession.userId, 'ASTRION', 'session must not expose the configured account ID');
    const adminProfile = await fetch(`${baseUrl}/api/account/profile`, { headers: { cookie } }).then(r => r.json());
    assert.equal(adminProfile.id, 'ASTRION', 'profile must not expose the configured account ID');

    const invalid = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(invalid.status, 400, 'invalid chat payload should be rejected clearly');

    const configure = async apis => {
      const response = await fetch(`${baseUrl}/api/admin/apis`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify({ apis })
      });
      assert.equal(response.status, 200, 'admin should be able to save API configuration');
    };
    const api = name => ({
      name,
      url: `http://127.0.0.1:${upstreamPort}/${name}`,
      model: 'mock-model', enabled: true, key: ''
    });
    const chat = async () => fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ messages: [{ role: 'user', content: '测试回复' }] })
    });

    await configure([api('slow'), api('fast')]);
    let started = Date.now();
    let response = await chat();
    let elapsed = Date.now() - started;
    let result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.answer, '快速接口答案');
    assert.equal(result.used, 'fast');
    assert.ok(elapsed < 900, `fastest valid response should win (elapsed ${elapsed}ms)`);
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(counts.slow, 1, 'slow provider should be called only once');
    assert.equal(counts.fast, 1, 'fast provider should be called only once');

    await configure([api('empty'), api('fast')]);
    response = await chat();
    result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.answer, '快速接口答案', 'empty upstream responses should fall back');
    assert.equal(counts.empty, 1);
    assert.equal(counts.fast, 2);

    const largeChat = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ messages: [{ role: 'user', content: [
        { type: 'image_url', image_url: { url: 'data:image/webp;base64,' + 'a'.repeat(1_400_000) } }
      ] }] })
    });
    assert.equal(largeChat.status, 200, 'compressed image chat payloads above 1MB should be accepted');
    assert.equal((await largeChat.json()).answer, '快速接口答案');

    const register = await fetch(`${baseUrl}/api/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'smokeuser', password: 'register-password' })
    });
    assert.equal(register.status, 201, 'ordinary user registration should succeed');
    const userLogin = await fetch(`${baseUrl}/api/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'smokeuser', password: 'register-password' })
    });
    assert.equal(userLogin.status, 200, 'registered user should be able to log in');
    const userCookie = userLogin.headers.get('set-cookie')?.split(';')[0];
    const userSession = await fetch(`${baseUrl}/api/session`, { headers: { cookie: userCookie } });
    const userData = await userSession.json();
    assert.equal(userData.authenticated, true);
    assert.equal(userData.role, 'guest');

    const logout = await fetch(`${baseUrl}/api/logout`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}'
    });
    assert.equal(logout.status, 200);
    const session = await fetch(`${baseUrl}/api/session`, { headers: { cookie } });
    assert.equal((await session.json()).authenticated, false);

    console.log('PASS: health, admin/user auth, payload validation, one-shot race, empty-response fallback, logout');
  } catch (error) {
    console.error(error);
    if (app && app.exitCode !== null) console.error('server logs:', logs);
    process.exitCode = 1;
  } finally {
    if (slowTimer) clearTimeout(slowTimer);
    if (app && app.exitCode === null) {
      app.kill('SIGTERM');
      await new Promise(resolve => {
        const timeout = setTimeout(() => { app.kill('SIGKILL'); resolve(); }, 1500);
        app.once('exit', () => { clearTimeout(timeout); resolve(); });
      });
    }
    await new Promise(resolve => upstream.close(resolve));
    upstream.closeAllConnections?.();
    if (dataDir) await fs.rm(dataDir, { recursive: true, force: true });
  }
})();
