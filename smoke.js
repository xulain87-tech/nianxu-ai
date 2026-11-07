#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { spawn, spawnSync } = require('node:child_process');

const project = path.resolve(__dirname, '..');
const counts = { slow: 0, fast: 0, empty: 0, primary: 0, alias: 0 };
const upstreamPayloads = [];
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
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      try { upstreamPayloads.push({ name, body: JSON.parse(raw || '{}'), authorization: req.headers.authorization || '' }); } catch (_) {}
      if (name === 'primary' || name === 'alias') return json(res, 503, { error: 'mock failure' });
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
  });

  let app;
  let dataDir;
  let logs = '';
  try {
    const html=await fs.readFile(path.join(project,'index.html'),'utf8');
    assert.doesNotMatch(html, /<\/style>你好，我是 ASTRION<style/);
    assert.match(html, /id="apiBackupPanel" hidden/, 'retired import/export editor must stay hidden');
    assert.match(html, /id="apiList" hidden/, 'retired API editor must stay hidden');
    assert.match(html, /Groq Key（服务端环境变量）/, 'primary key must be configured only on the server');
    assert.match(html, /#apiList,#apiBackupPanel,#saveSettings/);
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
        ZHIPU_API_KEY: '',
        ASTRION_TEST_GROQ_API_KEY: 'groq-test-sentinel',
        ASTRION_TEST_GROQ_API_URL: `http://127.0.0.1:${upstreamPort}/primary`,
        TRUST_PROXY_HOPS: '0'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    app.stdout.on('data', chunk => { logs += chunk.toString(); });
    app.stderr.on('data', chunk => { logs += chunk.toString(); });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    const health = await waitForHealth(baseUrl, app);
    assert.equal(health.status, 'ok');
    assert.equal(health.version, '1.3.2');

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

    const getApis = async () => fetch(`${baseUrl}/api/admin/apis`, { headers: { cookie } });
    let apiResponse = await getApis();
    assert.equal(apiResponse.status, 200);
    let apiData = await apiResponse.json();
    assert.equal(apiData.apis.length, 5, 'server should expose exactly five shared slots');
    assert.equal(apiData.apis[0].model, 'openai/gpt-oss-120b', 'first slot should be Groq GPT-OSS-120B');
    assert.equal(apiData.apis[0].url, `http://127.0.0.1:${upstreamPort}/primary`, 'test-only mock should replace the fixed endpoint only in NODE_ENV=test');
    assert.equal(apiData.apis[0].keySet, true, 'test sentinel should be available only to the fixed primary slot');
    assert.ok(apiData.apis.every(slot => !Object.hasOwn(slot, 'key')), 'API keys must never be returned');

    const invalid = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(invalid.status, 400, 'invalid chat payload should be rejected clearly');
    const wrongSlotCount = await fetch(`${baseUrl}/api/admin/apis`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ apis: [{ name: 'one' }] })
    });
    assert.equal(wrongSlotCount.status, 400, 'configuration must reject anything other than five slots');
    const insecureEndpoint=await fetch(`${baseUrl}/api/admin/apis`,{method:'PUT',headers:{'content-type':'application/json',cookie},body:JSON.stringify({apis:[{name:'main'},{name:'plain-http',url:'http://example.com/v1',model:'m',enabled:false,key:''},{name:'3'},{name:'4'},{name:'5'}]})});
    assert.equal(insecureEndpoint.status,400,'non-loopback HTTP endpoints must be rejected even when disabled');

    const fakeSecret = 'unit-test-secret-not-real';
    const provider = name => ({
      name,
      url: `http://127.0.0.1:${upstreamPort}/${name}`,
      model: 'mock-model', enabled: true, key: ''
    });
    const slot = (name, url = '', model = '', enabled = false, key = '') => ({ name, url, model, enabled, key });
    const configure = async (providers, secret = '') => {
      const apis = [
        slot('ignored first-slot input', 'https://invalid.example/chat', 'ignored', false, 'client-primary-key-sentinel'),
        providers[0] || slot('接口 2'),
        providers[1] || slot('接口 3'),
        providers[2] || slot('接口 4'),
        providers[3] || slot('接口 5', '', '', false, secret)
      ];
      const response = await fetch(`${baseUrl}/api/admin/apis`, {
        method: 'PUT', headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify({ apis })
      });
      assert.equal(response.status, 200, 'admin should be able to save all five shared slots');
    };
    await configure([{...provider('alias'),name:'Groq mirror'}, provider('slow'), provider('fast')], fakeSecret);
    apiResponse = await getApis();
    apiData = await apiResponse.json();
    assert.equal(apiData.apis.length, 5);
    assert.equal(apiData.apis[0].model, 'openai/gpt-oss-120b', 'admin cannot overwrite the fixed first slot');
    assert.equal(apiData.apis[4].keySet, true, 'server reports key presence only');
    assert.doesNotMatch(JSON.stringify(apiData), new RegExp(fakeSecret));
    const storedConfig=JSON.parse(await fs.readFile(path.join(dataDir,'ai-config.json'),'utf8'));
    assert.equal(storedConfig.apis[0].key,'','client-supplied primary key must be discarded');
    assert.equal(storedConfig.apis[0].primary,true,'the primary credential is bound to a fixed slot, not its name');
    assert.equal((await fs.stat(path.join(dataDir,'ai-config.json'))).mode & 0o777,0o600,'server-side API configuration file must be private');

    const chat = async (includeUntrustedSystem = true) => fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        messages: [
          ...(includeUntrustedSystem ? [{ role: 'system', content: 'CLIENT_SYSTEM_SENTINEL' }] : []),
          { role: 'user', content: '测试回复' }
        ]
      })
    });

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
    assert.ok(upstreamPayloads.some(x=>x.name==='primary'&&x.authorization==='Bearer groq-test-sentinel'),'the Groq environment sentinel should reach only the fixed primary endpoint');
    assert.ok(upstreamPayloads.some(x=>x.name==='alias'&&!x.authorization),'a backup slot named like Zhipu must not receive the primary environment Key');
    assert.ok(upstreamPayloads.length > 0);
    assert.ok(upstreamPayloads.every(x => !JSON.stringify(x.body).includes('CLIENT_SYSTEM_SENTINEL')),
      'client system-role messages must be discarded before reaching providers');
    assert.ok(upstreamPayloads.some(x => JSON.stringify(x.body).includes('ASTRION')),
      'server-owned system context should be supplied');

    await configure([provider('empty'), provider('fast')]);
    response = await chat(false);
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

    const privateList = await fetch(`${baseUrl}/api/custom-ai/list`);
    assert.equal(privateList.status, 401, 'custom AI data must require authentication');
    const customList = await fetch(`${baseUrl}/api/custom-ai/list`, { headers: { cookie } });
    assert.equal(customList.status, 200, 'custom AI list route should load for an authenticated user');
    const myAi = await fetch(`${baseUrl}/api/custom-ai/mine`, { headers: { cookie } });
    assert.equal(myAi.status, 200, 'custom AI profile route should load for an authenticated user');

    const createNotice = await fetch(`${baseUrl}/api/admin/notices`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ title: '测试公告', content: '所有登录用户可查看。' })
    });
    assert.ok([200, 201].includes(createNotice.status), 'admin should be able to publish a notice');

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
    const userApiAccess = await fetch(`${baseUrl}/api/admin/apis`, { headers: { cookie: userCookie } });
    assert.equal(userApiAccess.status, 401, 'ordinary users cannot edit shared provider settings');
    const sharedChat = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: userCookie },
      body: JSON.stringify({ messages: [{ role: 'user', content: '共享配置测试' }] })
    });
    assert.equal(sharedChat.status, 200);
    assert.equal((await sharedChat.json()).used, 'fast', 'ordinary users should use the same server-side provider slots');
    const published = await fetch(`${baseUrl}/api/notices`, { headers: { cookie: userCookie } });
    assert.equal(published.status, 200, 'all logged-in users should be able to fetch published notices');
    const publishedData = await published.json();
    assert.ok((publishedData.notices || []).some(n => n.title === '测试公告'));

    const imageWithoutKey = await fetch(`${baseUrl}/api/ai/image`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: userCookie },
      body: JSON.stringify({ prompt: 'test image', enhance: false })
    });
    assert.equal(imageWithoutKey.status, 400, 'image endpoint should fail clearly without a server-side key');
    assert.doesNotMatch(await imageWithoutKey.text(), new RegExp(fakeSecret));

    const logout = await fetch(`${baseUrl}/api/logout`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}'
    });
    assert.equal(logout.status, 200);
    const session = await fetch(`${baseUrl}/api/session`, { headers: { cookie } });
    assert.equal((await session.json()).authenticated, false);

    console.log('PASS: health, authentication, shared five-slot configuration, primary-key isolation, HTTPS validation, key redaction, server-owned prompt, race/fallback, custom AI routes, notices, image-key guard, logout');
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
