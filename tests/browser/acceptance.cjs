const { chromium } = require('playwright');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const assert = require('node:assert/strict');

(async () => {
  const url = 'https://localhost:8443';
  // A new container has no installation CA and must reject the actual proxy.
  const untrusted = await chromium.launch();
  const before = await untrusted.newPage();
  await assert.rejects(before.goto(url), /ERR_CERT_AUTHORITY_INVALID/);
  await untrusted.close();
  const db = `${process.env.HOME}/.pki/nssdb`;
  fs.mkdirSync(db, {recursive: true});
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${db}`]);
  execFileSync('certutil', ['-A', '-d', `sql:${db}`, '-n', 'VardrSec disposable test CA', '-t', 'C,,', '-i', '/trust/root.crt']);
  // Default certificate verification stays enabled; trust is isolated to this container.
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  const response = await page.goto(url);
  assert.equal(response.status(), 200);
  await page.getByLabel('Local username').fill('operator');
  await page.getByLabel('Local password').fill(process.env.FIXTURE_PASSWORD);
  await page.getByRole('button', {name:'Sign in locally',exact:true}).click();
  await page.getByLabel('Active Engagement').waitFor();
  const cookie = (await context.cookies()).find(c => c.name === '__Host-vardrmap.session');
  assert(cookie && cookie.secure && cookie.httpOnly && cookie.sameSite === 'Lax');
  const denied = await page.evaluate(async () => (await fetch('/backend/engagements', {
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'Must reject without CSRF'})
  })).status);
  assert.equal(denied, 403);
  if (process.env.FIXTURE_CREATE_RUNNER_KEY === '1') {
    await page.locator('nav').getByRole('button', {name:/Settings$/}).click();
    const generated = page.waitForResponse(r => r.url().endsWith('/auth/apikeys') && r.request().method() === 'POST');
    await page.getByRole('button', {name:'Generate Runner Key',exact:true}).click();
    const response = await generated;
    assert(response.ok(), 'Runner key creation through the UI failed');
    const key = await response.json();
    assert(key.scope === 'runner', 'UI must create a runner-scoped key');
    const displayed = await page.locator('code').filter({hasText:/^vmap_[A-Za-z0-9_-]+$/}).innerText();
    assert(displayed === key.token, 'The one-time key must be visible to the operator');
    assert(/^vmap_[A-Za-z0-9_-]{40,}$/.test(displayed), 'Invalid generated key format');
    await browser.close();
    // Private IPC only: the parent captures this stdout and never logs it or
    // writes it to artifacts. Do not add screenshots while the key is visible.
    console.log(JSON.stringify({token: displayed, id: key.id, scope: key.scope}));
    return;
  }
  await page.getByLabel('Engagement name').fill('Compose trusted HTTPS acceptance');
  await page.getByLabel('Engagement type').selectOption('internal');
  await page.getByRole('button', {name:'Create Engagement',exact:true}).click();
  const option = page.getByLabel('Active Engagement').locator('option', {hasText:'Compose trusted HTTPS acceptance'});
  await option.waitFor({state:'attached'});
  await page.reload();
  await page.getByRole('button', {name:'Sign out',exact:true}).waitFor();
  await page.locator('nav').getByRole('button', {name:/Settings$/}).click();
  const platform = page.getByRole('heading', {name:'Platform and Runner status'}).locator('..');
  await platform.getByText('Ready', {exact:true}).waitFor();
  await platform.getByText('Recent report', {exact:true}).waitFor();
  assert.match(await platform.innerText(), /Reported version \S+/);
  console.log('PASS: migrated PostgreSQL readiness and real Runner heartbeat are visible through trusted browser HTTPS');
  await page.getByRole('button', {name:'Sign out',exact:true}).click();
  await page.getByRole('button', {name:'Sign in locally',exact:true}).waitFor();
  assert(!(await context.cookies()).some(c => c.name === '__Host-vardrmap.session'));
  await browser.close();
  console.log('PASS: untrusted CA rejected; explicit isolated CA enrollment; real UI login, secure cookies, CSRF, write, reload and logout');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
