const {chromium} = require('playwright');
const {execFileSync} = require('node:child_process');
const {X509Certificate} = require('node:crypto');
const fs = require('node:fs');
const tls = require('node:tls');
const assert = require('node:assert/strict');

const url = 'https://localhost:8446';
const ca = fs.readFileSync('/trust/root.crt');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function browserProbe(trusted) {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    if (!trusted) {
      await assert.rejects(page.goto(url, {timeout:20000}), /ERR_CERT_AUTHORITY_INVALID/);
      return;
    }
    const response = await page.goto(url, {timeout:20000});
    assert.equal(response.status(), 200);
    assert.equal(await page.locator('body').innerText(), 'VardrSec certificate renewal acceptance');
  } finally {
    await browser.close();
  }
}

function leaf() {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({host:'127.0.0.1', port:8446, servername:'localhost', ca});
    socket.setTimeout(5000, () => socket.destroy(new Error('TLS handshake timed out')));
    socket.once('error', reject);
    socket.once('secureConnect', () => {
      try {
        assert(socket.authorized);
        assert(!socket.isSessionReused());
        const certificate = new X509Certificate(socket.getPeerCertificate().raw);
        resolve({serial:certificate.serialNumber, expires:Date.parse(certificate.validTo)});
      } catch (error) {
        reject(error);
      } finally {
        socket.destroy();
      }
    });
  });
}

(async () => {
  const mode = process.argv[2];
  assert(['renew', 'restart'].includes(mode));
  await browserProbe(false);
  const db = `${process.env.HOME}/.pki/nssdb`;
  fs.mkdirSync(db, {recursive:true});
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${db}`]);
  execFileSync('certutil', ['-A', '-d', `sql:${db}`, '-n', 'VardrSec disposable renewal CA', '-t', 'C,,', '-i', '/trust/root.crt']);
  await browserProbe(true);
  if (mode === 'restart') {
    await leaf();
    console.log('PASS: fresh browser and TLS handshake trust the original public CA after proxy restart');
    return;
  }

  const initial = await leaf();
  const remaining = initial.expires - Date.now();
  assert(remaining > 15000 && remaining <= 125000, 'Fixture must issue short-lived leaf certificates');
  console.log(`Observing leaf renewal with ${Math.ceil(remaining / 1000)} seconds remaining`);
  const serials = new Set([initial.serial]);
  let renewed = false;
  let samples = 1;
  const deadline = performance.now() + 180000;
  while (Date.now() <= initial.expires + 3000) {
    assert(performance.now() < deadline, 'Renewal observation exceeded its deadline');
    await sleep(1000);
    const current = await leaf();
    samples++;
    serials.add(current.serial);
    if (!renewed && current.serial !== initial.serial) {
      assert(Date.now() < initial.expires, 'Leaf renewal must precede original expiry');
      assert(current.expires > initial.expires, 'Renewal must extend validity');
      renewed = true;
    }
  }
  assert(renewed && serials.size >= 2, 'A running proxy must renew its leaf without reload');
  await browserProbe(true);
  console.log(`PASS: ${samples} fresh verified TLS handshakes; ${serials.size} leaf serials; renewal before expiry and fresh browser HTTPS after original expiry`);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
