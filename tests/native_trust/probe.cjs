const {chromium} = require('playwright');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    if (process.argv[2] === 'trusted') {
      const response = await page.goto('https://localhost:8445', {timeout:20000});
      assert.equal(response.status(), 200);
      assert.equal(await page.locator('body').innerText(), 'VardrSec native trust acceptance');
    } else {
      await assert.rejects(page.goto('https://localhost:8445', {timeout:20000}), /ERR_CERT_AUTHORITY_INVALID/);
    }
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
