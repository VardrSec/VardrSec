// Installed workflow: real UI review/queue and rendered evidence, real Runner/Gate.
const { chromium, expect } = require('playwright/test');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const readline = require('node:readline');
const assert = require('node:assert/strict');

const input = readline.createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const event = data => console.log('GATE_EVENT ' + JSON.stringify(data));

(async () => {
  const cases = JSON.parse(process.env.FIXTURE_CASES);
  const engagement = process.env.FIXTURE_ENGAGEMENT;
  const db = `${process.env.HOME}/.pki/nssdb`;
  fs.mkdirSync(db, {recursive: true});
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${db}`]);
  execFileSync('certutil', ['-A', '-d', `sql:${db}`, '-n', 'VardrSec disposable test CA', '-t', 'C,,', '-i', '/trust/root.crt']);
  const browser = await chromium.launch();
  let page;
  try {
    page = await browser.newPage({ viewport: {width: 1440, height: 1100} });
    await page.goto('https://localhost:8443'); // Normal certificate verification.
    await page.getByLabel('Local username').fill('operator');
    await page.getByLabel('Local password').fill(process.env.FIXTURE_PASSWORD);
    await page.getByRole('button', {name:'Sign in locally',exact:true}).click();
    await page.getByLabel('Active Engagement').selectOption(engagement);
    await page.locator('nav').getByRole('button', {name:/Review$/}).click();
    await page.getByRole('button', {name:'API Surface',exact:true}).click();
    await page.getByRole('heading', {name:'Draft authorization tests',exact:true}).waitFor();
    await page.getByLabel('Draft source').selectOption('openapi');
    await page.getByLabel('OpenAPI document', {exact:true}).fill(JSON.stringify({
      openapi: '3.1.0', info: {title:'Disposable authorization target',version:'1.0'},
      servers: [{url:'http://gate-fixture:8080'}],
      paths: {'/vulnerable/records/42': {get: {responses: {'200': {description:'Fixture'}}}}},
    }));
    await page.getByRole('button', {name:'Generate draft cases',exact:true}).click();
    const editor = page.getByLabel('Draft cases JSON');
    await editor.waitFor();
    const drafts = JSON.parse(await editor.inputValue());
    assert(drafts.length > 0 && drafts.every(d => d.spec.expected_access.every(e => e.decision === 'skip')));
    await editor.fill(JSON.stringify(cases));
    await page.getByRole('checkbox', {name:/I reviewed the request targets/}).check();
    const saving = page.waitForResponse(r => r.url().endsWith('/test-cases/reviewed') && r.request().method() === 'POST');
    await page.getByRole('button', {name:'Save reviewed cases',exact:true}).click();
    const saved = await saving;
    assert.equal(saved.status(), 201);
    const stored = (await saved.json()).test_cases;
    assert.equal(stored.length, 3);
    event({type:'reviewed', cases:stored});
    await page.getByRole('status').filter({hasText:'3 reviewed cases saved'}).waitFor();
    await page.locator('nav').getByRole('button', {name:/Dashboard$/}).click();
    const picker = page.getByRole('button', {name:'Select vardrgate',exact:true});
    if (!(await picker.isVisible())) {
      await page.getByRole('button', {name:/Tools .*show all/}).click();
    }
    await picker.click();
    for (const scenario of ['blocked', 'vulnerable', 'fixed', 'unavailable']) {
      const name = scenario === 'blocked' ? 'vulnerable' : scenario;
      const selected = stored.find(c => c.name === name);
      assert(selected);
      await page.getByLabel('Authorization test case', {exact:true}).selectOption(selected.id);
      const queued = page.waitForResponse(r => r.url().endsWith(`/engagements/${engagement}/jobs`) && r.request().method() === 'POST');
      await page.getByRole('button', {name:'Queue Job',exact:true}).click();
      const response = await queued;
      assert(response.ok());
      const job = await response.json();
      assert.equal(job.status, 'pending');
      const panel = page.getByRole('heading', {name:'API assessment & execution evidence',exact:true}).locator('..');
      await expect(panel).toContainText(`Job: ${job.id}`);
      event({type:'queued', scenario, job:job.id, case:selected.id});
      // The host runs only the explicitly announced job, then acknowledges completion.
      const next = await input.next();
      assert(!next.done && JSON.parse(next.value).continue === true);
      const status = scenario === 'blocked' || scenario === 'unavailable' ? 'inconclusive' : 'conclusive';
      await expect(panel).toContainText(`Assessment: ${status}.`, {timeout:30000});
      await expect(panel).toContainText('Job completion alone does not establish authorization or a clean result.');
      if (scenario !== 'blocked') {
        await expect(panel).toContainText('Result matches claimed case snapshot: reported hash matches.');
        await expect(panel).toContainText('Identity preflight: passed.');
        await expect(panel).toContainText('Scanner findings remain candidates.');
        const record = panel.locator('div.rounded.border')
          .filter({has:page.getByText(/Identity: peer$/)})
          .filter({hasText:'Expected deny'});
        await expect(record).toHaveCount(1);
        await record.getByText('Redacted execution record', {exact:true}).click();
        await expect(record.locator('pre')).toContainText('peer');
        await expect(record).toContainText('SHA-256');
      }
      await panel.screenshot({path:`/artifacts/${scenario}.png`});
      event({type:'rendered', scenario});
    }
    console.log('PASS: reviewed cases and queued jobs through installed UI; all four real assessments and evidence rendered over trusted HTTPS');
    await page.getByRole('button', {name:'Sign out',exact:true}).click();
    await page.getByRole('button', {name:'Sign in locally',exact:true}).waitFor();
  } catch (error) {
    await page?.screenshot({path:'/artifacts/failure.png', fullPage:true}).catch(() => {});
    throw error;
  } finally {
    input.return?.();
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => process.stdin.destroy());
