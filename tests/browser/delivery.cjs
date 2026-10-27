// Explicit operator actions through the installed UI. API reads verify persisted state.
const { expect } = require('playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const TITLE = 'Installed independent write verification';
const REPORT = 'Installed write assessment';
const nav = (page, name) => page.locator('nav').getByRole('button', {name:new RegExp(`${name}$`)}).click();
const panel = (page, name) => page.getByRole('heading', {name,exact:true}).locator('..');

async function read(page, path) {
  return page.evaluate(async path => {
    const r = await fetch('/backend' + path);
    if (!r.ok) throw new Error(`Fixture read failed: ${r.status}`);
    return r.json();
  }, path);
}

async function findingCard(page) {
  await nav(page, 'Findings');
  return page.getByText(TITLE, {exact:true}).locator('xpath=ancestor::div[contains(@class,"rounded-xl")][1]');
}

async function update(page, base, kind, notes, evidenceId, outcome) {
  const card = await findingCard(page);
  await card.getByText('Remediation & retests', {exact:true}).click();
  await card.getByLabel('Update type').selectOption(kind);
  if (outcome) await card.getByLabel('Verification outcome').selectOption(outcome);
  await card.getByLabel('Update notes').fill(notes);
  if (evidenceId) {
    const rows = (await read(page, `${base}/evidence?finding_id=${(await read(page, base + '/findings')).findings[0].id}&limit=50&offset=0`)).evidence;
    await expect(card.getByRole('checkbox')).toHaveCount(rows.length);
    await card.getByRole('checkbox').nth(rows.findIndex(e => e.id === evidenceId)).check();
  }
  const saved = page.waitForResponse(r => r.url().endsWith('/activity') && r.request().method() === 'POST');
  await card.getByRole('button', {name:'Save update',exact:true}).click();
  assert.equal((await saved).status(), 201);
  await expect(card.getByLabel('Update notes')).toHaveValue('');
}

async function link(page, findingId, evidenceId, jobId) {
  await nav(page, 'Dashboard');
  await page.getByText('vardrgate_api_test', {exact:true}).first().click();
  const assessment = panel(page, 'API assessment & execution evidence');
  await expect(assessment).toContainText(`Job: ${jobId}`);
  await assessment.getByRole('button', {name:'Link evidence to a finding',exact:true}).click();
  await assessment.getByLabel('Finding for selected evidence').selectOption(findingId);
  const record = assessment.getByText(new RegExp(`^Evidence ${evidenceId} ·`)).locator('..');
  const response = page.waitForResponse(r => r.url().endsWith(`/evidence/${evidenceId}/link`) && r.request().method() === 'POST');
  await record.getByRole('button', {name:'Link this evidence',exact:true}).click();
  assert((await response).ok());
  await expect(record).toContainText(`Linked finding: ${findingId}`);
}

async function saveReport(page, base, evidenceIds, next=false) {
  await nav(page, 'Reports');
  const report = panel(page, 'Engagement client reports');
  if (next) {
    await report.getByRole('button', {name:`${REPORT} · v1`,exact:true}).click();
    await report.getByRole('button', {name:'Draft next revision',exact:true}).click();
  } else {
    await report.getByRole('button', {name:'New engagement report',exact:true}).click();
  }
  await report.getByLabel('Engagement report title').fill(REPORT);
  await report.getByLabel('Executive summary').fill(next ? 'Independent readback verifies the ownership fix.' : 'Independent readback verifies unauthorized mutation.');
  await report.getByLabel('Methodology').fill('Reviewed write case; separate reader identity; isolated reset between actors.');
  await report.getByLabel('Limitations').fill('Disposable local synthetic target only; not a production assessment.');
  await report.getByLabel('Remediation priorities').fill('Enforce ownership before mutation; confirm the fix with independent readback.');
  await report.getByText(/^Select evidence \(/).click();
  const choices = report.locator('details').filter({has:page.getByText(/^Select evidence \(/)});
  const rows = (await read(page, base + '/evidence?limit=50&offset=0')).evidence;
  await expect(choices.getByRole('checkbox')).toHaveCount(rows.length);
  for (let i=0; i<rows.length; i++) await choices.getByRole('checkbox').nth(i).setChecked(evidenceIds.includes(rows[i].id));
  const saving = page.waitForResponse(r => r.url().includes('/deliverables') && r.request().method() === 'POST');
  await report.getByRole('button', {name:next ? 'Save new revision' : 'Create revision 1',exact:true}).click();
  const response = await saving;
  assert.equal(response.status(), 201);
  const revision = await response.json();
  const status = page.waitForResponse(r => r.url().endsWith(`/revisions/${revision.revision}`) && r.request().method() === 'PATCH');
  await report.getByLabel('Report revision status').selectOption('delivered');
  assert((await status).ok());
  await exportRevision(page, report, {...revision, status:'delivered'});
  await report.screenshot({path:`/artifacts/report-v${revision.revision}.png`});
  return revision.deliverable_id;
}

async function exportRevision(page, report, revision, suffix='') {
  await expect(report).toContainText(`SHA-256 ${revision.content_hash}`);
  const downloaded = page.waitForEvent('download');
  await report.getByRole('button', {name:'Download Markdown',exact:true}).click();
  const file = await downloaded;
  assert.equal(file.suggestedFilename(), `engagement-report-${revision.deliverable_id}-v${revision.revision}.md`);
  const bytes = fs.readFileSync(await file.path());
  assert.equal(bytes.toString('utf8'), revision.markdown);
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), revision.content_hash);
  await file.saveAs(`/artifacts/report-v${revision.revision}${suffix}.md`);
}

async function confirm(page, base, evidenceId, jobId) {
  await nav(page, 'Findings');
  const form = panel(page, 'Add Finding');
  await form.getByText('Title', {exact:true}).locator('..').getByRole('textbox').fill(TITLE);
  await form.getByText('Status', {exact:true}).locator('..').getByRole('combobox').selectOption('triaged');
  await form.getByText('Asset', {exact:true}).locator('..').getByRole('textbox').fill('http://gate-fixture:8080/verification/write');
  for (const [i, text] of ['A peer changed an owner record; independently verified.', 'Replay the reviewed installed write case.', 'Unauthorized record modification.', 'Enforce ownership before mutation.'].entries()) {
    await form.locator('textarea').nth(i).fill(text);
  }
  const created = page.waitForResponse(r => r.url().endsWith('/findings') && r.request().method() === 'POST');
  await form.getByRole('button', {name:'Save Finding',exact:true}).click();
  const response = await created;
  assert(response.ok());
  const finding = await response.json();
  await link(page, finding.id, evidenceId, jobId);
  await update(page, base, 'retest', 'Controlled replay confirms the unauthorized write.', evidenceId, 'still_open');
  const report = await saveReport(page, base, [evidenceId]);
  return {finding:finding.id, report};
}

async function remediation(page, base) {
  await update(page, base, 'remediation', 'Enabled the disposable target ownership check.');
}

async function complete(page, base, state, evidenceId, jobId, firstEvidence) {
  await link(page, state.finding, evidenceId, jobId);
  await update(page, base, 'retest', 'The same case now proves no unauthorized write effect.', evidenceId, 'verified_fixed');
  const stored = (await read(page, base + '/findings')).findings;
  assert.equal(stored.length, 1);
  assert.equal(stored[0].status, 'triaged'); // A retest must not silently close the finding.
  const card = await findingCard(page);
  await card.getByRole('button', {name:'Edit',exact:true}).click();
  const tracker = page.getByRole('heading', {name:/^Finding Tracker/}).locator('..');
  await tracker.getByText('Status', {exact:true}).locator('..').getByRole('combobox').selectOption('closed');
  const saved = page.waitForResponse(r => r.url().endsWith(`/findings/${state.finding}`) && r.request().method() === 'PATCH');
  await tracker.getByRole('button', {name:'Save',exact:true}).click();
  assert((await saved).ok());
  assert.equal(await saveReport(page, base, [firstEvidence,evidenceId], true), state.report);
  const report = panel(page, 'Engagement client reports');
  await report.getByText('Revision history', {exact:true}).click();
  await report.getByRole('button', {name:'v1 · delivered',exact:true}).click();
  const original = await read(page, `${base}/deliverables/${state.report}/revisions/1`);
  await exportRevision(page, report, original, '-after-retest');
}

module.exports = { confirm, remediation, complete };
