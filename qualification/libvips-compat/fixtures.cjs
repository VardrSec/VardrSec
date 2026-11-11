// Ordinary small generated fixtures only. No security or malformed-input cases.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(process.argv[2]);
const mode = process.argv[3];
const pins = JSON.parse(fs.readFileSync(path.join(__dirname, 'pins.json')));
const targetImage = process.env.QUALIFICATION_TARGET_IMAGE || null;
if(targetImage) assert.equal(targetImage,pins.target_node_image);
assert(['original', 'candidate'].includes(mode));
const sharp = require(path.join(root, mode, 'node_modules/sharp'));
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
(async () => {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  assert.equal(process.versions.node.split('.')[0], '24');
  assert.equal(sharp.versions.sharp, '0.35.5'); assert.equal(sharp.versions.vips, '8.18.7');
  const dir = path.join(root, 'fixtures');
  const rows = [];
  if (mode === 'original' && !fs.existsSync(dir)) {
    fs.mkdirSync(dir);
    const raw = Buffer.alloc(32 * 24 * 4);
    for (let y=0;y<24;y++) for(let x=0;x<32;x++) {
      const i=(y*32+x)*4; raw[i]=x*7;raw[i+1]=y*10;raw[i+2]=100;raw[i+3]=x<16?128:255;
    }
    for (const format of ['png','jpeg','webp','avif','tiff','gif']) {
      const input = sharp(raw, {raw:{width:32,height:24,channels:4}});
      fs.writeFileSync(path.join(dir,format), await input.toFormat(format).toBuffer());
    }
    fs.writeFileSync(path.join(dir,'icc'), await sharp(raw,{raw:{width:32,height:24,channels:4}}).withIccProfile('srgb').png().toBuffer());
    fs.writeFileSync(path.join(dir,'svg'), '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="24"><defs><linearGradient id="g"><stop stop-color="red"/><stop offset="1" stop-color="blue"/></linearGradient></defs><rect width="32" height="24" fill="url(#g)"/><circle cx="16" cy="12" r="6" opacity=".5" fill="white"/></svg>');
  }
  for(const name of ['png','jpeg','webp','avif','tiff','gif','icc','svg']) {
    const input = fs.readFileSync(path.join(dir,name));
    const metadata = await sharp(input).metadata();
    assert.equal(metadata.width,32);assert.equal(metadata.height,24);
    if(name==='png') assert.equal(metadata.hasAlpha,true);
    if(name==='icc') assert(metadata.icc && metadata.icc.length>0);
    for(const operation of ['decode','resize-rotate']) {
      let pipeline=sharp(input);
      if(operation==='resize-rotate') pipeline=sharp(await pipeline.resize(16,12).png().toBuffer()).rotate(90);
      const {data,info} = await pipeline.ensureAlpha().raw().toBuffer({resolveWithObject:true});
      assert.equal(info.width,operation==='decode'?32:12);assert.equal(info.height,operation==='decode'?24:16);
      rows.push({fixture:name,operation,inputSha256:digest(input),pixelsSha256:digest(data),width:info.width,height:info.height,channels:info.channels});
    }
    if(mode==='candidate' && !['icc','svg'].includes(name)) {
      const encoded=await sharp(input).toFormat(name).toBuffer();
      const check=await sharp(encoded).metadata();assert.equal(check.width,32);assert.equal(check.height,24);
      // Save receipts, not a claim that lossy re-encoding preserves source pixels.
      rows.push({fixture:name,operation:'encode-decode',encodedSha256:digest(encoded),width:check.width,height:check.height});
    }
  }
  const libraryPath=path.join(root,mode,'node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.8.18.7');
  const mapped=fs.readFileSync('/proc/self/maps','utf8').split('\n').filter(l=>l.includes('libvips-cpp.so'));
  assert(mapped.length>0 && mapped.every(l=>l.endsWith(libraryPath)), 'unexpected loaded libvips path');
  const librarySha256=digest(fs.readFileSync(libraryPath));
  assert.equal(librarySha256,pins[mode==='original'?'original_library_sha256':'candidate_library_sha256']);
  const report={mode,librarySha256,targetImage,node:process.version,platform:process.platform,arch:process.arch,versions:sharp.versions,rows,releaseClearance:false,limits:['single linux x64 platform','not a security regression suite','not full application integration','no typography/fonts or animation coverage',...(targetImage?[]:['local runtime not pinned target container'])]};
  fs.writeFileSync(path.join(root,mode+'-results.json'),JSON.stringify(report,null,2)+'\n');
  if(mode==='candidate') {
    const baseline=JSON.parse(fs.readFileSync(path.join(root,'original-results.json')));
    assert.deepEqual(sharp.versions,baseline.versions,'library version inventory changed');
    assert.deepEqual(rows.filter(r=>r.operation!=='encode-decode'),baseline.rows,'candidate decoded pixels differ from published-library baseline');
  }
  console.log(mode+': '+rows.length+' ordinary checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
