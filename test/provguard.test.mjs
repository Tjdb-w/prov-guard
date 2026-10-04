// Prov Guard 端到端测试：以子进程方式驱动 provguard.mjs CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { sign as cryptoSign, createPrivateKey } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { stableJsonStringify } from '../provguard.mjs';

const CLI = fileURLToPath(new URL('../provguard.mjs', import.meta.url));

let root;
let paths;

function makeTree() {
  const art = join(root, 'art');
  mkdirSync(join(art, 'sub', 'deep'), { recursive: true });
  mkdirSync(join(art, 'emptydir'));
  writeFileSync(join(art, 'a.txt'), 'hello world\n');
  writeFileSync(join(art, 'empty.bin'), Buffer.alloc(0));
  writeFileSync(join(art, 'sub', 'b.txt'), 'nested\n');
  writeFileSync(join(art, 'sub', 'deep', 'c.bin'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]));
  return art;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'provguard-test-'));
  const art = makeTree();
  paths = { art, keys: join(root, 'keys'), out: join(root, 'attest'), keys2: join(root, 'keys2') };
});

afterEach(() => {
  // 测试可能 chmod 000，先恢复再删除。
  chmodSafe(join(paths.out, 'proof.json'));
  rmSync(root, { recursive: true, force: true });
});

function chmodSafe(p) {
  try {
    chmodSync(p, 0o644);
  } catch {
    /* ignore */
  }
}

function run(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  let stdout = null;
  let stderr = null;
  try {
    stdout = res.stdout.trim() ? JSON.parse(res.stdout) : null;
  } catch {
    stdout = { _unparsed: res.stdout };
  }
  try {
    stderr = res.stderr.trim() ? JSON.parse(res.stderr) : null;
  } catch {
    stderr = { _unparsed: res.stderr };
  }
  return { code: res.status, stdout, stderr };
}

function keygen(dir) {
  const r = run(['keygen', '--key-dir', dir]);
  assert.equal(r.code, 0, r.stderr);
  return {
    priv: join(dir, 'provguard.private.pem'),
    pub: join(dir, 'provguard.public.pem'),
  };
}

function generate(artifact, key, out) {
  const r = run(['generate', '--artifact', artifact, '--key', key, '--out', out]);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  return r.stdout;
}

function verify(artifact, out, pub, overrides = {}) {
  return run([
    'verify',
    '--artifact', overrides.artifact ?? artifact,
    '--proof', overrides.proof ?? join(out, 'proof.json'),
    '--signature', overrides.signature ?? join(out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
  ]);
}

function verifyWithSbom(artifact, out, pub, overrides = {}) {
  return run([
    'verify',
    '--artifact', overrides.artifact ?? artifact,
    '--proof', overrides.proof ?? join(out, 'proof.json'),
    '--signature', overrides.signature ?? join(out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
    '--sbom', overrides.sbom ?? join(out, 'sbom.json'),
    '--sbom-signature', overrides.sbomSignature ?? join(out, 'sbom.json.sig'),
  ]);
}

// ---------------------------------------------------------------------------

test('keygen 生成可用的 Ed25519 密钥对', () => {
  const k = keygen(paths.keys);
  const priv = readFileSync(k.priv, 'utf8');
  const pub = readFileSync(k.pub, 'utf8');
  assert.match(priv, /PRIVATE KEY/);
  assert.match(pub, /PUBLIC KEY/);
});

test('完整往返：生成并验证成功，输出 VERIFIED 与约定字段', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.status, 'GENERATED');
  assert.equal(g.fileCount, 4); // 空目录不计文件
  assert.match(g.artifactDigest, /^[0-9a-f]{64}$/);

  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0);
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.proofVersion, '1.0');
  assert.equal(v.stdout.artifactDigest, g.artifactDigest);
  assert.equal(v.stdout.fileCount, 4);
});

test('产物字节被修改 -> INTEGRITY_MISMATCH，携带差异路径', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  const mm = v.stderr.details.mismatches;
  assert.ok(mm.some((m) => m.path === 'a.txt' && m.kind === 'content-modified'));
});

test('新增文件 -> INTEGRITY_MISMATCH / added', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  writeFileSync(join(paths.art, 'new.txt'), 'x');
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'new.txt' && m.kind === 'added'));
});

test('删除文件 -> INTEGRITY_MISMATCH / missing', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  rmSync(join(paths.art, 'empty.bin'));
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'empty.bin' && m.kind === 'missing'));
});

test('错误公钥 -> KEY_NOT_FOUND（区别于签名失配）', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generate(paths.art, k.priv, paths.out);
  const v = verify(paths.art, paths.out, k2.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'KEY_NOT_FOUND');
});

test('证明体被改动但公钥正确 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proofPath = join(paths.out, 'proof.json');
  const proof = JSON.parse(readFileSync(proofPath, 'utf8'));
  proof.generatedAt = '2000-01-01T00:00:00.000Z';
  writeFileSync(proofPath, JSON.stringify(proof, null, 2) + '\n');
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('签名文件非 Base64 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'bad.sig');
  writeFileSync(bad, '!!! not base64 !!!');
  const v = verify(paths.art, paths.out, k.pub, { signature: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('签名长度非法 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'short.sig');
  writeFileSync(bad, Buffer.from('too-short').toString('base64'));
  const v = verify(paths.art, paths.out, k.pub, { signature: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('签名被替换为另一产物的合法签名 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const otherOut = join(root, 'other');
  mkdirSync(join(root, 'art2'));
  writeFileSync(join(root, 'art2', 'x.txt'), 'different content');
  generate(join(root, 'art2'), k.priv, otherOut);
  // 用 art2 的签名冒充 art 的签名；同公钥故指纹一致，验签必失败。
  const v = verify(paths.art, paths.out, k.pub, { signature: join(otherOut, 'proof.json.sig') });
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('证明文件不是合法 JSON -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'badproof.json');
  writeFileSync(bad, '{broken');
  const v = verify(paths.art, paths.out, k.pub, { proof: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('证明缺字段 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'missing.json');
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  delete proof.artifactDigest;
  writeFileSync(bad, JSON.stringify(proof));
  const v = verify(paths.art, paths.out, k.pub, { proof: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('各输入路径不存在 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  assert.equal(verify(paths.art, paths.out, k.pub, { artifact: join(root, 'nope') }).stderr.errorCode, 'INPUT_NOT_FOUND');
  assert.equal(verify(paths.art, paths.out, k.pub, { proof: join(root, 'nope.json') }).stderr.errorCode, 'INPUT_NOT_FOUND');
  assert.equal(verify(paths.art, paths.out, k.pub, { signature: join(root, 'nope.sig') }).stderr.errorCode, 'INPUT_NOT_FOUND');
  assert.equal(verify(paths.art, paths.out, k.pub, { key: join(root, 'nope.pem') }).stderr.errorCode, 'INPUT_NOT_FOUND');
});

test('不可解析的公钥 -> KEY_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'bad.pem');
  writeFileSync(bad, 'not a key');
  const v = verify(paths.art, paths.out, k.pub, { key: bad });
  assert.equal(v.stderr.errorCode, 'KEY_NOT_FOUND');
});

test('生成时使用不可解析的私钥 -> KEY_NOT_FOUND', () => {
  const bad = join(root, 'badpriv.pem');
  writeFileSync(bad, 'not a key');
  const r = run(['generate', '--artifact', paths.art, '--key', bad, '--out', paths.out]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'KEY_NOT_FOUND');
});

test('SBOM 确定性：时间变化不影响清单与产物摘要', () => {
  const k = keygen(paths.keys);
  const o1 = join(root, 'd1');
  const o2 = join(root, 'd2');
  generate(paths.art, k.priv, o1);
  generate(paths.art, k.priv, o2);
  const sbom1 = JSON.parse(readFileSync(join(o1, 'sbom.json'), 'utf8'));
  const sbom2 = JSON.parse(readFileSync(join(o2, 'sbom.json'), 'utf8'));
  assert.deepEqual(sbom1, sbom2);
  const p1 = JSON.parse(readFileSync(join(o1, 'proof.json'), 'utf8'));
  const p2 = JSON.parse(readFileSync(join(o2, 'proof.json'), 'utf8'));
  assert.deepEqual(p1.files, p2.files);
  assert.equal(p1.artifactDigest, p2.artifactDigest);
});

test('零字节文件按真实文件记录（摘要为 SHA256 空值）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const sbom = JSON.parse(readFileSync(join(paths.out, 'sbom.json'), 'utf8'));
  const empty = sbom.files.find((f) => f.path === 'empty.bin');
  assert.equal(empty.size, 0);
  assert.equal(empty.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('相对路径使用正斜杠并按路径排序', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const sbom = JSON.parse(readFileSync(join(paths.out, 'sbom.json'), 'utf8'));
  const listed = sbom.files.map((f) => f.path);
  for (const p of listed) assert.ok(!p.includes('\\'), `路径含反斜杠: ${p}`);
  const sorted = [...listed].sort();
  assert.deepEqual(listed, sorted);
  assert.ok(listed.includes('sub/deep/c.bin'));
});

test('JSON 使用两空格缩进', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const text = readFileSync(join(paths.out, 'sbom.json'), 'utf8');
  assert.match(text, /\n {2}"files"/);
});

test('单文件产物可生成并验证', () => {
  const k = keygen(paths.keys);
  const file = join(root, 'one.bin');
  writeFileSync(file, 'single payload');
  const out = join(root, 'one-out');
  const g = run(['generate', '--artifact', file, '--key', k.priv, '--out', out]);
  assert.equal(g.code, 0, JSON.stringify(g.stderr));
  const v = run([
    'verify', '--artifact', file,
    '--proof', join(out, 'proof.json'),
    '--signature', join(out, 'proof.json.sig'),
    '--key', k.pub,
  ]);
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.fileCount, 1);
});

test('输出目录位于产物内部时被排除，验证仍通过', () => {
  const k = keygen(paths.keys);
  const outInside = join(paths.art, '_attest');
  generate(paths.art, k.priv, outInside);
  const sbom = JSON.parse(readFileSync(join(outInside, 'sbom.json'), 'utf8'));
  assert.ok(!sbom.files.some((f) => f.path.startsWith('_attest/')));
  const v = verify(paths.art, outInside, k.pub);
  assert.equal(v.stdout.status, 'VERIFIED');
});

test('缺少必填参数 -> USAGE_ERROR 且非零退出', () => {
  const r = run(['generate', '--artifact', paths.art]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'USAGE_ERROR');
});

test('未知子命令 -> USAGE_ERROR', () => {
  const r = run(['frobnicate']);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'USAGE_ERROR');
});

// ---------------------------------------------------------------------------
// SBOM 签名保护
// ---------------------------------------------------------------------------

test('generate 产出 sbom.json.sig，proof 记录 sbomDigest，输出含 sbomSignaturePath', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.ok(g.sbomSignaturePath.endsWith('sbom.json.sig'));

  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.match(proof.sbomDigest, /^[0-9a-f]{64}$/);

  const sigText = readFileSync(join(paths.out, 'sbom.json.sig'), 'utf8');
  assert.match(sigText, /^[A-Za-z0-9+/=]+\n$/);
  assert.equal(Buffer.from(sigText.trim(), 'base64').length, 64);
});

test('verify 启用 SBOM 校验：成功并输出 sbomDigest', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  const v = verifyWithSbom(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.artifactDigest, g.artifactDigest);
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(v.stdout.sbomDigest, proof.sbomDigest);
});

test('verify 不带 SBOM 参数时行为不变（stdout 无 sbomDigest）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.ok(!('sbomDigest' in v.stdout));
});

test('--sbom 与 --sbom-signature 只给一者 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const base = [
    'verify',
    '--artifact', paths.art,
    '--proof', join(paths.out, 'proof.json'),
    '--signature', join(paths.out, 'proof.json.sig'),
    '--key', k.pub,
  ];
  const onlySbom = run([...base, '--sbom', join(paths.out, 'sbom.json')]);
  assert.equal(onlySbom.code, 1);
  assert.equal(onlySbom.stderr.errorCode, 'USAGE_ERROR');
  const onlySig = run([...base, '--sbom-signature', join(paths.out, 'sbom.json.sig')]);
  assert.equal(onlySig.code, 1);
  assert.equal(onlySig.stderr.errorCode, 'USAGE_ERROR');
});

test('sbom.json 被替换/改动 -> INTEGRITY_MISMATCH（sbomDigest 不一致）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const sbomPath = join(paths.out, 'sbom.json');
  const sbom = JSON.parse(readFileSync(sbomPath, 'utf8'));
  sbom.files = [];
  writeFileSync(sbomPath, JSON.stringify(sbom, null, 2) + '\n');
  const v = verifyWithSbom(paths.art, paths.out, k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'sbom.json'));
});

test('SBOM 签名与 sbom.json 内容不匹配 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  // proof.json.sig 同为合法 64 字节签名，但签的是证明而非 SBOM。
  const v = verifyWithSbom(paths.art, paths.out, k.pub, {
    sbomSignature: join(paths.out, 'proof.json.sig'),
  });
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('SBOM 签名非 Base64 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'bad-sbom.sig');
  writeFileSync(bad, '!!! not base64 !!!');
  const v = verifyWithSbom(paths.art, paths.out, k.pub, { sbomSignature: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('SBOM 签名长度非法 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'short-sbom.sig');
  writeFileSync(bad, Buffer.from('too-short').toString('base64'));
  const v = verifyWithSbom(paths.art, paths.out, k.pub, { sbomSignature: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('sbom.json 不是合法 JSON -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'bad-sbom.json');
  writeFileSync(bad, '{broken');
  const v = verifyWithSbom(paths.art, paths.out, k.pub, { sbom: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('sbom.json 缺字段 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const bad = join(root, 'missing-sbom.json');
  const sbom = JSON.parse(readFileSync(join(paths.out, 'sbom.json'), 'utf8'));
  delete sbom.rootType;
  writeFileSync(bad, JSON.stringify(sbom));
  const v = verifyWithSbom(paths.art, paths.out, k.pub, { sbom: bad });
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('SBOM 相关路径不存在 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  assert.equal(
    verifyWithSbom(paths.art, paths.out, k.pub, { sbom: join(root, 'nope.json') }).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  assert.equal(
    verifyWithSbom(paths.art, paths.out, k.pub, { sbomSignature: join(root, 'nope.sig') }).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
});

test('SBOM 模式下产物被篡改仍 -> INTEGRITY_MISMATCH', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyWithSbom(paths.art, paths.out, k.pub);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'a.txt' && m.kind === 'content-modified'));
});

// ---------------------------------------------------------------------------
// 策略（--policy）
// ---------------------------------------------------------------------------

function writePolicy(obj, name = 'policy.json') {
  const p = join(root, name);
  writeFileSync(p, JSON.stringify(obj, null, 2));
  return p;
}

function verifyWithPolicy(pub, policyPath, { sbom = false, overrides = {} } = {}) {
  const args = [
    'verify',
    '--artifact', overrides.artifact ?? paths.art,
    '--proof', overrides.proof ?? join(paths.out, 'proof.json'),
    '--signature', overrides.signature ?? join(paths.out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
  ];
  if (sbom) {
    args.push('--sbom', overrides.sbom ?? join(paths.out, 'sbom.json'));
    args.push('--sbom-signature', overrides.sbomSignature ?? join(paths.out, 'sbom.json.sig'));
  }
  args.push('--policy', policyPath);
  return run(args);
}

function readProof() {
  return JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
}

// 用私钥对（可能被改动的）证明重新签名，使签名与完整性步骤通过，
// 从而专门测试策略层对非法 generatedAt 的处理。
function resignProof(proofObj, privPath) {
  const key = createPrivateKey(readFileSync(privPath));
  const canonical = stableJsonStringify(proofObj);
  writeFileSync(join(paths.out, 'proof.json'), `${canonical}\n`);
  writeFileSync(
    join(paths.out, 'proof.json.sig'),
    `${cryptoSign(null, Buffer.from(canonical, 'utf8'), key).toString('base64')}\n`,
  );
}

test('策略通过：VERIFIED 附带 policyStatus=PASS', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof();
  const p = writePolicy({
    policyVersion: '1.0',
    proofNotBefore: '2000-01-01T00:00:00Z',
    proofNotAfter: '2099-01-01T00:00:00Z',
    allowedKeyFingerprints: [proof.signerKeyFingerprint],
    requireSbom: false,
    maxFileCount: 4,
    maxSize: proof.size,
  });
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('不传 --policy 时输出不含 policyStatus（行为不变）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0);
  assert.ok(!('policyStatus' in v.stdout));
});

test('时间窗口为闭区间：边界相等通过，越界按 proof-not-before/proof-not-after 违规', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const ts = readProof().generatedAt;
  const t = new Date(ts).getTime();
  const iso = (ms) => new Date(ms).toISOString();

  const onBounds = writePolicy(
    { policyVersion: '1.0', proofNotBefore: ts, proofNotAfter: ts },
    'policy-bounds.json',
  );
  assert.equal(verifyWithPolicy(k.pub, onBounds).code, 0);

  const tooEarly = writePolicy(
    { policyVersion: '1.0', proofNotBefore: iso(t + 1) },
    'policy-early.json',
  );
  const r1 = verifyWithPolicy(k.pub, tooEarly);
  assert.equal(r1.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(r1.stderr.details.violations, [{ rule: 'proof-not-before', observed: ts }]);

  const tooLate = writePolicy(
    { policyVersion: '1.0', proofNotAfter: iso(t - 1) },
    'policy-late.json',
  );
  const r2 = verifyWithPolicy(k.pub, tooLate);
  assert.equal(r2.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(r2.stderr.details.violations, [{ rule: 'proof-not-after', observed: ts }]);
});

test('密钥指纹白名单：命中通过（大小写不敏感），未命中违规', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const fp = readProof().signerKeyFingerprint;

  const upper = writePolicy(
    { policyVersion: '1.0', allowedKeyFingerprints: [fp.toUpperCase()] },
    'policy-upper.json',
  );
  assert.equal(verifyWithPolicy(k.pub, upper).code, 0);

  const other = 'a'.repeat(64);
  const mismatch = writePolicy(
    { policyVersion: '1.0', allowedKeyFingerprints: [other] },
    'policy-other.json',
  );
  const v = verifyWithPolicy(k.pub, mismatch);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'allowed-key-fingerprints', observed: fp },
  ]);
});

test('requireSbom：缺 SBOM 违规；成对提供且有效时通过；为 false 不禁止额外 SBOM', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);

  const required = writePolicy({ policyVersion: '1.0', requireSbom: true }, 'policy-req.json');
  const v1 = verifyWithPolicy(k.pub, required);
  assert.equal(v1.code, 1);
  assert.equal(v1.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v1.stderr.details.violations, [{ rule: 'require-sbom', observed: 'absent' }]);

  assert.equal(verifyWithPolicy(k.pub, required, { sbom: true }).code, 0);

  const optional = writePolicy({ policyVersion: '1.0', requireSbom: false }, 'policy-opt.json');
  const v3 = verifyWithPolicy(k.pub, optional, { sbom: true });
  assert.equal(v3.code, 0, JSON.stringify(v3.stderr));
  assert.equal(v3.stdout.policyStatus, 'PASS');
  assert.equal(v3.stdout.sbomDigest, readProof().sbomDigest);
});

test('文件数与大小上限：等于上限通过，超出违规', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof();
  assert.equal(proof.files.length, 4);

  const exact = writePolicy(
    { policyVersion: '1.0', maxFileCount: 4, maxSize: proof.size },
    'policy-exact.json',
  );
  assert.equal(verifyWithPolicy(k.pub, exact).code, 0);

  const over = writePolicy(
    { policyVersion: '1.0', maxFileCount: 3, maxSize: proof.size - 1 },
    'policy-over.json',
  );
  const v = verifyWithPolicy(k.pub, over);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'max-file-count', observed: 4 },
    { rule: 'max-size', observed: proof.size },
  ]);
});

test('多项违规按 时间→密钥→SBOM→文件数→大小 排序', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({
    policyVersion: '1.0',
    proofNotBefore: '2099-01-01T00:00:00Z',
    allowedKeyFingerprints: ['a'.repeat(64)],
    requireSbom: true,
    maxFileCount: 0,
    maxSize: 0,
  });
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(
    v.stderr.details.violations.map((x) => x.rule),
    ['proof-not-before', 'allowed-key-fingerprints', 'require-sbom', 'max-file-count', 'max-size'],
  );
});

test('proof.generatedAt 非法时间 -> generated-at-invalid（签名仍有效）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof();
  proof.generatedAt = 'not-a-timestamp';
  resignProof(proof, k.priv);

  const p = writePolicy({
    policyVersion: '1.0',
    proofNotBefore: '2000-01-01T00:00:00Z',
    proofNotAfter: '2099-01-01T00:00:00Z',
  });
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'generated-at-invalid', observed: 'not-a-timestamp' },
  ]);
});

test('策略文件非法 -> POLICY_INVALID（不输出部分成功）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const cases = [
    ['{broken', 'not-json'],
    ['[1,2,3]', 'array'],
    [JSON.stringify({ policyVersion: '1.0', unknown: 1 }), 'unknown-field'],
    [JSON.stringify({ proofNotBefore: '2020-01-01T00:00:00Z' }), 'missing-version'],
    [JSON.stringify({ policyVersion: '2.0' }), 'bad-version'],
    [JSON.stringify({ policyVersion: '1.0', proofNotBefore: 123 }), 'bad-time-type'],
    [JSON.stringify({ policyVersion: '1.0', proofNotBefore: '2020-13-01T00:00:00Z' }), 'bad-time-value'],
    [JSON.stringify({ policyVersion: '1.0', proofNotBefore: '2020-01-01 00:00:00' }), 'non-utc'],
    [JSON.stringify({ policyVersion: '1.0', allowedKeyFingerprints: [] }), 'empty-fps'],
    [JSON.stringify({ policyVersion: '1.0', allowedKeyFingerprints: 'nope' }), 'fps-not-array'],
    [JSON.stringify({ policyVersion: '1.0', allowedKeyFingerprints: ['z'.repeat(64)] }), 'bad-fp'],
    [JSON.stringify({ policyVersion: '1.0', requireSbom: 'yes' }), 'bad-bool'],
    [JSON.stringify({ policyVersion: '1.0', maxFileCount: -1 }), 'negative-count'],
    [JSON.stringify({ policyVersion: '1.0', maxFileCount: 1.5 }), 'non-integer'],
    [JSON.stringify({ policyVersion: '1.0', maxSize: '1' }), 'bad-size-type'],
    [
      JSON.stringify({
        policyVersion: '1.0',
        proofNotBefore: '2021-01-01T00:00:00Z',
        proofNotAfter: '2020-01-01T00:00:00Z',
      }),
      'inverted-range',
    ],
  ];
  for (const [content, name] of cases) {
    const p = writePolicy(content, `policy-${name}.json`);
    const v = verifyWithPolicy(k.pub, p);
    assert.equal(v.code, 1, name);
    assert.equal(v.stderr.errorCode, 'POLICY_INVALID', `${name}: ${JSON.stringify(v.stderr)}`);
    assert.equal(v.stdout, null, name);
  }
});

test('策略文件缺失 -> INPUT_NOT_FOUND；不可读 -> PERMISSION_DENIED', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v1 = verifyWithPolicy(k.pub, join(root, 'nope-policy.json'));
  assert.equal(v1.stderr.errorCode, 'INPUT_NOT_FOUND');

  // root 用户绕过文件权限，无法构造不可读场景；跳过该断言。
  if (typeof process.getuid === 'function' && process.getuid() === 0) return;
  const p = writePolicy({ policyVersion: '1.0' }, 'locked.json');
  chmodSync(p, 0o000);
  try {
    const v2 = verifyWithPolicy(k.pub, p);
    assert.equal(v2.code, 1);
    assert.equal(v2.stderr.errorCode, 'PERMISSION_DENIED');
  } finally {
    chmodSync(p, 0o644);
  }
});

test('伪造/篡改优先于策略：按原错误码返回，不进入策略评估', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({
    policyVersion: '1.0',
    allowedKeyFingerprints: ['a'.repeat(64)],
    requireSbom: true,
    maxFileCount: 0,
    maxSize: 0,
  });

  // 产物被篡改 -> INTEGRITY_MISMATCH（即使策略必然违规）。
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  assert.equal(verifyWithPolicy(k.pub, p).stderr.errorCode, 'INTEGRITY_MISMATCH');
  writeFileSync(join(paths.art, 'a.txt'), 'hello world\n');

  // 错误公钥 -> KEY_NOT_FOUND。
  assert.equal(verifyWithPolicy(k2.pub, p).stderr.errorCode, 'KEY_NOT_FOUND');

  // 证明改动未重签 -> SIGNATURE_INVALID。
  const proof = readProof();
  proof.generatedAt = '2000-01-01T00:00:00.000Z';
  writeFileSync(join(paths.out, 'proof.json'), JSON.stringify(proof, null, 2) + '\n');
  assert.equal(verifyWithPolicy(k.pub, p).stderr.errorCode, 'SIGNATURE_INVALID');
});

test('--policy 缺少路径 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = run([
    'verify',
    '--artifact', paths.art,
    '--proof', join(paths.out, 'proof.json'),
    '--signature', join(paths.out, 'proof.json.sig'),
    '--key', k.pub,
    '--policy',
  ]);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'USAGE_ERROR');
});

// ---------------------------------------------------------------------------
// 符号链接安全（SYMLINK_INVALID）
// ---------------------------------------------------------------------------

test('generate：符号链接越出产物根目录 -> SYMLINK_INVALID / outside-root，且不写出任何证明', () => {
  const k = keygen(paths.keys);
  writeFileSync(join(root, 'secret.txt'), 'top secret');
  symlinkSync(join(root, 'secret.txt'), join(paths.art, 'leak.txt'));
  const r = run(['generate', '--artifact', paths.art, '--key', k.priv, '--out', paths.out]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.status, 'ERROR');
  assert.equal(r.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(r.stderr.details.reason, 'outside-root');
  assert.equal(r.stderr.details.path, 'leak.txt');
  assert.equal(r.stdout, null);
  // 失败发生在写出任何证明之前。
  for (const f of ['proof.json', 'proof.json.sig', 'sbom.json', 'sbom.json.sig']) {
    assert.ok(!existsSync(join(paths.out, f)), `不应写出 ${f}`);
  }
});

test('generate：指向根目录自身的符号链接 -> SYMLINK_INVALID / cycle', () => {
  const k = keygen(paths.keys);
  symlinkSync('.', join(paths.art, 'loop'));
  const r = run(['generate', '--artifact', paths.art, '--key', k.priv, '--out', paths.out]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(r.stderr.details.reason, 'cycle');
  assert.equal(r.stderr.details.path, 'loop');
});

test('generate：子目录内指回上级的符号链接 -> SYMLINK_INVALID / cycle（相对路径为链接路径）', () => {
  const k = keygen(paths.keys);
  symlinkSync('..', join(paths.art, 'sub', 'up'));
  const r = run(['generate', '--artifact', paths.art, '--key', k.priv, '--out', paths.out]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(r.stderr.details.reason, 'cycle');
  assert.equal(r.stderr.details.path, 'sub/up');
});

test('generate：符号链接互相指向成环（ELOOP）-> SYMLINK_INVALID / cycle', () => {
  const k = keygen(paths.keys);
  symlinkSync('b', join(paths.art, 'a'));
  symlinkSync('a', join(paths.art, 'b'));
  const r = run(['generate', '--artifact', paths.art, '--key', k.priv, '--out', paths.out]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(r.stderr.details.reason, 'cycle');
  assert.ok(['a', 'b'].includes(r.stderr.details.path));
});

test('verify：签名有效后扫描阶段发现越界链接 -> SYMLINK_INVALID（非 INTEGRITY_MISMATCH）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  writeFileSync(join(root, 'secret.txt'), 'top secret');
  symlinkSync(join(root, 'secret.txt'), join(paths.art, 'leak.txt'));
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(v.stderr.details.reason, 'outside-root');
  assert.equal(v.stderr.details.path, 'leak.txt');
});

test('verify：签名有效后扫描阶段发现回路链接 -> SYMLINK_INVALID / cycle', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  symlinkSync('.', join(paths.art, 'loop'));
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(v.stderr.details.reason, 'cycle');
});

test('安全的内部符号链接：按链接路径记录目标内容，生成/验证稳定一致', () => {
  const k = keygen(paths.keys);
  symlinkSync('a.txt', join(paths.art, 'alias.txt')); // 指向内部普通文件
  symlinkSync('sub', join(paths.art, 'subdir-link')); // 指向内部目录
  const o1 = join(root, 's1');
  const o2 = join(root, 's2');
  const g1 = generate(paths.art, k.priv, o1);
  const g2 = generate(paths.art, k.priv, o2);
  assert.equal(g1.status, 'GENERATED');
  assert.equal(g1.artifactDigest, g2.artifactDigest); // 相同安全产物结果稳定
  assert.equal(g1.fileCount, 7); // 原 4 个 + 链接文件 1 个 + 链接目录展开 2 个

  const sbom = JSON.parse(readFileSync(join(o1, 'sbom.json'), 'utf8'));
  const alias = sbom.files.find((f) => f.path === 'alias.txt');
  const orig = sbom.files.find((f) => f.path === 'a.txt');
  assert.equal(alias.sha256, orig.sha256);
  assert.equal(alias.size, orig.size);
  assert.ok(sbom.files.some((f) => f.path === 'subdir-link/b.txt'));
  assert.ok(sbom.files.some((f) => f.path === 'subdir-link/deep/c.bin'));

  const v = verify(paths.art, o1, k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.artifactDigest, g1.artifactDigest);
  assert.equal(v.stdout.fileCount, 7);
});

test('两个链接指向同一内部目录（非回路）：均按链接路径记录且不报错', () => {
  const k = keygen(paths.keys);
  symlinkSync('sub', join(paths.art, 'link1'));
  symlinkSync('sub', join(paths.art, 'link2'));
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.status, 'GENERATED');
  const sbom = JSON.parse(readFileSync(join(paths.out, 'sbom.json'), 'utf8'));
  assert.ok(sbom.files.some((f) => f.path === 'link1/b.txt'));
  assert.ok(sbom.files.some((f) => f.path === 'link2/b.txt'));
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.stdout.status, 'VERIFIED');
});

// ---------------------------------------------------------------------------
// 多方共签（--co-key / --cosignatures / --cosigner-key / --min-cosigners）
// ---------------------------------------------------------------------------

function keygenNamed(dir, name) {
  const r = run(['keygen', '--key-dir', dir, '--name', name]);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  return {
    priv: join(dir, `${name}.private.pem`),
    pub: join(dir, `${name}.public.pem`),
  };
}

function generateCosign(artifact, mainPriv, coPrivs, out) {
  const args = ['generate', '--artifact', artifact, '--key', mainPriv, '--out', out];
  for (const c of coPrivs) args.push('--co-key', c);
  return run(args);
}

function verifyCosign(artifact, out, pub, cosigDir, cosignerPubs, min, overrides = {}) {
  const args = [
    'verify',
    '--artifact', overrides.artifact ?? artifact,
    '--proof', overrides.proof ?? join(out, 'proof.json'),
    '--signature', overrides.signature ?? join(out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
  ];
  if (overrides.sbom) args.push('--sbom', overrides.sbom);
  if (overrides.sbomSignature) args.push('--sbom-signature', overrides.sbomSignature);
  if (cosigDir !== null) args.push('--cosignatures', cosigDir);
  for (const p of cosignerPubs) args.push('--cosigner-key', p);
  if (min !== null) args.push('--min-cosigners', String(min));
  if (overrides.policy) args.push('--policy', overrides.policy);
  return run(args);
}

// 生成主密钥 + 两把共签密钥并产出共签证明；返回各路径与指纹。
function setupCosign(coNames = ['a', 'b']) {
  const main = keygenNamed(join(root, 'k-main'), 'main');
  const cos = coNames.map((n) => keygenNamed(join(root, `k-${n}`), n));
  const g = generateCosign(paths.art, main.priv, cos.map((c) => c.priv), paths.out);
  assert.equal(g.code, 0, JSON.stringify(g.stderr));
  return { main, cos, gen: g.stdout };
}

test('共签往返：proof 1.1、声明升序去重、两份清单结构正确，verify 输出 cosignerCount', () => {
  const { main, cos, gen } = setupCosign();
  assert.equal(gen.proofVersion, '1.1');
  assert.equal(gen.cosignerCount, 2);

  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(proof.proofVersion, '1.1');
  assert.ok(Array.isArray(proof.cosignerKeyFingerprints));
  const sorted = [...proof.cosignerKeyFingerprints].sort();
  assert.deepEqual(proof.cosignerKeyFingerprints, sorted);
  assert.equal(new Set(proof.cosignerKeyFingerprints).size, 2);
  assert.ok(!proof.cosignerKeyFingerprints.includes(proof.signerKeyFingerprint));

  for (const name of ['proof.cosignatures.json', 'sbom.cosignatures.json']) {
    const m = JSON.parse(readFileSync(join(paths.out, name), 'utf8'));
    assert.equal(m.schemaVersion, '1.0');
    assert.equal(m.artifactDigest, proof.artifactDigest);
    assert.equal(m.sbomDigest, proof.sbomDigest);
    assert.deepEqual(m.signers.map((s) => s.keyFingerprint), sorted);
    for (const s of m.signers) {
      assert.equal(Buffer.from(s.signature, 'base64').length, 64);
    }
  }

  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, cos.map((c) => c.pub), 2);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 2);
  assert.equal(v.stdout.proofVersion, '1.1');
});

test('缺省不共签：proofVersion 1.0、无声明字段、不创建共签清单，旧行为不变', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.proofVersion, '1.0');
  assert.ok(!('proofCosignaturesPath' in g));
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(proof.proofVersion, '1.0');
  assert.ok(!('cosignerKeyFingerprints' in proof));
  for (const f of ['proof.cosignatures.json', 'sbom.cosignatures.json']) {
    assert.ok(!existsSync(join(paths.out, f)), `不应创建 ${f}`);
  }
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0);
  assert.ok(!('cosignerCount' in v.stdout));
});

test('重复 --co-key 或与主密钥相同 -> USAGE_ERROR', () => {
  const main = keygenNamed(join(root, 'k-main'), 'main');
  const a = keygenNamed(join(root, 'k-a'), 'a');
  const dup = generateCosign(paths.art, main.priv, [a.priv, a.priv], paths.out);
  assert.equal(dup.code, 1);
  assert.equal(dup.stderr.errorCode, 'USAGE_ERROR');
  const sameAsMain = generateCosign(paths.art, main.priv, [main.priv], paths.out);
  assert.equal(sameAsMain.code, 1);
  assert.equal(sameAsMain.stderr.errorCode, 'USAGE_ERROR');
});

test('共签参数组缺一 -> USAGE_ERROR；min 非正整数或超过公钥数 -> USAGE_ERROR', () => {
  const { main, cos } = setupCosign();
  // 缺少 --cosigner-key
  assert.equal(verifyCosign(paths.art, paths.out, main.pub, paths.out, [], 1).stderr.errorCode, 'USAGE_ERROR');
  // 缺少 --cosignatures
  assert.equal(verifyCosign(paths.art, paths.out, main.pub, null, [cos[0].pub], 1).stderr.errorCode, 'USAGE_ERROR');
  // 缺少 --min-cosigners
  assert.equal(verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], null).stderr.errorCode, 'USAGE_ERROR');
  // min = 0
  assert.equal(verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], 0).stderr.errorCode, 'USAGE_ERROR');
  // min 超过公钥数
  assert.equal(verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], 2).stderr.errorCode, 'USAGE_ERROR');
});

test('min 阈值：达到 min 即通过，cosignerCount 为有效共签数', () => {
  const { main, cos } = setupCosign(['a', 'b', 'c']);
  const v1 = verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], 1);
  assert.equal(v1.code, 0, JSON.stringify(v1.stderr));
  assert.equal(v1.stdout.cosignerCount, 1);
  const v2 = verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub, cos[2].pub], 2);
  assert.equal(v2.code, 0, JSON.stringify(v2.stderr));
  assert.equal(v2.stdout.cosignerCount, 2);
});

test('未声明的共签公钥 -> KEY_NOT_FOUND', () => {
  const { main, cos } = setupCosign();
  const stranger = keygenNamed(join(root, 'k-stranger'), 'stranger');
  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, [stranger.pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'KEY_NOT_FOUND');
  // 主公钥不是声明的共签者
  const v2 = verifyCosign(paths.art, paths.out, main.pub, paths.out, [main.pub], 1);
  assert.equal(v2.stderr.errorCode, 'KEY_NOT_FOUND');
  assert.ok(cos.length > 0);
});

test('共签签名被篡改 -> SIGNATURE_INVALID', () => {
  const { main, cos } = setupCosign();
  const badDir = join(root, 'badcosig');
  mkdirSync(badDir);
  const m = JSON.parse(readFileSync(join(paths.out, 'proof.cosignatures.json'), 'utf8'));
  // signers 按指纹排序，与密钥生成顺序无关；全部篡改以确保所验公钥命中。
  for (const s of m.signers) s.signature = Buffer.alloc(64).toString('base64');
  writeFileSync(join(badDir, 'proof.cosignatures.json'), JSON.stringify(m, null, 2));
  writeFileSync(
    join(badDir, 'sbom.cosignatures.json'),
    readFileSync(join(paths.out, 'sbom.cosignatures.json')),
  );
  const v = verifyCosign(paths.art, paths.out, main.pub, badDir, [cos[0].pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('重复 --cosigner-key 去重后有效数不足 min -> SIGNATURE_INVALID', () => {
  const { main, cos } = setupCosign();
  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub, cos[0].pub], 2);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('共签清单缺失 -> INPUT_NOT_FOUND', () => {
  const { main, cos } = setupCosign();
  rmSync(join(paths.out, 'sbom.cosignatures.json'));
  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INPUT_NOT_FOUND');
});

test('清单含主签名指纹或签名者集合与声明不一致 -> PROOF_INVALID', () => {
  const { main, cos } = setupCosign();
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));

  // 清单中加入主签名者指纹
  const badDir = join(root, 'mainfp');
  mkdirSync(badDir);
  const m = JSON.parse(readFileSync(join(paths.out, 'proof.cosignatures.json'), 'utf8'));
  m.signers.push({ keyFingerprint: proof.signerKeyFingerprint, signature: m.signers[0].signature });
  m.signers.sort((x, y) => (x.keyFingerprint < y.keyFingerprint ? -1 : 1));
  writeFileSync(join(badDir, 'proof.cosignatures.json'), JSON.stringify(m, null, 2));
  writeFileSync(join(badDir, 'sbom.cosignatures.json'), readFileSync(join(paths.out, 'sbom.cosignatures.json')));
  const v1 = verifyCosign(paths.art, paths.out, main.pub, badDir, [cos[0].pub], 1);
  assert.equal(v1.stderr.errorCode, 'PROOF_INVALID');

  // 清单签名者集合与证明声明不一致（删掉一个共签者）
  const badDir2 = join(root, 'setmismatch');
  mkdirSync(badDir2);
  const m2 = JSON.parse(readFileSync(join(paths.out, 'proof.cosignatures.json'), 'utf8'));
  m2.signers = m2.signers.slice(1);
  writeFileSync(join(badDir2, 'proof.cosignatures.json'), JSON.stringify(m2, null, 2));
  writeFileSync(join(badDir2, 'sbom.cosignatures.json'), readFileSync(join(paths.out, 'sbom.cosignatures.json')));
  const v2 = verifyCosign(paths.art, paths.out, main.pub, badDir2, [cos[0].pub], 1);
  assert.equal(v2.stderr.errorCode, 'PROOF_INVALID');
});

test('产物变化优先于共签错误 -> INTEGRITY_MISMATCH', () => {
  const { main, cos } = setupCosign();
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, [cos[0].pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
});

test('共签与 SBOM、策略组合：全部通过后输出 cosignerCount 与 policyStatus', () => {
  const { main, cos } = setupCosign();
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  const policy = writePolicy({
    policyVersion: '1.0',
    allowedKeyFingerprints: [proof.signerKeyFingerprint],
  });
  const v = verifyCosign(paths.art, paths.out, main.pub, paths.out, cos.map((c) => c.pub), 2, {
    sbom: join(paths.out, 'sbom.json'),
    sbomSignature: join(paths.out, 'sbom.json.sig'),
    policy,
  });
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 2);
  assert.equal(v.stdout.sbomDigest, proof.sbomDigest);
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('共签失败优先于策略评估（不进入策略）', () => {
  const { main, cos } = setupCosign();
  const badDir = join(root, 'badcosig2');
  mkdirSync(badDir);
  const m = JSON.parse(readFileSync(join(paths.out, 'proof.cosignatures.json'), 'utf8'));
  for (const s of m.signers) s.signature = Buffer.alloc(64).toString('base64');
  writeFileSync(join(badDir, 'proof.cosignatures.json'), JSON.stringify(m, null, 2));
  writeFileSync(join(badDir, 'sbom.cosignatures.json'), readFileSync(join(paths.out, 'sbom.cosignatures.json')));
  // 策略必然违规，但共签错误应先返回。
  const policy = writePolicy({ policyVersion: '1.0', maxFileCount: 0 });
  const v = verifyCosign(paths.art, paths.out, main.pub, badDir, [cos[0].pub], 1, { policy });
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('1.0 旧证明配合共签参数：清单缺失 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  const a = keygenNamed(join(root, 'k-a'), 'a');
  generate(paths.art, k.priv, paths.out); // 1.0 证明，无共签清单
  const v = verifyCosign(paths.art, paths.out, k.pub, paths.out, [a.pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INPUT_NOT_FOUND');
});
