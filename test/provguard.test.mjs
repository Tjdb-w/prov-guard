// Prov Guard 端到端测试：以子进程方式驱动 provguard.mjs CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { sign as cryptoSign, createPrivateKey } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
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
