// Prov Guard 端到端测试：以子进程方式驱动 provguard.mjs CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { sign as cryptoSign, createPrivateKey, createHash } from 'node:crypto';
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
// 多方共签（generate --co-key；verify --cosignatures/--cosigner-key/--min-cosigners）
// ---------------------------------------------------------------------------

function generateWithCoKeys(artifact, mainPriv, out, coPrivs) {
  const args = ['generate', '--artifact', artifact, '--key', mainPriv, '--out', out];
  for (const p of coPrivs) args.push('--co-key', p);
  const r = run(args);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  return r.stdout;
}

function verifyWithCosign(artifact, out, pub, coPubs, min, overrides = {}) {
  const args = [
    'verify',
    '--artifact', overrides.artifact ?? artifact,
    '--proof', overrides.proof ?? join(out, 'proof.json'),
    '--signature', overrides.signature ?? join(out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
  ];
  if (!overrides.skipCosignatures) args.push('--cosignatures', overrides.cosignatures ?? out);
  for (const p of coPubs) args.push('--cosigner-key', p);
  if (min !== undefined) args.push('--min-cosigners', String(min));
  if (overrides.policy) args.push('--policy', overrides.policy);
  return run(args);
}

function setupCosign() {
  const main = keygen(paths.keys);
  const co1 = keygen(join(root, 'co1'));
  const co2 = keygen(join(root, 'co2'));
  return { main, co1, co2 };
}

test('共签往返：proofVersion 1.1、声明升序、双清单结构合法、验证输出 cosignerCount', () => {
  const { main, co1, co2 } = setupCosign();
  const g = generateWithCoKeys(paths.art, main.priv, paths.out, [co2.priv, co1.priv]);
  assert.equal(g.status, 'GENERATED');
  assert.equal(g.proofVersion, '1.1');
  assert.equal(g.cosignerCount, 2);

  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(proof.proofVersion, '1.1');
  assert.ok(Array.isArray(proof.cosignerKeyFingerprints));
  assert.equal(proof.cosignerKeyFingerprints.length, 2);
  const sorted = [...proof.cosignerKeyFingerprints].sort();
  assert.deepEqual(proof.cosignerKeyFingerprints, sorted); // 按指纹升序
  assert.ok(!proof.cosignerKeyFingerprints.includes(proof.signerKeyFingerprint));

  for (const name of ['proof.cosignatures.json', 'sbom.cosignatures.json']) {
    const m = JSON.parse(readFileSync(join(paths.out, name), 'utf8'));
    assert.equal(m.schemaVersion, '1.0');
    assert.equal(m.artifactDigest, g.artifactDigest);
    assert.equal(m.sbomDigest, proof.sbomDigest);
    assert.deepEqual(
      m.signers.map((s) => s.keyFingerprint),
      proof.cosignerKeyFingerprints,
    ); // 集合与证明声明一致且升序
    for (const s of m.signers) assert.match(s.signature, /^[A-Za-z0-9+/]+={0,2}$/);
  }

  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub, co2.pub], 2);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.proofVersion, '1.1');
  assert.equal(v.stdout.cosignerCount, 2);
});

test('缺省不变：无 --co-key 时不创建共签清单，proofVersion 仍为 1.0', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.proofVersion, '1.0');
  assert.equal(g.cosignerCount, undefined);
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(proof.cosignerKeyFingerprints, undefined);
  assert.ok(!existsSync(join(paths.out, 'proof.cosignatures.json')));
  assert.ok(!existsSync(join(paths.out, 'sbom.cosignatures.json')));
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, undefined);
});

test('1.1 证明不带共签参数仍可按原路径验证（无 cosignerCount）', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const v = verify(paths.art, paths.out, main.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.proofVersion, '1.1');
  assert.equal(v.stdout.cosignerCount, undefined);
});

test('重复 --co-key -> USAGE_ERROR', () => {
  const { main, co1 } = setupCosign();
  const r = run([
    'generate', '--artifact', paths.art, '--key', main.priv, '--out', paths.out,
    '--co-key', co1.priv, '--co-key', co1.priv,
  ]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'USAGE_ERROR');
});

test('--co-key 与主密钥相同 -> USAGE_ERROR', () => {
  const { main } = setupCosign();
  const r = run([
    'generate', '--artifact', paths.art, '--key', main.priv, '--out', paths.out,
    '--co-key', main.priv,
  ]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'USAGE_ERROR');
});

test('共签三参数缺一 -> USAGE_ERROR', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  // 缺 --min-cosigners
  let v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], undefined);
  assert.equal(v.stderr.errorCode, 'USAGE_ERROR');
  // 缺 --cosignatures
  v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1, { skipCosignatures: true });
  assert.equal(v.stderr.errorCode, 'USAGE_ERROR');
  // 缺 --cosigner-key
  v = run([
    'verify', '--artifact', paths.art,
    '--proof', join(paths.out, 'proof.json'),
    '--signature', join(paths.out, 'proof.json.sig'),
    '--key', main.pub,
    '--cosignatures', paths.out, '--min-cosigners', '1',
  ]);
  assert.equal(v.stderr.errorCode, 'USAGE_ERROR');
});

test('--min-cosigners 非正整数或超过公钥数 -> USAGE_ERROR', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  for (const bad of ['0', '-1', '1.5', 'abc']) {
    const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], bad);
    assert.equal(v.stderr.errorCode, 'USAGE_ERROR', `min=${bad}`);
  }
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 2); // 只有 1 个公钥
  assert.equal(v.stderr.errorCode, 'USAGE_ERROR');
});

test('共签清单缺失 -> INPUT_NOT_FOUND', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const emptyDir = join(root, 'empty-cosig');
  mkdirSync(emptyDir);
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1, { cosignatures: emptyDir });
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INPUT_NOT_FOUND');
});

test('未声明的共签公钥 -> KEY_NOT_FOUND', () => {
  const { main, co1, co2 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co2.pub], 1); // co2 未声明
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'KEY_NOT_FOUND');
});

test('共签签名被篡改 -> SIGNATURE_INVALID', () => {
  const { main, co1, co2 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv, co2.priv]);
  const manifestPath = join(paths.out, 'proof.cosignatures.json');
  const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
  [m.signers[0].signature, m.signers[1].signature] = [m.signers[1].signature, m.signers[0].signature];
  writeFileSync(manifestPath, JSON.stringify(m, null, 2) + '\n');
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub, co2.pub], 2);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('有效共签数不足（重复公钥按指纹去重）-> SIGNATURE_INVALID', () => {
  const { main, co1, co2 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv, co2.priv]);
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub, co1.pub], 2);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('产物被篡改时共签参数不改变优先级 -> INTEGRITY_MISMATCH', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
});

test('共签清单包含主签名指纹 -> PROOF_INVALID', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  const manifestPath = join(paths.out, 'proof.cosignatures.json');
  const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
  m.signers.push({
    keyFingerprint: proof.signerKeyFingerprint,
    signature: m.signers[0].signature,
  });
  m.signers.sort((a, b) => (a.keyFingerprint < b.keyFingerprint ? -1 : 1)); // 保持升序，隔离变量
  writeFileSync(manifestPath, JSON.stringify(m, null, 2) + '\n');
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('部分共签达到 min 即可通过：min=1 时 cosignerCount 为实际有效数', () => {
  const { main, co1, co2 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv, co2.priv]);
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 1);
});

test('共签与策略组合：共签通过后才执行策略，全通过输出 cosignerCount 与 policyStatus', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const policyPath = join(root, 'policy.json');
  writeFileSync(policyPath, JSON.stringify({ policyVersion: '1.0', maxFileCount: 10 }));
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1, { policy: policyPath });
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 1);
  assert.equal(v.stdout.policyStatus, 'PASS');
});

// ---------------------------------------------------------------------------
// 证明分发包（generate --bundle；verify --bundle）
// ---------------------------------------------------------------------------

const BUNDLE_NAME = 'proof.bundle.json';
const BUNDLE_BASE_MEMBERS = ['proof', 'proof-signature', 'sbom', 'sbom-signature'];
const BUNDLE_ALL_MEMBERS = [
  'proof',
  'proof-cosignatures',
  'proof-signature',
  'sbom',
  'sbom-cosignatures',
  'sbom-signature',
];

function generateBundle(artifact, mainPriv, out, coPrivs = []) {
  const args = ['generate', '--artifact', artifact, '--key', mainPriv, '--out', out, '--bundle'];
  for (const p of coPrivs) args.push('--co-key', p);
  const r = run(args);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  return r.stdout;
}

function verifyBundle(artifact, bundlePath, pub, opts = {}) {
  const args = ['verify', '--artifact', artifact, '--key', pub, '--bundle', bundlePath];
  for (const p of opts.coPubs ?? []) args.push('--cosigner-key', p);
  if (opts.min !== undefined) args.push('--min-cosigners', String(opts.min));
  if (opts.policy) args.push('--policy', opts.policy);
  return run(args);
}

function readBundleFile(out) {
  return JSON.parse(readFileSync(join(out, BUNDLE_NAME), 'utf8'));
}

function writeBundleFile(obj, name = BUNDLE_NAME) {
  const p = join(root, name);
  writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
  return p;
}

function memberBytes(bundle, name) {
  return Buffer.from(bundle.members[name].payload, 'base64');
}

// 以给定字节重写成员并重算 sha256/size，使信封自身保持自洽。
function setMember(bundle, name, bytes) {
  const buf = Buffer.from(bytes);
  bundle.members[name] = {
    payload: buf.toString('base64'),
    sha256: createHash('sha256').update(buf).digest('hex'),
    size: buf.length,
  };
}

test('--bundle：独立文件照常写出，额外生成 proof.bundle.json，成功 JSON 含 bundlePath', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  assert.ok(g.bundlePath.endsWith(BUNDLE_NAME));
  for (const f of ['proof.json', 'proof.json.sig', 'sbom.json', 'sbom.json.sig', BUNDLE_NAME]) {
    assert.ok(existsSync(join(paths.out, f)), `应写出 ${f}`);
  }
});

test('不带 --bundle：不生成分发包，输出与语义不变（无 bundlePath）', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.bundlePath, undefined);
  assert.ok(!existsSync(join(paths.out, BUNDLE_NAME)));
});

test('分发包结构：bundleVersion 1.0、成员按逻辑名排序、字段顺序稳定', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const b = readBundleFile(paths.out);
  assert.equal(b.bundleVersion, '1.0');
  assert.deepEqual(Object.keys(b), ['bundleVersion', 'members']);
  assert.deepEqual(Object.keys(b.members), BUNDLE_BASE_MEMBERS);
  for (const name of BUNDLE_BASE_MEMBERS) {
    assert.deepEqual(Object.keys(b.members[name]), ['payload', 'sha256', 'size']);
  }
});

test('分发包成员：payload 为原文件字节，sha256 与 size 与字节一致', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const b = readBundleFile(paths.out);
  const diskFile = {
    proof: 'proof.json',
    'proof-signature': 'proof.json.sig',
    sbom: 'sbom.json',
    'sbom-signature': 'sbom.json.sig',
  };
  for (const name of BUNDLE_BASE_MEMBERS) {
    const disk = readFileSync(join(paths.out, diskFile[name]));
    const bytes = memberBytes(b, name);
    assert.ok(bytes.equals(disk), `${name} 必须保留原始文件字节`);
    assert.equal(b.members[name].size, disk.length);
    assert.equal(b.members[name].sha256, createHash('sha256').update(disk).digest('hex'));
  }
});

test('共签分发包：额外含成对共签成员且按逻辑名排序，字节与磁盘清单一致', () => {
  const { main, co1, co2 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co2.priv, co1.priv]);
  const b = readBundleFile(paths.out);
  assert.deepEqual(Object.keys(b.members), BUNDLE_ALL_MEMBERS);
  const diskFile = {
    'proof-cosignatures': 'proof.cosignatures.json',
    'sbom-cosignatures': 'sbom.cosignatures.json',
  };
  for (const name of ['proof-cosignatures', 'sbom-cosignatures']) {
    const disk = readFileSync(join(paths.out, diskFile[name]));
    assert.ok(memberBytes(b, name).equals(disk));
    assert.equal(b.members[name].sha256, createHash('sha256').update(disk).digest('hex'));
  }
  // 共签成员内容确为共签清单结构。
  const pm = JSON.parse(memberBytes(b, 'proof-cosignatures').toString('utf8'));
  assert.equal(pm.schemaVersion, '1.0');
  assert.equal(pm.signers.length, 2);
});

test('分发包确定性：重复生成仅 proof 及其签名输入变化，成员/字段顺序与其余成员稳定', () => {
  const { main, co1 } = setupCosign();
  const o1 = join(root, 'd1');
  const o2 = join(root, 'd2');
  generateBundle(paths.art, main.priv, o1, [co1.priv]);
  generateBundle(paths.art, main.priv, o2, [co1.priv]);
  const b1 = readBundleFile(o1);
  const b2 = readBundleFile(o2);
  assert.deepEqual(Object.keys(b1.members), BUNDLE_ALL_MEMBERS);
  assert.deepEqual(Object.keys(b2.members), BUNDLE_ALL_MEMBERS);
  // SBOM、SBOM 签名与 SBOM 共签清单不依赖时间，字节级稳定。
  for (const name of ['sbom', 'sbom-signature', 'sbom-cosignatures']) {
    assert.equal(b1.members[name].payload, b2.members[name].payload, `${name} 应稳定`);
  }
  // proof 成员仅 generatedAt 不同。
  const p1 = JSON.parse(memberBytes(b1, 'proof').toString('utf8'));
  const p2 = JSON.parse(memberBytes(b2, 'proof').toString('utf8'));
  assert.notEqual(p1.generatedAt, p2.generatedAt);
  assert.deepEqual({ ...p1, generatedAt: null }, { ...p2, generatedAt: null });
  // proof 主签名与 proof 共签清单因签名输入含 proof 字节而变化。
  assert.notEqual(b1.members['proof-signature'].payload, b2.members['proof-signature'].payload);
  assert.notEqual(b1.members['proof-cosignatures'].payload, b2.members['proof-cosignatures'].payload);
});

test('verify --bundle 往返成功：字段与独立文件模式一致且始终含 sbomDigest', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const v = verifyBundle(paths.art, join(paths.out, BUNDLE_NAME), k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.proofVersion, '1.0');
  assert.equal(v.stdout.artifactDigest, g.artifactDigest);
  assert.equal(v.stdout.fileCount, 4);
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(v.stdout.sbomDigest, proof.sbomDigest);
  // 与独立文件 + SBOM 模式的成功字段一致。
  const v2 = verifyWithSbom(paths.art, paths.out, k.pub);
  assert.deepEqual(v.stdout, v2.stdout);
});

test('verify --bundle：输出目录位于产物内部时同样自排除', () => {
  const k = keygen(paths.keys);
  const outInside = join(paths.art, '_attest');
  generateBundle(paths.art, k.priv, outInside);
  const sbom = JSON.parse(readFileSync(join(outInside, 'sbom.json'), 'utf8'));
  assert.ok(!sbom.files.some((f) => f.path.startsWith('_attest/')));
  const v = verifyBundle(paths.art, join(outInside, BUNDLE_NAME), k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
});

test('verify --bundle 共签往返：输出 cosignerCount，min=1 部分达标', () => {
  const { main, co1, co2 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co1.priv, co2.priv]);
  const bundle = join(paths.out, BUNDLE_NAME);

  const v2 = verifyBundle(paths.art, bundle, main.pub, { coPubs: [co1.pub, co2.pub], min: 2 });
  assert.equal(v2.code, 0, JSON.stringify(v2.stderr));
  assert.equal(v2.stdout.status, 'VERIFIED');
  assert.equal(v2.stdout.proofVersion, '1.1');
  assert.equal(v2.stdout.cosignerCount, 2);
  assert.match(v2.stdout.sbomDigest, /^[0-9a-f]{64}$/);

  const v1 = verifyBundle(paths.art, bundle, main.pub, { coPubs: [co1.pub], min: 1 });
  assert.equal(v1.code, 0, JSON.stringify(v1.stderr));
  assert.equal(v1.stdout.cosignerCount, 1);
});

test('verify --bundle 共签下产物被篡改 -> INTEGRITY_MISMATCH', () => {
  const { main, co1 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co1.priv]);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyBundle(paths.art, join(paths.out, BUNDLE_NAME), main.pub, {
    coPubs: [co1.pub],
    min: 1,
  });
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
});

test('verify --bundle 未声明的共签公钥 -> KEY_NOT_FOUND；共签签名被篡改 -> SIGNATURE_INVALID', () => {
  const { main, co1, co2 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co1.priv]);
  const bundlePath = join(paths.out, BUNDLE_NAME);

  const vKey = verifyBundle(paths.art, bundlePath, main.pub, { coPubs: [co2.pub], min: 1 }); // co2 未声明
  assert.equal(vKey.code, 1);
  assert.equal(vKey.stderr.errorCode, 'KEY_NOT_FOUND');

  const b = readBundleFile(paths.out);
  const m = JSON.parse(memberBytes(b, 'proof-cosignatures').toString('utf8'));
  // 翻转签名中段的一个字符（避开尾部 '=' 填充），保持 Base64 与 64 字节长度合法。
  const sig = m.signers[0].signature;
  const pos = Math.floor(sig.length / 2);
  m.signers[0].signature = sig.slice(0, pos) + (sig[pos] === 'A' ? 'B' : 'A') + sig.slice(pos + 1);
  setMember(b, 'proof-cosignatures', Buffer.from(JSON.stringify(m, null, 2) + '\n'));
  const tamperedPath = writeBundleFile(b, 'cosig-tampered.json');
  const vSig = verifyBundle(paths.art, tamperedPath, main.pub, { coPubs: [co1.pub], min: 1 });
  assert.equal(vSig.code, 1);
  assert.equal(vSig.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('verify --bundle 策略：requireSbom 视为满足；通过带 policyStatus，违规 POLICY_VIOLATION', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const bundlePath = join(paths.out, BUNDLE_NAME);

  const reqPath = join(root, 'policy-req.json');
  writeFileSync(reqPath, JSON.stringify({ policyVersion: '1.0', requireSbom: true }));
  const vReq = verifyBundle(paths.art, bundlePath, k.pub, { policy: reqPath });
  assert.equal(vReq.code, 0, JSON.stringify(vReq.stderr));
  assert.equal(vReq.stdout.policyStatus, 'PASS');

  const overPath = join(root, 'policy-over.json');
  writeFileSync(overPath, JSON.stringify({ policyVersion: '1.0', maxFileCount: 0 }));
  const vOver = verifyBundle(paths.art, bundlePath, k.pub, { policy: overPath });
  assert.equal(vOver.code, 1);
  assert.equal(vOver.stderr.errorCode, 'POLICY_VIOLATION');
});

test('verify --bundle 与独立文件参数混用 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const bundlePath = join(paths.out, BUNDLE_NAME);
  const base = ['verify', '--artifact', paths.art, '--key', k.pub, '--bundle', bundlePath];
  for (const [flag, value] of [
    ['--proof', join(paths.out, 'proof.json')],
    ['--signature', join(paths.out, 'proof.json.sig')],
    ['--sbom', join(paths.out, 'sbom.json')],
    ['--sbom-signature', join(paths.out, 'sbom.json.sig')],
    ['--cosignatures', paths.out],
  ]) {
    const r = run([...base, flag, value]);
    assert.equal(r.code, 1, flag);
    assert.equal(r.stderr.errorCode, 'USAGE_ERROR', flag);
  }
});

test('verify --bundle 参数成对/缺失 -> USAGE_ERROR', () => {
  const { main, co1 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co1.priv]);
  const bundlePath = join(paths.out, BUNDLE_NAME);

  // 缺 --artifact / --key。
  assert.equal(run(['verify', '--key', main.pub, '--bundle', bundlePath]).stderr.errorCode, 'USAGE_ERROR');
  assert.equal(run(['verify', '--artifact', paths.art, '--bundle', bundlePath]).stderr.errorCode, 'USAGE_ERROR');
  // --bundle 缺路径。
  assert.equal(
    run(['verify', '--artifact', paths.art, '--key', main.pub, '--bundle']).stderr.errorCode,
    'USAGE_ERROR',
  );
  // 包模式共签两参数只给一者。
  assert.equal(
    verifyBundle(paths.art, bundlePath, main.pub, { min: 1 }).stderr.errorCode,
    'USAGE_ERROR',
  );
  assert.equal(
    verifyBundle(paths.art, bundlePath, main.pub, { coPubs: [co1.pub] }).stderr.errorCode,
    'USAGE_ERROR',
  );
  // min 超过提供的公钥数量。
  assert.equal(
    verifyBundle(paths.art, bundlePath, main.pub, { coPubs: [co1.pub], min: 2 }).stderr.errorCode,
    'USAGE_ERROR',
  );
});

test('verify 无 --bundle 且缺少成对输入 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const r = run(['verify', '--artifact', paths.art, '--key', k.pub]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.errorCode, 'USAGE_ERROR');
});

test('分发包 JSON 不可解析 / bundleVersion 非 1.0 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);

  const broken = join(root, 'broken-bundle.json');
  writeFileSync(broken, '{broken');
  assert.equal(verifyBundle(paths.art, broken, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const b = readBundleFile(paths.out);
  for (const version of ['2.0', 1.0, null, undefined]) {
    const edited = JSON.parse(JSON.stringify(b));
    if (version === undefined) delete edited.bundleVersion;
    else edited.bundleVersion = version;
    const p = writeBundleFile(edited, `bundle-v-${String(version)}.json`);
    assert.equal(verifyBundle(paths.art, p, k.pub).stderr.errorCode, 'PROOF_INVALID', `version=${version}`);
  }
});

test('分发包成员缺失或多余 -> PROOF_INVALID', () => {
  const { main, co1 } = setupCosign();
  generateBundle(paths.art, main.priv, paths.out, [co1.priv]);
  const coBundlePath = join(paths.out, BUNDLE_NAME);

  // 删除基础成员。
  const b1 = readBundleFile(paths.out);
  delete b1.members.sbom;
  const p1 = writeBundleFile(b1, 'bundle-missing-sbom.json');
  assert.equal(verifyBundle(paths.art, p1, main.pub).stderr.errorCode, 'PROOF_INVALID');

  // 共签成员单个出现（不成对）。
  const b2 = readBundleFile(paths.out);
  delete b2.members['proof-cosignatures'];
  const p2 = writeBundleFile(b2, 'bundle-half-cosig.json');
  assert.equal(verifyBundle(paths.art, p2, main.pub).stderr.errorCode, 'PROOF_INVALID');

  // 未知/多余成员。
  const b3 = readBundleFile(paths.out);
  b3.members.extra = {
    payload: Buffer.from('x').toString('base64'),
    sha256: createHash('sha256').update(Buffer.from('x')).digest('hex'),
    size: 1,
  };
  const p3 = writeBundleFile(b3, 'bundle-extra.json');
  assert.equal(verifyBundle(paths.art, p3, main.pub).stderr.errorCode, 'PROOF_INVALID');

  // v1.1 证明却附在不含共签成员的包中：以共签包内容注入 v1.0 包。
  const plainOut = join(root, 'plain-out');
  generateBundle(paths.art, main.priv, plainOut);
  const b4 = readBundleFile(plainOut);
  const co = readBundleFile(paths.out);
  b4.members['proof-cosignatures'] = co.members['proof-cosignatures'];
  b4.members['sbom-cosignatures'] = co.members['sbom-cosignatures'];
  const p4 = writeBundleFile(b4, 'bundle-injected-cosig.json');
  assert.equal(verifyBundle(paths.art, p4, main.pub).stderr.errorCode, 'PROOF_INVALID');

  // v1.0 包请求共签校验（包内无共签成员）。
  assert.equal(
    verifyBundle(paths.art, join(plainOut, BUNDLE_NAME), main.pub, {
      coPubs: [co1.pub],
      min: 1,
    }).stderr.errorCode,
    'PROOF_INVALID',
  );
});

test('分发包成员 Base64 非法 / 长度不符 / SHA-256 不符 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);

  const bBad64 = readBundleFile(paths.out);
  bBad64.members.sbom.payload = '!!!not-base64!!!';
  const pBad64 = writeBundleFile(bBad64, 'bundle-bad64.json');
  assert.equal(verifyBundle(paths.art, pBad64, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const bSize = readBundleFile(paths.out);
  bSize.members.sbom.size = 1;
  const pSize = writeBundleFile(bSize, 'bundle-size.json');
  assert.equal(verifyBundle(paths.art, pSize, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const bHash = readBundleFile(paths.out);
  bHash.members.sbom.sha256 = 'a'.repeat(64);
  const pHash = writeBundleFile(bHash, 'bundle-hash.json');
  assert.equal(verifyBundle(paths.art, pHash, k.pub).stderr.errorCode, 'PROOF_INVALID');

  // 改 payload 但不改元数据（信封不自洽）-> 同样 PROOF_INVALID。
  const bPayload = readBundleFile(paths.out);
  bPayload.members.sbom.payload = Buffer.from('{}').toString('base64');
  const pPayload = writeBundleFile(bPayload, 'bundle-payload.json');
  assert.equal(verifyBundle(paths.art, pPayload, k.pub).stderr.errorCode, 'PROOF_INVALID');
});

test('包内 proof 不是合法 JSON 或结构非法 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);

  const b1 = readBundleFile(paths.out);
  setMember(b1, 'proof', Buffer.from('{broken'));
  const p1 = writeBundleFile(b1, 'bundle-bad-proof-json.json');
  assert.equal(verifyBundle(paths.art, p1, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const b2 = readBundleFile(paths.out);
  const proof = JSON.parse(memberBytes(b2, 'proof').toString('utf8'));
  delete proof.artifactDigest;
  setMember(b2, 'proof', Buffer.from(JSON.stringify(proof, null, 2) + '\n'));
  const p2 = writeBundleFile(b2, 'bundle-bad-proof-shape.json');
  assert.equal(verifyBundle(paths.art, p2, k.pub).stderr.errorCode, 'PROOF_INVALID');
});

test('信封自洽但证明内容被改动 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const b = readBundleFile(paths.out);
  const proof = JSON.parse(memberBytes(b, 'proof').toString('utf8'));
  proof.generatedAt = '2000-01-01T00:00:00.000Z';
  setMember(b, 'proof', Buffer.from(JSON.stringify(proof, null, 2) + '\n'));
  const p = writeBundleFile(b, 'bundle-proof-tampered.json');
  assert.equal(verifyBundle(paths.art, p, k.pub).stderr.errorCode, 'SIGNATURE_INVALID');
});

test('信封自洽但 SBOM 签名被替换 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  const b = readBundleFile(paths.out);
  // proof-signature 同为合法 64 字节签名，但签的是证明而非 SBOM。
  setMember(b, 'sbom-signature', memberBytes(b, 'proof-signature'));
  const p = writeBundleFile(b, 'bundle-sbom-sig-swapped.json');
  assert.equal(verifyBundle(paths.art, p, k.pub).stderr.errorCode, 'SIGNATURE_INVALID');
});

test('verify --bundle 错误主公钥 -> KEY_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generateBundle(paths.art, k.priv, paths.out);
  const v = verifyBundle(paths.art, join(paths.out, BUNDLE_NAME), k2.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'KEY_NOT_FOUND');
});

test('verify --bundle 产物字节被修改 -> INTEGRITY_MISMATCH 且携带差异路径', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyBundle(paths.art, join(paths.out, BUNDLE_NAME), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'a.txt' && m.kind === 'content-modified'));
});

test('分发包文件不存在 -> INPUT_NOT_FOUND；不可解析主公钥 -> KEY_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generateBundle(paths.art, k.priv, paths.out);
  assert.equal(
    verifyBundle(paths.art, join(root, 'nope-bundle.json'), k.pub).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  const badKey = join(root, 'bad.pem');
  writeFileSync(badKey, 'not a key');
  assert.equal(
    verifyBundle(paths.art, join(paths.out, BUNDLE_NAME), badKey).stderr.errorCode,
    'KEY_NOT_FOUND',
  );
});

test('验证顺序：共签清单缺失/非法时产物差异仍优先报 INTEGRITY_MISMATCH', () => {
  // 独立文件模式：共签清单缺失 + 产物被篡改 -> 完整性优先（清单第 8 步才读取）。
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const emptyDir = join(root, 'empty-cosig');
  mkdirSync(emptyDir);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v1 = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1, { cosignatures: emptyDir });
  assert.equal(v1.code, 1);
  assert.equal(v1.stderr.errorCode, 'INTEGRITY_MISMATCH');

  // 包模式：包内共签清单结构非法 + 产物被篡改 -> 完整性优先（清单第 8 步才解析）。
  const out2 = join(root, 'attest2');
  writeFileSync(join(paths.art, 'a.txt'), 'hello world\n'); // 恢复
  generateBundle(paths.art, main.priv, out2, [co1.priv]);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED-AGAIN\n');
  const b = readBundleFile(out2);
  setMember(b, 'proof-cosignatures', Buffer.from('{broken'));
  const p = writeBundleFile(b, 'bundle-order.json');
  const v2 = verifyBundle(paths.art, p, main.pub, { coPubs: [co1.pub], min: 1 });
  assert.equal(v2.code, 1);
  assert.equal(v2.stderr.errorCode, 'INTEGRITY_MISMATCH');
});
