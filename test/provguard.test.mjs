// Prov Guard 端到端测试：以子进程方式驱动 provguard.mjs CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { sign as cryptoSign, createPrivateKey, createPublicKey, createHash, generateKeyPairSync } from 'node:crypto';
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

function generateBundle(artifact, key, out, extra = []) {
  const r = run(['generate', '--artifact', artifact, '--key', key, '--out', out, ...extra, '--bundle']);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  return r.stdout;
}

function verifyBundle(artifact, bundlePath, pub, extra = []) {
  return run(['verify', '--artifact', artifact, '--bundle', bundlePath, '--key', pub, ...extra]);
}

function readBundle(out = paths.out) {
  return JSON.parse(readFileSync(join(out, 'proof.bundle.json'), 'utf8'));
}

// 修改包内某成员后回写；transform 接收解码后的字节，返回新字节。
// 默认同步更新 sha256 与 size（构造“自洽但内容被改”的包）。
function rewriteBundleMember(name, transform, { fixMeta = true } = {}) {
  const p = join(paths.out, 'proof.bundle.json');
  const b = JSON.parse(readFileSync(p, 'utf8'));
  const bytes = transform(Buffer.from(b.members[name].data, 'base64'));
  b.members[name].data = bytes.toString('base64');
  if (fixMeta) {
    b.members[name].sha256 = createHash('sha256').update(bytes).digest('hex');
    b.members[name].size = bytes.length;
  }
  writeFileSync(p, JSON.stringify(b, null, 2) + '\n');
}

test('generate --bundle：独立文件照常输出，另生成 proof.bundle.json，成员字节与原文件一致', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  assert.ok(g.bundlePath.endsWith('proof.bundle.json'));
  for (const f of ['proof.json', 'proof.json.sig', 'sbom.json', 'sbom.json.sig']) {
    assert.ok(existsSync(join(paths.out, f)), `独立文件 ${f} 应照常输出`);
  }
  const b = readBundle();
  assert.equal(b.bundleVersion, '1.0');
  assert.deepEqual(Object.keys(b.members), ['proof', 'proof-signature', 'sbom', 'sbom-signature']);
  const fileOf = {
    proof: 'proof.json',
    'proof-signature': 'proof.json.sig',
    sbom: 'sbom.json',
    'sbom-signature': 'sbom.json.sig',
  };
  for (const [name, file] of Object.entries(fileOf)) {
    const disk = readFileSync(join(paths.out, file));
    const m = b.members[name];
    assert.equal(m.size, disk.length, name);
    assert.equal(m.sha256, createHash('sha256').update(disk).digest('hex'), name);
    assert.deepEqual(Buffer.from(m.data, 'base64'), disk, `${name} 应保留原文件字节`);
  }
});

test('不使用 --bundle 时不生成 proof.bundle.json，输出字段不变', () => {
  const k = keygen(paths.keys);
  const g = generate(paths.art, k.priv, paths.out);
  assert.equal(g.bundlePath, undefined);
  assert.ok(!existsSync(join(paths.out, 'proof.bundle.json')));
});

test('分发包确定性：重复生成时成员顺序一致，sbom 等成员逐字节稳定', () => {
  const k = keygen(paths.keys);
  const o1 = join(root, 'b1');
  const o2 = join(root, 'b2');
  generateBundle(paths.art, k.priv, o1);
  generateBundle(paths.art, k.priv, o2);
  const b1 = readBundle(o1);
  const b2 = readBundle(o2);
  assert.deepEqual(Object.keys(b1.members), Object.keys(b2.members));
  assert.deepEqual(Object.keys(b1.members['sbom']), Object.keys(b2.members['sbom']));
  for (const name of ['sbom', 'sbom-signature']) {
    assert.deepEqual(b1.members[name], b2.members[name], `${name} 应逐字节稳定`);
  }
});

test('verify --bundle 往返成功，输出字段与独立文件模式一致（含 sbomDigest）', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const v = verifyBundle(paths.art, g.bundlePath, k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.proofVersion, '1.0');
  assert.equal(v.stdout.artifactDigest, g.artifactDigest);
  assert.equal(v.stdout.fileCount, 4);
  const proof = JSON.parse(readFileSync(join(paths.out, 'proof.json'), 'utf8'));
  assert.equal(v.stdout.sbomDigest, proof.sbomDigest);
});

test('--bundle 与独立文件参数混用 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const base = ['verify', '--artifact', paths.art, '--bundle', g.bundlePath, '--key', k.pub];
  for (const extra of [
    ['--proof', join(paths.out, 'proof.json')],
    ['--signature', join(paths.out, 'proof.json.sig')],
    ['--sbom', join(paths.out, 'sbom.json')],
    ['--sbom-signature', join(paths.out, 'sbom.json.sig')],
    ['--cosignatures', paths.out],
  ]) {
    const v = run([...base, ...extra]);
    assert.equal(v.code, 1, extra[0]);
    assert.equal(v.stderr.errorCode, 'USAGE_ERROR', extra[0]);
  }
});

test('--bundle 缺路径、缺 --artifact/--key，或共签参数缺一 -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  assert.equal(run(['verify', '--artifact', paths.art, '--bundle', '--key', k.pub]).stderr.errorCode, 'USAGE_ERROR');
  assert.equal(run(['verify', '--bundle', g.bundlePath, '--key', k.pub]).stderr.errorCode, 'USAGE_ERROR');
  assert.equal(run(['verify', '--artifact', paths.art, '--bundle', g.bundlePath]).stderr.errorCode, 'USAGE_ERROR');
  // 共签参数只给一者
  const k2 = keygen(paths.keys2);
  assert.equal(
    verifyBundle(paths.art, g.bundlePath, k.pub, ['--cosigner-key', k2.pub]).stderr.errorCode,
    'USAGE_ERROR',
  );
  assert.equal(
    verifyBundle(paths.art, g.bundlePath, k.pub, ['--min-cosigners', '1']).stderr.errorCode,
    'USAGE_ERROR',
  );
});

test('分发包路径不存在 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  const v = verifyBundle(paths.art, join(root, 'nope.bundle.json'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INPUT_NOT_FOUND');
});

test('包 JSON 不可解析 / bundleVersion 非 1.0 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const broken = join(root, 'broken.bundle.json');
  writeFileSync(broken, '{broken');
  assert.equal(verifyBundle(paths.art, broken, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const b = readBundle();
  b.bundleVersion = '2.0';
  writeFileSync(g.bundlePath, JSON.stringify(b));
  assert.equal(verifyBundle(paths.art, g.bundlePath, k.pub).stderr.errorCode, 'PROOF_INVALID');
});

test('成员缺失或多余 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);

  const missing = readBundle();
  delete missing.members.sbom;
  const p1 = join(root, 'missing.bundle.json');
  writeFileSync(p1, JSON.stringify(missing));
  assert.equal(verifyBundle(paths.art, p1, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const extra = readBundle();
  extra.members['extra-file'] = extra.members.sbom;
  writeFileSync(g.bundlePath, JSON.stringify(extra));
  assert.equal(verifyBundle(paths.art, g.bundlePath, k.pub).stderr.errorCode, 'PROOF_INVALID');
});

test('成员 Base64 非法 / 长度不符 / SHA-256 不符 -> PROOF_INVALID', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);

  const badB64 = readBundle();
  badB64.members.sbom.data = '!!! not base64 !!!';
  const p1 = join(root, 'badb64.bundle.json');
  writeFileSync(p1, JSON.stringify(badB64));
  assert.equal(verifyBundle(paths.art, p1, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const badSize = readBundle();
  badSize.members.sbom.size += 1;
  const p2 = join(root, 'badsize.bundle.json');
  writeFileSync(p2, JSON.stringify(badSize));
  assert.equal(verifyBundle(paths.art, p2, k.pub).stderr.errorCode, 'PROOF_INVALID');

  const badSha = readBundle();
  badSha.members.sbom.sha256 = '0'.repeat(64);
  writeFileSync(g.bundlePath, JSON.stringify(badSha));
  assert.equal(verifyBundle(paths.art, g.bundlePath, k.pub).stderr.errorCode, 'PROOF_INVALID');
});

test('包内证明被篡改（成员摘要同步更新）-> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  rewriteBundleMember('proof', (bytes) => {
    const proof = JSON.parse(bytes.toString('utf8'));
    proof.generatedAt = '2000-01-01T00:00:00.000Z';
    return Buffer.from(JSON.stringify(proof, null, 2) + '\n', 'utf8');
  });
  const v = verifyBundle(paths.art, g.bundlePath, k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('包模式：错误主公钥 -> KEY_NOT_FOUND；产物篡改 -> INTEGRITY_MISMATCH', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  const g = generateBundle(paths.art, k.priv, paths.out);
  assert.equal(verifyBundle(paths.art, g.bundlePath, k2.pub).stderr.errorCode, 'KEY_NOT_FOUND');

  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyBundle(paths.art, g.bundlePath, k.pub);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'a.txt' && m.kind === 'content-modified'));
});

test('共签分发包：含共签成员，verify --bundle 校验共签并输出 cosignerCount', () => {
  const { main, co1, co2 } = setupCosign();
  const g = generateBundle(paths.art, main.priv, paths.out, ['--co-key', co2.priv, '--co-key', co1.priv]);
  assert.equal(g.proofVersion, '1.1');
  const b = readBundle();
  assert.deepEqual(Object.keys(b.members), [
    'proof',
    'proof-cosignatures',
    'proof-signature',
    'sbom',
    'sbom-cosignatures',
    'sbom-signature',
  ]);
  // 共签成员字节与独立清单文件一致
  assert.deepEqual(
    Buffer.from(b.members['proof-cosignatures'].data, 'base64'),
    readFileSync(join(paths.out, 'proof.cosignatures.json')),
  );
  const v = verifyBundle(paths.art, g.bundlePath, main.pub, [
    '--cosigner-key', co1.pub,
    '--cosigner-key', co2.pub,
    '--min-cosigners', '2',
  ]);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 2);
});

test('共签包被移除共签成员（证明仍声明共签者）-> PROOF_INVALID', () => {
  const { main, co1 } = setupCosign();
  const g = generateBundle(paths.art, main.priv, paths.out, ['--co-key', co1.priv]);
  const b = readBundle();
  delete b.members['proof-cosignatures'];
  delete b.members['sbom-cosignatures'];
  writeFileSync(g.bundlePath, JSON.stringify(b));
  const v = verifyBundle(paths.art, g.bundlePath, main.pub, [
    '--cosigner-key', co1.pub,
    '--min-cosigners', '1',
  ]);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'PROOF_INVALID');
});

test('包模式策略：违规 -> POLICY_VIOLATION；通过 -> policyStatus PASS', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const bad = writePolicy({ policyVersion: '1.0', maxFileCount: 0 }, 'policy-bad.json');
  const v1 = verifyBundle(paths.art, g.bundlePath, k.pub, ['--policy', bad]);
  assert.equal(v1.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v1.stderr.details.violations, [{ rule: 'max-file-count', observed: 4 }]);

  const good = writePolicy({ policyVersion: '1.0', maxFileCount: 4, requireSbom: true }, 'policy-good.json');
  const v2 = verifyBundle(paths.art, g.bundlePath, k.pub, ['--policy', good]);
  assert.equal(v2.code, 0, JSON.stringify(v2.stderr));
  assert.equal(v2.stdout.policyStatus, 'PASS');
});

// ---------------------------------------------------------------------------
// 策略签名（policy-sign；verify --policy-signature/--policy-key）
// ---------------------------------------------------------------------------

function policySign(priv, overrides = {}) {
  const policyPath = overrides.policy ?? join(root, 'policy.json');
  return run([
    'policy-sign',
    '--policy', policyPath,
    '--key', overrides.key ?? priv,
    '--signature', overrides.signature ?? join(root, 'policy.json.sig'),
  ]);
}

function verifyWithPolicySig(pub, policyPath, sigPath, polKeyPath, extra = []) {
  return run([
    'verify',
    '--artifact', paths.art,
    '--proof', join(paths.out, 'proof.json'),
    '--signature', join(paths.out, 'proof.json.sig'),
    '--key', pub,
    '--policy', policyPath,
    '--policy-signature', sigPath,
    '--policy-key', polKeyPath,
    ...extra,
  ]);
}

test('policy-sign 成功：输出 POLICY_SIGNED、路径与签名公钥指纹', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 10 });
  const r = policySign(k.priv);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  assert.equal(r.stdout.status, 'POLICY_SIGNED');
  assert.equal(r.stdout.policyPath, join(root, 'policy.json'));
  assert.equal(r.stdout.signaturePath, join(root, 'policy.json.sig'));
  const pubObj = createPublicKey(readFileSync(k.pub));
  const fp = createHash('sha256').update(pubObj.export({ type: 'spki', format: 'der' })).digest('hex');
  assert.equal(r.stdout.policySignerFingerprint, fp);

  const sigText = readFileSync(join(root, 'policy.json.sig'), 'utf8');
  assert.match(sigText, /^[A-Za-z0-9+/=]+\n$/);
  assert.equal(Buffer.from(sigText.trim(), 'base64').length, 64);
});

test('policy-sign 重复生成逐字节一致', () => {
  const k = keygen(paths.keys);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 10 });
  const r1 = policySign(k.priv, { signature: join(root, 'a.sig') });
  const r2 = policySign(k.priv, { signature: join(root, 'b.sig') });
  assert.equal(r1.code, 0, JSON.stringify(r1.stderr));
  assert.equal(r2.code, 0, JSON.stringify(r2.stderr));
  assert.deepEqual(readFileSync(join(root, 'a.sig')), readFileSync(join(root, 'b.sig')));
});

test('policy-sign 不改写策略、私钥或证明', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 10 });
  const before = {
    policy: readFileSync(p),
    key: readFileSync(k.priv),
    proof: readFileSync(join(paths.out, 'proof.json')),
  };
  const r = policySign(k.priv);
  assert.equal(r.code, 0);
  assert.deepEqual(readFileSync(p), before.policy);
  assert.deepEqual(readFileSync(k.priv), before.key);
  assert.deepEqual(readFileSync(join(paths.out, 'proof.json')), before.proof);
});

test('policy-sign 对非规范磁盘策略（键乱序、无尾换行）同样可签且验证互通', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const messy = join(root, 'messy.json');
  writeFileSync(messy, '{"maxFileCount":10,"policyVersion":"1.0"}');
  const r = policySign(k.priv, { policy: messy, signature: join(root, 'messy.sig') });
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  const v = verifyWithPolicySig(k.pub, messy, join(root, 'messy.sig'), k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
  assert.ok(/^[0-9a-f]{64}$/.test(v.stdout.policySignerFingerprint));
});

test('verify 启用策略签名：通过输出 policyStatus PASS 与 policySignerFingerprint', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 4 });
  policySign(k.priv);
  const v = verifyWithPolicySig(k.pub, p, join(root, 'policy.json.sig'), k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
  const proof = readProof();
  assert.ok(!('policySignerFingerprint' in proof));
  const pubObj = createPublicKey(readFileSync(k.pub));
  const fp = createHash('sha256').update(pubObj.export({ type: 'spki', format: 'der' })).digest('hex');
  assert.equal(v.stdout.policySignerFingerprint, fp);
});

test('策略签名可使用与主签名不同的密钥', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 4 });
  const r = policySign(k2.priv);
  assert.equal(r.code, 0, JSON.stringify(r.stderr));
  const v = verifyWithPolicySig(k.pub, p, join(root, 'policy.json.sig'), k2.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policySignerFingerprint, r.stdout.policySignerFingerprint);
});

test('策略公钥与签名不匹配 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 4 });
  policySign(k.priv);
  // 用另一公钥验同一签名必失败。
  const v = verifyWithPolicySig(k.pub, p, join(root, 'policy.json.sig'), k2.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('策略内容被改动 -> SIGNATURE_INVALID（先于规则评估）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 10 });
  policySign(k.priv);
  // 改成必然违规的取值，但签名仍对应旧内容 -> 应报 SIGNATURE_INVALID 而非 VIOLATION。
  writeFileSync(p, JSON.stringify({ policyVersion: '1.0', maxFileCount: 0 }));
  const v = verifyWithPolicySig(k.pub, p, join(root, 'policy.json.sig'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('策略签名 Base64 非法 / 长度非法 -> SIGNATURE_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0' });
  policySign(k.priv);
  const badB64 = join(root, 'bad-pol.sig');
  writeFileSync(badB64, '!!! not base64 !!!');
  assert.equal(verifyWithPolicySig(k.pub, p, badB64, k.pub).stderr.errorCode, 'SIGNATURE_INVALID');
  const short = join(root, 'short-pol.sig');
  writeFileSync(short, Buffer.from('too-short').toString('base64'));
  assert.equal(verifyWithPolicySig(k.pub, p, short, k.pub).stderr.errorCode, 'SIGNATURE_INVALID');
});

test('策略、签名或策略公钥缺失 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0' });
  policySign(k.priv);
  const sig = join(root, 'policy.json.sig');
  assert.equal(
    verifyWithPolicySig(k.pub, join(root, 'nope.json'), sig, k.pub).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  assert.equal(
    verifyWithPolicySig(k.pub, p, join(root, 'nope.sig'), k.pub).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  assert.equal(
    verifyWithPolicySig(k.pub, p, sig, join(root, 'nope.pem')).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
});

test('策略公钥不可解析 / 非 Ed25519 -> KEY_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0' });
  policySign(k.priv);
  const sig = join(root, 'policy.json.sig');
  const bad = join(root, 'bad-polkey.pem');
  writeFileSync(bad, 'not a key');
  assert.equal(verifyWithPolicySig(k.pub, p, sig, bad).stderr.errorCode, 'KEY_NOT_FOUND');
  const { publicKey: rsaPub } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPath = join(root, 'rsa.pub.pem');
  writeFileSync(rsaPath, rsaPub.export({ type: 'spki', format: 'pem' }));
  assert.equal(verifyWithPolicySig(k.pub, p, sig, rsaPath).stderr.errorCode, 'KEY_NOT_FOUND');
});

test('策略本身非法（即使有签名）-> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  // policy-sign 直接拒绝非法策略。
  const bad = join(root, 'bad.json');
  writeFileSync(bad, JSON.stringify({ policyVersion: '2.0' }));
  const r1 = policySign(k.priv, { policy: bad, signature: join(root, 'bad.sig') });
  assert.equal(r1.code, 1);
  assert.equal(r1.stderr.errorCode, 'POLICY_INVALID');
  // verify 侧同样先校验策略结构。
  const good = writePolicy({ policyVersion: '1.0' });
  policySign(k.priv);
  writeFileSync(good, JSON.stringify({ policyVersion: '1.0', unknown: 1 }));
  const v = verifyWithPolicySig(k.pub, good, join(root, 'policy.json.sig'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_INVALID');
});

test('策略合法且签名通过但规则违规 -> POLICY_VIOLATION，violations 排序不变', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', maxFileCount: 0, maxSize: 0 });
  policySign(k.priv);
  const v = verifyWithPolicySig(k.pub, p, join(root, 'policy.json.sig'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations.map((x) => x.rule), ['max-file-count', 'max-size']);
});

test('证明/产物篡改优先于策略签名阶段（缺失的签名文件不提前报错）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0' });
  // 产物被篡改 -> INTEGRITY_MISMATCH，即使策略签名文件不存在。
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyWithPolicySig(k.pub, p, join(root, 'nope.sig'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
});

test('bundle 模式支持策略签名往返', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const p = writePolicy({ policyVersion: '1.0', requireSbom: true, maxFileCount: 4 });
  policySign(k.priv);
  const v = run([
    'verify',
    '--artifact', paths.art,
    '--bundle', g.bundlePath,
    '--key', k.pub,
    '--policy', p,
    '--policy-signature', join(root, 'policy.json.sig'),
    '--policy-key', k.pub,
  ]);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
  assert.match(v.stdout.policySignerFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(v.stdout.sbomDigest, readProof().sbomDigest);
});

test('策略签名参数不成对或缺 --policy -> USAGE_ERROR', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const base = [
    'verify', '--artifact', paths.art,
    '--proof', join(paths.out, 'proof.json'),
    '--signature', join(paths.out, 'proof.json.sig'),
    '--key', k.pub,
  ];
  const p = writePolicy({ policyVersion: '1.0' });
  policySign(k.priv);
  const sig = join(root, 'policy.json.sig');
  // 只给 --policy-signature
  assert.equal(run([...base, '--policy', p, '--policy-signature', sig]).stderr.errorCode, 'USAGE_ERROR');
  // 只给 --policy-key
  assert.equal(run([...base, '--policy', p, '--policy-key', k.pub]).stderr.errorCode, 'USAGE_ERROR');
  // 两者成对但无 --policy
  assert.equal(
    run([...base, '--policy-signature', sig, '--policy-key', k.pub]).stderr.errorCode,
    'USAGE_ERROR',
  );
  // --policy-signature 缺值
  assert.equal(
    run([...base, '--policy', p, '--policy-signature', '--policy-key', k.pub]).stderr.errorCode,
    'USAGE_ERROR',
  );
});

test('policy-sign 缺参数 -> USAGE_ERROR；未知子命令行为不变', () => {
  const k = keygen(paths.keys);
  const p = writePolicy({ policyVersion: '1.0' });
  assert.equal(run(['policy-sign', '--policy', p, '--key', k.priv]).stderr.errorCode, 'USAGE_ERROR');
  assert.equal(
    run(['policy-sign', '--policy', p, '--signature', join(root, 'x.sig')]).stderr.errorCode,
    'USAGE_ERROR',
  );
  assert.equal(run(['policy-sign']).stderr.errorCode, 'USAGE_ERROR');
});

test('policy-sign 策略/私钥缺失 -> INPUT_NOT_FOUND；私钥不可解析 -> KEY_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  const p = writePolicy({ policyVersion: '1.0' });
  assert.equal(
    run(['policy-sign', '--policy', join(root, 'nope.json'), '--key', k.priv,
      '--signature', join(root, 'x.sig')]).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  assert.equal(
    policySign(join(root, 'nope.pem'), { policy: p, signature: join(root, 'x.sig') }).stderr.errorCode,
    'INPUT_NOT_FOUND',
  );
  const bad = join(root, 'badpriv.pem');
  writeFileSync(bad, 'not a key');
  assert.equal(
    policySign(bad, { policy: p, signature: join(root, 'x.sig') }).stderr.errorCode,
    'KEY_NOT_FOUND',
  );
});

test('未启用策略签名时 verify 输出不含 policySignerFingerprint（行为不变）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verify(paths.art, paths.out, k.pub);
  assert.equal(v.code, 0);
  assert.ok(!('policySignerFingerprint' in v.stdout));
  const p = writePolicy({ policyVersion: '1.0' });
  const v2 = verifyWithPolicy(k.pub, p);
  assert.equal(v2.code, 0);
  assert.equal(v2.stdout.policyStatus, 'PASS');
  assert.ok(!('policySignerFingerprint' in v2.stdout));
});

// ---------------------------------------------------------------------------
// 策略 1.1：文件级发布准入（requiredFiles / forbiddenFiles）
// ---------------------------------------------------------------------------

const ZERO_DIGEST = '0'.repeat(64);

function proofFileMap() {
  return new Map(readProof().files.map((f) => [f.path, f]));
}

test('1.1 策略通过：requiredFiles 全部命中且摘要一致，forbiddenFiles 均不出现', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const files = proofFileMap();
  const p = writePolicy({
    policyVersion: '1.1',
    requiredFiles: {
      'a.txt': files.get('a.txt').sha256,
      'sub/b.txt': files.get('sub/b.txt').sha256,
      'sub/deep/c.bin': files.get('sub/deep/c.bin').sha256,
      'empty.bin': files.get('empty.bin').sha256,
    },
    forbiddenFiles: ['not-there.txt', 'sub/missing.bin'],
  }, 'policy-11-good.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('1.1 接受全部旧字段（时间窗口、指纹、SBOM、文件数、大小）并通过', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof();
  const files = proofFileMap();
  const p = writePolicy({
    policyVersion: '1.1',
    proofNotBefore: '2000-01-01T00:00:00Z',
    proofNotAfter: '2099-01-01T00:00:00Z',
    allowedKeyFingerprints: [proof.signerKeyFingerprint],
    requireSbom: false,
    maxFileCount: 4,
    maxSize: proof.size,
    requiredFiles: { 'a.txt': files.get('a.txt').sha256 },
    forbiddenFiles: ['absent.txt'],
  }, 'policy-11-all.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('requiredFiles 路径缺失 -> required-file-missing，observed 为路径', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({
    policyVersion: '1.1',
    requiredFiles: { 'does/not/exist.bin': ZERO_DIGEST },
  }, 'policy-11-missing.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'required-file-missing', observed: 'does/not/exist.bin' },
  ]);
});

test('requiredFiles 摘要不符 -> required-file-digest-mismatch，observed 为实际摘要（小写）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const actual = proofFileMap().get('a.txt').sha256;
  const p = writePolicy({
    policyVersion: '1.1',
    requiredFiles: { 'a.txt': ZERO_DIGEST },
  }, 'policy-11-digest.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'required-file-digest-mismatch', observed: actual },
  ]);
  assert.match(actual, /^[0-9a-f]{64}$/);
});

test('forbiddenFiles 路径出现 -> forbidden-file-present，observed 为路径', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({
    policyVersion: '1.1',
    forbiddenFiles: ['sub/deep/c.bin'],
  }, 'policy-11-forbidden.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'forbidden-file-present', observed: 'sub/deep/c.bin' },
  ]);
});

test('三类文件违规排序：先 missing 后 digest-mismatch 再 forbidden，同类按路径 UTF-16 码元升序', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const files = proofFileMap();
  // 缺失路径中 z-* 字典序晚于 a-*，仍应排在所有 digest-mismatch 之前，
  // 证明排序按“违规小类分组 + 组内路径”，而非跨小类的全局路径排序。
  const p = writePolicy({
    policyVersion: '1.1',
    requiredFiles: {
      'sub/b.txt': ZERO_DIGEST, // 存在但摘要不符
      'a.txt': ZERO_DIGEST, // 存在但摘要不符（路径序早于 sub/b.txt）
      'z-missing.txt': ZERO_DIGEST, // 缺失
      'a-missing.txt': ZERO_DIGEST, // 缺失
    },
    forbiddenFiles: ['empty.bin'], // 存在
  }, 'policy-11-order.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'required-file-missing', observed: 'a-missing.txt' },
    { rule: 'required-file-missing', observed: 'z-missing.txt' },
    { rule: 'required-file-digest-mismatch', observed: files.get('a.txt').sha256 },
    { rule: 'required-file-digest-mismatch', observed: files.get('sub/b.txt').sha256 },
    { rule: 'forbidden-file-present', observed: 'empty.bin' },
  ]);
});

test('新规则排在时间、密钥、SBOM、文件数、大小规则之后', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const p = writePolicy({
    policyVersion: '1.1',
    proofNotBefore: '2099-01-01T00:00:00Z',
    allowedKeyFingerprints: ['a'.repeat(64)],
    requireSbom: true,
    maxFileCount: 0,
    maxSize: 0,
    forbiddenFiles: ['a.txt'],
  }, 'policy-11-after-legacy.json');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(
    v.stderr.details.violations.map((x) => x.rule),
    [
      'proof-not-before',
      'allowed-key-fingerprints',
      'require-sbom',
      'max-file-count',
      'max-size',
      'forbidden-file-present',
    ],
  );
});

test('路径按清单 Unicode 大小写精确匹配：A.TXT 不命中 a.txt', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const digestA = proofFileMap().get('a.txt').sha256;

  // 仅大小写不同的禁止路径不构成违规。
  const forbidUpper = writePolicy(
    { policyVersion: '1.1', forbiddenFiles: ['A.TXT', 'Sub/b.txt'] },
    'policy-11-case-forbid.json',
  );
  const v1 = verifyWithPolicy(k.pub, forbidUpper);
  assert.equal(v1.code, 0, JSON.stringify(v1.stderr));
  assert.equal(v1.stdout.policyStatus, 'PASS');

  // 仅大小写不同的必需路径按缺失处理，而非匹配到 a.txt。
  const requireUpper = writePolicy(
    { policyVersion: '1.1', requiredFiles: { 'A.TXT': digestA } },
    'policy-11-case-require.json',
  );
  const v2 = verifyWithPolicy(k.pub, requireUpper);
  assert.equal(v2.code, 1);
  assert.equal(v2.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v2.stderr.details.violations, [
    { rule: 'required-file-missing', observed: 'A.TXT' },
  ]);
});

test('1.1 策略非法 -> POLICY_INVALID（版本、类型、空值、摘要、路径、重复、重叠）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const cases = [
    [JSON.stringify({ policyVersion: '1.0', requiredFiles: { 'a.txt': d } }), '1.0-required'],
    [JSON.stringify({ policyVersion: '1.0', forbiddenFiles: ['a.txt'] }), '1.0-forbidden'],
    [JSON.stringify({ policyVersion: '1.2', requiredFiles: { 'a.txt': d } }), 'bad-version'],
    [JSON.stringify({ policyVersion: '1.1', unknown: 1 }), 'unknown-field'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: {} }), 'empty-required'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: [] }), 'empty-forbidden'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: [] }), 'required-array'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: 'x' }), 'required-string'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: null }), 'required-null'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: {} }), 'forbidden-object'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: 'x' }), 'forbidden-string'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: { 'a.txt': 123 } }), 'digest-number'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: { 'a.txt': 'XYZ' } }), 'digest-chars'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: { 'a.txt': 'a'.repeat(63) } }), 'digest-short'],
    [JSON.stringify({ policyVersion: '1.1', requiredFiles: { 'a.txt': 'A'.repeat(64) } }), 'digest-uppercase'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['/a.txt'] }), 'absolute'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a\\b.txt'] }), 'backslash'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a//b'] }), 'empty-segment'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a/'] }), 'trailing-slash'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['/'] }), 'root-slash'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['../a'] }), 'dotdot'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a/./b'] }), 'dot-segment'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['.'] }), 'single-dot'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: [''] }), 'empty-path'],
    [JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a.txt', 'a.txt'] }), 'duplicate'],
    [
      JSON.stringify({
        policyVersion: '1.1',
        requiredFiles: { 'a.txt': d },
        forbiddenFiles: ['a.txt'],
      }),
      'overlap',
    ],
  ];
  for (const [content, name] of cases) {
    const p = writePolicy(content, `policy-11-invalid-${name}.json`);
    const v = verifyWithPolicy(k.pub, p);
    assert.equal(v.code, 1, name);
    assert.equal(v.stderr.errorCode, 'POLICY_INVALID', `${name}: ${JSON.stringify(v.stderr)}`);
    assert.equal(v.stdout, null, name);
  }
});

test('policy-sign 支持 1.1：签名往返成功、重复生成逐字节一致且不改写策略', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const p = writePolicy({
    policyVersion: '1.1',
    requiredFiles: { 'a.txt': d },
    forbiddenFiles: ['evil.bin'],
  }, 'policy-11-sign.json');
  const before = readFileSync(p);

  const s1 = join(root, 'p11-a.sig');
  const s2 = join(root, 'p11-b.sig');
  const r1 = policySign(k.priv, { policy: p, signature: s1 });
  const r2 = policySign(k.priv, { policy: p, signature: s2 });
  assert.equal(r1.code, 0, JSON.stringify(r1.stderr));
  assert.equal(r1.stdout.status, 'POLICY_SIGNED');
  assert.equal(r2.code, 0);
  assert.deepEqual(readFileSync(s1), readFileSync(s2)); // 逐字节确定
  assert.deepEqual(readFileSync(p), before); // 不改写策略

  const v = verifyWithPolicySig(k.pub, p, s1, k.pub);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
  assert.match(v.stdout.policySignerFingerprint, /^[0-9a-f]{64}$/);
});

test('policy-sign 直接拒绝非法 1.1 策略（重叠/绝对路径/大写摘要）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const badCases = [
    { policyVersion: '1.1', requiredFiles: { 'a.txt': d }, forbiddenFiles: ['a.txt'] },
    { policyVersion: '1.1', forbiddenFiles: ['/etc/passwd'] },
    { policyVersion: '1.1', requiredFiles: { 'a.txt': 'A'.repeat(64) } },
  ];
  badCases.forEach((obj, i) => {
    const p = writePolicy(obj, `policy-11-badsign-${i}.json`);
    const r = policySign(k.priv, { policy: p, signature: join(root, `p11-bad-${i}.sig`) });
    assert.equal(r.code, 1, `case ${i}`);
    assert.equal(r.stderr.errorCode, 'POLICY_INVALID', `case ${i}`);
  });
});

test('签名后的 1.1 策略被篡改 -> SIGNATURE_INVALID（先于文件规则评估）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const p = writePolicy({ policyVersion: '1.1', requiredFiles: { 'a.txt': d } }, 'policy-11-tamper.json');
  policySign(k.priv, { policy: p, signature: join(root, 'p11-tamper.sig') });
  // 改成必然违规的取值，但签名仍对应旧内容 -> SIGNATURE_INVALID 而非 VIOLATION。
  writeFileSync(p, JSON.stringify({ policyVersion: '1.1', forbiddenFiles: ['a.txt'] }));
  const v = verifyWithPolicySig(k.pub, p, join(root, 'p11-tamper.sig'), k.pub);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('产物篡改优先于 1.1 文件规则 -> INTEGRITY_MISMATCH', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const p = writePolicy({ policyVersion: '1.1', requiredFiles: { 'a.txt': d } }, 'policy-11-tamper-art.json');
  // 修改 a.txt：完整性阶段先失败，即使其摘要也必然不再匹配 requiredFiles。
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
  assert.ok(v.stderr.details.mismatches.some((m) => m.path === 'a.txt' && m.kind === 'content-modified'));
});

test('错误公钥 / 危险符号链接在 1.1 策略下仍返回原有错误码', () => {
  const k = keygen(paths.keys);
  const k2 = keygen(paths.keys2);
  generate(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;
  const p = writePolicy({ policyVersion: '1.1', requiredFiles: { 'a.txt': d } }, 'policy-11-prio.json');

  // 错误公钥 -> KEY_NOT_FOUND。
  assert.equal(verifyWithPolicy(k2.pub, p).stderr.errorCode, 'KEY_NOT_FOUND');

  // 越界符号链接 -> SYMLINK_INVALID（签名有效后的扫描阶段先于策略）。
  writeFileSync(join(root, 'secret.txt'), 'top secret');
  symlinkSync(join(root, 'secret.txt'), join(paths.art, 'leak.txt'));
  const v = verifyWithPolicy(k.pub, p);
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'SYMLINK_INVALID');
  assert.equal(v.stderr.details.reason, 'outside-root');
});

test('bundle 模式：1.1 策略往返（PASS）与禁止文件违规', () => {
  const k = keygen(paths.keys);
  const g = generateBundle(paths.art, k.priv, paths.out);
  const d = proofFileMap().get('a.txt').sha256;

  const good = writePolicy(
    { policyVersion: '1.1', requiredFiles: { 'a.txt': d }, forbiddenFiles: ['absent.bin'] },
    'policy-11-bundle-good.json',
  );
  const v1 = verifyBundle(paths.art, g.bundlePath, k.pub, ['--policy', good]);
  assert.equal(v1.code, 0, JSON.stringify(v1.stderr));
  assert.equal(v1.stdout.policyStatus, 'PASS');

  const bad = writePolicy(
    { policyVersion: '1.1', forbiddenFiles: ['sub/b.txt'] },
    'policy-11-bundle-bad.json',
  );
  const v2 = verifyBundle(paths.art, g.bundlePath, k.pub, ['--policy', bad]);
  assert.equal(v2.code, 1);
  assert.equal(v2.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v2.stderr.details.violations, [
    { rule: 'forbidden-file-present', observed: 'sub/b.txt' },
  ]);
});

test('共签 + 1.1 策略：全部通过时同时输出 cosignerCount 与 policyStatus', () => {
  const { main, co1 } = setupCosign();
  generateWithCoKeys(paths.art, main.priv, paths.out, [co1.priv]);
  const d = proofFileMap().get('a.txt').sha256;
  const p = writePolicy(
    { policyVersion: '1.1', requiredFiles: { 'a.txt': d, 'sub/b.txt': proofFileMap().get('sub/b.txt').sha256 } },
    'policy-11-cosign.json',
  );
  const v = verifyWithCosign(paths.art, paths.out, main.pub, [co1.pub], 1, { policy: p });
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.cosignerCount, 1);
  assert.equal(v.stdout.policyStatus, 'PASS');
});
