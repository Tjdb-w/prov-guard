// Prov Guard 端到端测试：以子进程方式驱动 provguard.mjs CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

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
// 验证策略（--policy）
// ---------------------------------------------------------------------------

function writePolicy(obj) {
  const p = join(root, 'policy.json');
  writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj));
  return p;
}

function verifyWithPolicy(artifact, out, pub, policyPath, overrides = {}) {
  const args = [
    'verify',
    '--artifact', overrides.artifact ?? artifact,
    '--proof', overrides.proof ?? join(out, 'proof.json'),
    '--signature', overrides.signature ?? join(out, 'proof.json.sig'),
    '--key', overrides.key ?? pub,
    '--policy', policyPath,
  ];
  if (overrides.sbom) args.push('--sbom', overrides.sbom);
  if (overrides.sbomSignature) args.push('--sbom-signature', overrides.sbomSignature);
  return run(args);
}

function readProof(out) {
  return JSON.parse(readFileSync(join(out, 'proof.json'), 'utf8'));
}

// 与 provguard.mjs 相同的稳定序列化：键排序、两空格缩进。
function stableJson(value) {
  const sortDeep = (v) => {
    if (Array.isArray(v)) return v.map(sortDeep);
    if (v !== null && typeof v === 'object') {
      const o = {};
      for (const k of Object.keys(v).sort()) o[k] = sortDeep(v[k]);
      return o;
    }
    return v;
  };
  return JSON.stringify(sortDeep(value), null, 2);
}

// 修改证明并重新签名（用于构造“签名有效但策略不通过”的场景）。
function resignProof(out, privPath, mutate) {
  const proofPath = join(out, 'proof.json');
  const proof = JSON.parse(readFileSync(proofPath, 'utf8'));
  mutate(proof);
  const canonical = stableJson(proof);
  writeFileSync(proofPath, `${canonical}\n`);
  const priv = createPrivateKey(readFileSync(privPath));
  const sig = cryptoSign(null, Buffer.from(canonical, 'utf8'), priv);
  writeFileSync(join(out, 'proof.json.sig'), `${sig.toString('base64')}\n`);
  return proof;
}

test('策略全部满足 -> VERIFIED 且 policyStatus 为 PASS', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    proofNotBefore: '2000-01-01T00:00:00Z',
    proofNotAfter: '2100-01-01T00:00:00Z',
    allowedKeyFingerprints: [proof.signerKeyFingerprint],
    requireSbom: true,
    maxFileCount: 4,
    maxSize: proof.size,
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy, {
    sbom: join(paths.out, 'sbom.json'),
    sbomSignature: join(paths.out, 'sbom.json.sig'),
  });
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.status, 'VERIFIED');
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('仅 policyVersion 的最简策略 -> PASS；不带 --policy 时无 policyStatus 字段', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v1 = verifyWithPolicy(paths.art, paths.out, k.pub, writePolicy({ policyVersion: '1.0' }));
  assert.equal(v1.code, 0, JSON.stringify(v1.stderr));
  assert.equal(v1.stdout.policyStatus, 'PASS');

  const v2 = verify(paths.art, paths.out, k.pub);
  assert.equal(v2.code, 0, JSON.stringify(v2.stderr));
  assert.ok(!('policyStatus' in v2.stdout));
});

test('指纹大小写不敏感：策略中指纹大写仍 PASS', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    allowedKeyFingerprints: [proof.signerKeyFingerprint.toUpperCase()],
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('生成时间晚于 proofNotAfter -> POLICY_VIOLATION / generated-at-after-not-after', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({ policyVersion: '1.0', proofNotAfter: '2000-01-01T00:00:00Z' });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.code, 1);
  assert.equal(v.stdout, null);
  assert.equal(v.stderr.status, 'ERROR');
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'generated-at-after-not-after', observed: proof.generatedAt },
  ]);
});

test('生成时间早于 proofNotBefore -> POLICY_VIOLATION / generated-at-before-not-before', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({ policyVersion: '1.0', proofNotBefore: '2100-01-01T00:00:00Z' });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'generated-at-before-not-before', observed: proof.generatedAt },
  ]);
});

test('时间边界为闭区间：generatedAt 恰等于边界时通过', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    proofNotBefore: proof.generatedAt,
    proofNotAfter: proof.generatedAt,
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('签名密钥指纹不在信任列表 -> POLICY_VIOLATION / key-fingerprint-not-allowed', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    allowedKeyFingerprints: ['0'.repeat(64)],
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'key-fingerprint-not-allowed', observed: proof.signerKeyFingerprint },
  ]);
});

test('requireSbom 为 true 但未提供 SBOM -> POLICY_VIOLATION / sbom-required；提供则通过', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const policy = writePolicy({ policyVersion: '1.0', requireSbom: true });

  const v1 = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v1.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v1.stderr.details.violations, [{ rule: 'sbom-required', observed: false }]);

  const v2 = verifyWithPolicy(paths.art, paths.out, k.pub, policy, {
    sbom: join(paths.out, 'sbom.json'),
    sbomSignature: join(paths.out, 'sbom.json.sig'),
  });
  assert.equal(v2.code, 0, JSON.stringify(v2.stderr));
  assert.equal(v2.stdout.policyStatus, 'PASS');
});

test('requireSbom 为 false 不禁止额外 SBOM', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const policy = writePolicy({ policyVersion: '1.0', requireSbom: false });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy, {
    sbom: join(paths.out, 'sbom.json'),
    sbomSignature: join(paths.out, 'sbom.json.sig'),
  });
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('文件数与总大小超限 -> POLICY_VIOLATION，违规按规则排序', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    proofNotAfter: '2000-01-01T00:00:00Z',
    allowedKeyFingerprints: ['0'.repeat(64)],
    maxFileCount: 3,
    maxSize: proof.size - 1,
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(
    v.stderr.details.violations.map((x) => x.rule),
    ['generated-at-after-not-after', 'key-fingerprint-not-allowed', 'file-count-exceeded', 'size-exceeded'],
  );
  const byRule = Object.fromEntries(v.stderr.details.violations.map((x) => [x.rule, x.observed]));
  assert.equal(byRule['file-count-exceeded'], 4);
  assert.equal(byRule['size-exceeded'], proof.size);
});

test('上限含边界：maxFileCount/maxSize 恰好相等时通过', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proof = readProof(paths.out);
  const policy = writePolicy({
    policyVersion: '1.0',
    maxFileCount: proof.files.length,
    maxSize: proof.size,
  });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.code, 0, JSON.stringify(v.stderr));
  assert.equal(v.stdout.policyStatus, 'PASS');
});

test('generatedAt 非法（签名有效）-> POLICY_VIOLATION / generated-at-invalid', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  resignProof(paths.out, k.priv, (p) => {
    p.generatedAt = 'not-a-time';
  });
  const policy = writePolicy({ policyVersion: '1.0', proofNotAfter: '2100-01-01T00:00:00Z' });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
  assert.deepEqual(v.stderr.details.violations, [
    { rule: 'generated-at-invalid', observed: 'not-a-time' },
  ]);
});

test('策略不输出部分成功：违规时 stdout 无 VERIFIED', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const policy = writePolicy({ policyVersion: '1.0', maxFileCount: 0 });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.code, 1);
  assert.equal(v.stdout, null);
  assert.equal(v.stderr.errorCode, 'POLICY_VIOLATION');
});

test('产物被篡改时即使有策略也按原错误码返回（INTEGRITY_MISMATCH）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  writeFileSync(join(paths.art, 'a.txt'), 'CHANGED\n');
  const policy = writePolicy({ policyVersion: '1.0', maxFileCount: 100 });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'INTEGRITY_MISMATCH');
});

test('签名无效时即使有策略也按原错误码返回（SIGNATURE_INVALID）', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const proofPath = join(paths.out, 'proof.json');
  const proof = JSON.parse(readFileSync(proofPath, 'utf8'));
  proof.generatedAt = '2000-01-01T00:00:00.000Z';
  writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
  const policy = writePolicy({ policyVersion: '1.0' });
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, policy);
  assert.equal(v.stderr.errorCode, 'SIGNATURE_INVALID');
});

test('策略文件不存在 -> INPUT_NOT_FOUND', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verifyWithPolicy(paths.art, paths.out, k.pub, join(root, 'nope-policy.json'));
  assert.equal(v.code, 1);
  assert.equal(v.stderr.errorCode, 'INPUT_NOT_FOUND');
});

test('策略 JSON 不可解析或顶层非对象 -> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  for (const content of ['{broken', '[1,2]', '"str"', '42', 'null']) {
    const v = verifyWithPolicy(paths.art, paths.out, k.pub, writePolicy(content));
    assert.equal(v.code, 1, content);
    assert.equal(v.stderr.errorCode, 'POLICY_INVALID', content);
  }
});

test('策略缺 policyVersion 或取值不符 -> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  for (const obj of [{}, { policyVersion: '2.0' }, { policyVersion: 1 }]) {
    const v = verifyWithPolicy(paths.art, paths.out, k.pub, writePolicy(obj));
    assert.equal(v.stderr.errorCode, 'POLICY_INVALID', JSON.stringify(obj));
  }
});

test('策略含未知字段 -> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verifyWithPolicy(
    paths.art, paths.out, k.pub,
    writePolicy({ policyVersion: '1.0', unexpected: true }),
  );
  assert.equal(v.stderr.errorCode, 'POLICY_INVALID');
});

test('策略字段类型或取值非法 -> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const badPolicies = [
    { policyVersion: '1.0', proofNotBefore: 'not-a-time' },
    { policyVersion: '1.0', proofNotAfter: '2026-01-01' }, // 缺时间部分
    { policyVersion: '1.0', allowedKeyFingerprints: [] }, // 空数组不接受
    { policyVersion: '1.0', allowedKeyFingerprints: 'abc' },
    { policyVersion: '1.0', allowedKeyFingerprints: ['xyz'] },
    { policyVersion: '1.0', requireSbom: 'yes' },
    { policyVersion: '1.0', maxFileCount: -1 },
    { policyVersion: '1.0', maxFileCount: 1.5 },
    { policyVersion: '1.0', maxSize: Number.MAX_SAFE_INTEGER + 1 },
    { policyVersion: '1.0', maxSize: '100' },
  ];
  for (const obj of badPolicies) {
    const v = verifyWithPolicy(paths.art, paths.out, k.pub, writePolicy(obj));
    assert.equal(v.code, 1, JSON.stringify(obj));
    assert.equal(v.stderr.errorCode, 'POLICY_INVALID', JSON.stringify(obj));
  }
});

test('proofNotBefore 晚于 proofNotAfter -> POLICY_INVALID', () => {
  const k = keygen(paths.keys);
  generate(paths.art, k.priv, paths.out);
  const v = verifyWithPolicy(
    paths.art, paths.out, k.pub,
    writePolicy({
      policyVersion: '1.0',
      proofNotBefore: '2100-01-01T00:00:00Z',
      proofNotAfter: '2000-01-01T00:00:00Z',
    }),
  );
  assert.equal(v.stderr.errorCode, 'POLICY_INVALID');
});
