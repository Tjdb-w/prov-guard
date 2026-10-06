// Prov Guard 发布门禁（gate）端到端测试：以子进程方式驱动 CLI。
// 运行：node --test
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { buildSbom, computeArtifactDigest, stableJsonStringify } from '../provguard.mjs';

const CLI = fileURLToPath(new URL('../provguard.mjs', import.meta.url));

let root;
let art;
let digest;
let signerKey;
let proofPath;
let sbomPath;
let policyPath;

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
  return { code: res.status, stdout, stderr, rawStdout: res.stdout, rawStderr: res.stderr };
}

// 构造自包含签名证明：公钥内嵌，签名为对去除 signature 字段后稳定 JSON 的 Ed25519 签名。
function makeProof(overrides = {}) {
  const proof = {
    artifactDigest: digest,
    source: 'https://github.com/example/widget#refs/tags/v1.2.3',
    signer: 'release-bot@example.com',
    publicKey: signerKey.pubPem,
    ...overrides,
  };
  const canonical = stableJsonStringify(proof);
  return { ...proof, signature: cryptoSign(null, Buffer.from(canonical, 'utf8'), signerKey.priv).toString('base64') };
}

function makeSbom(overrides = {}) {
  return {
    artifactDigest: digest,
    packages: [
      { name: 'left-pad', version: '1.0.0', license: 'MIT' },
      { name: 'widget-core', version: '2.1.0', license: 'Apache-2.0' },
    ],
    ...overrides,
  };
}

function makePolicy(overrides = {}) {
  return {
    allowedSources: ['https://github.com/example/widget#refs/tags/v1.2.3'],
    allowedSigners: ['release-bot@example.com'],
    artifactDigest: digest,
    allowedPackages: ['left-pad', 'widget-core'],
    allowedLicenses: ['MIT', 'Apache-2.0', 'BSD-2-Clause'],
    ...overrides,
  };
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function gate(overrides = {}) {
  return run([
    'gate',
    '--artifact', overrides.artifact ?? art,
    '--proof', overrides.proof ?? proofPath,
    '--sbom', overrides.sbom ?? sbomPath,
    '--policy', overrides.policy ?? policyPath,
  ]);
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'provguard-gate-test-'));
  art = join(root, 'art');
  mkdirSync(join(art, 'sub'), { recursive: true });
  writeFileSync(join(art, 'a.txt'), 'hello world\n');
  writeFileSync(join(art, 'sub', 'b.txt'), 'nested\n');
  digest = computeArtifactDigest(await buildSbom(art, null));

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  signerKey = {
    priv: privateKey,
    pubPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };

  proofPath = join(root, 'proof.json');
  sbomPath = join(root, 'sbom.json');
  policyPath = join(root, 'policy.json');
  writeJson(proofPath, makeProof());
  writeJson(sbomPath, makeSbom());
  writeJson(policyPath, makePolicy());
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

test('gate 全部条件通过：输出 allowed 报告并以 0 退出', () => {
  const r = gate();
  assert.equal(r.code, 0, r.rawStderr);
  assert.equal(r.stdout.status, 'allowed');
  assert.equal(r.stdout.artifactDigest, digest);
  assert.equal(r.stdout.proofSource, 'https://github.com/example/widget#refs/tags/v1.2.3');
  assert.equal(r.stdout.signer, 'release-bot@example.com');
  assert.equal(r.stdout.packageCount, 2);
  assert.deepEqual(
    r.stdout.conditions.map((c) => [c.id, c.result]),
    [['source', 'pass'], ['signer', 'pass'], ['digest', 'pass'], ['packages', 'pass'], ['licenses', 'pass']],
  );
});

test('gate 报告键按固定顺序输出（顶层与条件条目）', () => {
  const r = gate();
  assert.equal(r.code, 0, r.rawStderr);
  const topKeys = ['status', 'artifactDigest', 'proofSource', 'signer', 'packageCount', 'conditions'];
  const positions = topKeys.map((k) => r.rawStdout.indexOf(`"${k}"`));
  for (let i = 1; i < positions.length; i += 1) {
    assert.ok(positions[i] > positions[i - 1], `键顺序错误: ${topKeys.join(',')}`);
  }
  const cond = r.rawStdout.indexOf('"conditions"');
  const idPos = r.rawStdout.indexOf('"id"', cond);
  const observedPos = r.rawStdout.indexOf('"observed"', cond);
  const resultPos = r.rawStdout.indexOf('"result"', cond);
  assert.ok(idPos < observedPos && observedPos < resultPos, '条件条目键顺序应为 id/observed/result');
});

test('gate 策略只含部分条件时报告仅覆盖这些条件', () => {
  writeJson(policyPath, { allowedLicenses: ['MIT', 'Apache-2.0'] });
  const r = gate();
  assert.equal(r.code, 0, r.rawStderr);
  assert.equal(r.stdout.status, 'allowed');
  assert.deepEqual(r.stdout.conditions, [
    { id: 'licenses', observed: ['Apache-2.0', 'MIT'], result: 'pass' },
  ]);
});

test('gate 许可证违规：输出 denied 报告并以 4 退出（非系统错误）', () => {
  writeJson(sbomPath, makeSbom({
    packages: [
      { name: 'left-pad', license: 'MIT' },
      { name: 'evil-lib', license: 'GPL-3.0' },
    ],
  }));
  writeJson(policyPath, makePolicy({ allowedPackages: ['left-pad', 'evil-lib'] }));
  const r = gate();
  assert.equal(r.code, 4, r.rawStderr);
  assert.equal(r.stdout.status, 'denied');
  const licenses = r.stdout.conditions.find((c) => c.id === 'licenses');
  assert.equal(licenses.result, 'fail');
  assert.deepEqual(licenses.observed, ['GPL-3.0', 'MIT']);
  // denied 是正常业务结果：stderr 为空。
  assert.equal(r.rawStderr, '');
});

test('gate 来源与签名主体违规：对应条件判定 fail', () => {
  writeJson(policyPath, {
    allowedSources: ['https://github.com/example/other#main'],
    allowedSigners: ['someone-else@example.com'],
  });
  const r = gate();
  assert.equal(r.code, 4, r.rawStderr);
  assert.equal(r.stdout.status, 'denied');
  assert.deepEqual(r.stdout.conditions, [
    { id: 'source', observed: 'https://github.com/example/widget#refs/tags/v1.2.3', result: 'fail' },
    { id: 'signer', observed: 'release-bot@example.com', result: 'fail' },
  ]);
});

test('gate 包名范围违规：packages 条件 fail 且 observed 为实际包名列表', () => {
  writeJson(policyPath, { allowedPackages: ['left-pad'] });
  const r = gate();
  assert.equal(r.code, 4, r.rawStderr);
  assert.deepEqual(r.stdout.conditions, [
    { id: 'packages', observed: ['left-pad', 'widget-core'], result: 'fail' },
  ]);
});

test('gate 策略摘要与产物不一致（证明有效）：digest 条件 fail，以 4 退出', () => {
  const other = '0'.repeat(64);
  writeJson(policyPath, { artifactDigest: other });
  const r = gate();
  assert.equal(r.code, 4, r.rawStderr);
  assert.deepEqual(r.stdout.conditions, [{ id: 'digest', observed: digest, result: 'fail' }]);
});

test('gate 缺少必填参数：stderr 输出 InputError 并以 2 退出', () => {
  const r = run(['gate', '--artifact', art, '--proof', proofPath]);
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate 输入路径不存在：InputError + 退出码 2', () => {
  const r = gate({ proof: join(root, 'no-such-proof.json') });
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate 证明 JSON 语法错误：InputError + 退出码 2', () => {
  writeFileSync(proofPath, '{ not json', 'utf8');
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate 证明缺少必需字段：InputError + 退出码 2', () => {
  const p = makeProof();
  delete p.signer;
  writeJson(proofPath, p);
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate SBOM 缺少 packages 字段：InputError + 退出码 2', () => {
  writeJson(sbomPath, { artifactDigest: digest });
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate 空策略：PolicyError + 退出码 2', () => {
  writeJson(policyPath, {});
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'PolicyError');
});

test('gate 未知条件类型：PolicyError + 退出码 2', () => {
  writeJson(policyPath, { allowedLicenses: ['MIT'], maxFileCount: 3 });
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'PolicyError');
});

test('gate 条件值不符合定义：PolicyError + 退出码 2', () => {
  writeJson(policyPath, { allowedLicenses: [] });
  assert.equal(gate().code, 2);
  assert.equal(gate().stderr.errorCode, 'PolicyError');
  writeJson(policyPath, { artifactDigest: 'not-a-digest' });
  const r = gate();
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'PolicyError');
});

test('gate 证明被篡改（签名无效）：VerificationError + 退出码 3', () => {
  const p = makeProof();
  p.source = 'https://evil.example.com/repo#main'; // 篡改已签名内容
  writeJson(proofPath, p);
  const r = gate();
  assert.equal(r.code, 3);
  assert.equal(r.stderr.errorCode, 'VerificationError');
});

test('gate 证明摘要与实际产物不一致：VerificationError + 退出码 3', () => {
  writeFileSync(join(art, 'extra.txt'), 'tampered\n'); // 改变产物但不改证明
  const r = gate();
  assert.equal(r.code, 3);
  assert.equal(r.stderr.errorCode, 'VerificationError');
});

test('gate SBOM 与产物无法对应：VerificationError + 退出码 3', () => {
  writeJson(sbomPath, makeSbom({ artifactDigest: 'f'.repeat(64) }));
  const r = gate();
  assert.equal(r.code, 3);
  assert.equal(r.stderr.errorCode, 'VerificationError');
});

test('gate 产物路径不存在：InputError + 退出码 2', () => {
  const r = gate({ artifact: join(root, 'no-such-artifact') });
  assert.equal(r.code, 2);
  assert.equal(r.stderr.errorCode, 'InputError');
});

test('gate 不写出任何业务数据文件', () => {
  const listingBefore = readdirSync(root).sort();
  const r = gate();
  assert.equal(r.code, 0, r.rawStderr);
  assert.deepEqual(readdirSync(root).sort(), listingBefore);
});
