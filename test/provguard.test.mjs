// Prov Guard 集成与单元测试（node:test，无第三方依赖）。
import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  computeArtifactDigest,
  diffFiles,
  parseProof,
  proofCanonical,
  stableJSONStringify,
} from '../src/core.mjs';

const CLI = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'src',
  'cli.mjs',
);

let tmpRoot;

before(() => {
  tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'provguard-test-'));
});

after(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function run(...args) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
  });
  let json = null;
  try {
    json = JSON.parse(res.stdout);
  } catch {
    // 保留原始输出便于断言非 JSON 场景
  }
  return { code: res.status, json, stdout: res.stdout, stderr: res.stderr };
}

let seq = 0;
function freshDir(prefix) {
  const dir = path.join(tmpRoot, `${prefix}-${seq++}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// 构建一个含多级目录、空文件、二进制与文本的标准产物。
function makeArtifact(root) {
  mkdirSync(path.join(root, 'sub', 'deep'), { recursive: true });
  writeFileSync(path.join(root, 'a.txt'), 'hello artifact\n');
  writeFileSync(path.join(root, 'sub', 'b.json'), '{"v":1}\n');
  writeFileSync(path.join(root, 'sub', 'deep', 'c.bin'), Buffer.from([
    0x00, 0x01, 0xff, 0x10, 0x7f,
  ]));
  writeFileSync(path.join(root, 'empty.dat'), Buffer.alloc(0));
}

function setupGeneratedArtifact() {
  const root = freshDir('case');
  const artifact = path.join(root, 'artifact');
  mkdirSync(artifact);
  makeArtifact(artifact);
  const keys = path.join(root, 'keys');
  const out = path.join(root, 'out');
  run('keygen', '--out', keys);
  const gen = run(
    'generate',
    '--artifact', artifact,
    '--key', path.join(keys, 'private_key.pem'),
    '--out', out,
  );
  return { root, artifact, keys, out, gen };
}

function verifyOf(ctx, overrides = {}) {
  return run(
    'verify',
    '--artifact', overrides.artifact ?? ctx.artifact,
    '--proof', overrides.proof ?? path.join(ctx.out, 'proof.json'),
    '--signature', overrides.signature ?? path.join(ctx.out, 'proof.json.sig'),
    '--key', overrides.key ?? path.join(ctx.keys, 'public_key.pem'),
  );
}

// ---------------------------------------------------------------------------
// 生成 / 验证成功路径
// ---------------------------------------------------------------------------

describe('happy path', () => {
  test('keygen 生成 PEM 密钥对且私钥权限收窄', () => {
    const dir = freshDir('keygen');
    const r = run('keygen', '--out', dir);
    assert.equal(r.code, 0);
    assert.equal(r.json.status, 'KEYS_GENERATED');
    const priv = readFileSync(path.join(dir, 'private_key.pem'), 'utf8');
    const pub = readFileSync(path.join(dir, 'public_key.pem'), 'utf8');
    assert.match(priv, /PRIVATE KEY/);
    assert.match(pub, /PUBLIC KEY/);
    if (!('getuid' in process) || process.getuid() !== 0) {
      const mode = statSync(path.join(dir, 'private_key.pem')).mode & 0o777;
      assert.equal(mode, 0o600);
    }
  });

  test('无改动的产物验证通过，输出 VERIFIED/版本/摘要/条目数', () => {
    const ctx = setupGeneratedArtifact();
    assert.equal(ctx.gen.code, 0);
    assert.equal(ctx.gen.json.status, 'GENERATED');
    const v = verifyOf(ctx);
    assert.equal(v.code, 0, v.stdout);
    assert.equal(v.json.status, 'VERIFIED');
    assert.equal(v.json.version, '1.0');
    assert.match(v.json.artifact_digest, /^[0-9a-f]{64}$/);
    assert.equal(v.json.file_count, 4);
  });

  test('空目录产物：零文件也可生成并验证，摘要为 sha256 空输入', () => {
    const root = freshDir('empty');
    const artifact = path.join(root, 'art');
    mkdirSync(artifact);
    const keys = path.join(root, 'keys');
    const out = path.join(root, 'out');
    run('keygen', '--out', keys);
    const gen = run(
      'generate', '--artifact', artifact,
      '--key', path.join(keys, 'private_key.pem'), '--out', out,
    );
    assert.equal(gen.code, 0, gen.stdout);
    const v = run(
      'verify', '--artifact', artifact,
      '--proof', path.join(out, 'proof.json'),
      '--signature', path.join(out, 'proof.json.sig'),
      '--key', path.join(keys, 'public_key.pem'),
    );
    assert.equal(v.code, 0, v.stdout);
    assert.equal(v.json.file_count, 0);
    assert.equal(
      v.json.artifact_digest,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  test('零字节文件按真实文件记录（size=0、空内容摘要）', () => {
    const ctx = setupGeneratedArtifact();
    const sbom = JSON.parse(readFileSync(path.join(ctx.out, 'sbom.json'), 'utf8'));
    const empty = sbom.files.find((f) => f.path === 'empty.dat');
    assert.ok(empty);
    assert.equal(empty.size, 0);
    assert.equal(
      empty.sha256,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  test('相对路径统一使用正斜杠', () => {
    const ctx = setupGeneratedArtifact();
    const sbom = JSON.parse(readFileSync(path.join(ctx.out, 'sbom.json'), 'utf8'));
    const nested = sbom.files.find((f) => f.path === 'sub/deep/c.bin');
    assert.ok(nested, JSON.stringify(sbom.files.map((f) => f.path)));
    for (const f of sbom.files) assert.ok(!f.path.includes('\\'));
  });
});

// ---------------------------------------------------------------------------
// 篡改检测
// ---------------------------------------------------------------------------

describe('tamper detection', () => {
  let ctx;
  beforeEach(() => {
    ctx = setupGeneratedArtifact();
  });

  test('修改文件字节 -> INTEGRITY_MISMATCH(5) 且给出差异路径', () => {
    writeFileSync(path.join(ctx.artifact, 'a.txt'), 'HELLO artifact\n');
    const v = verifyOf(ctx);
    assert.equal(v.code, 5);
    assert.equal(v.json.error, 'INTEGRITY_MISMATCH');
    const d = v.json.detail.differences.find((x) => x.path === 'a.txt');
    assert.ok(d);
    assert.equal(d.kind, 'modified');
    assert.ok(d.fields.includes('sha256'));
  });

  test('等长内容替换也被捕获（大小不变、摘要变化）', () => {
    writeFileSync(path.join(ctx.artifact, 'a.txt'), 'hellX artifact\n');
    const v = verifyOf(ctx);
    assert.equal(v.code, 5);
    const d = v.json.detail.differences.find((x) => x.path === 'a.txt');
    assert.deepEqual(d.fields, ['sha256']);
  });

  test('新增文件 -> added', () => {
    writeFileSync(path.join(ctx.artifact, 'added.txt'), 'new');
    const v = verifyOf(ctx);
    assert.equal(v.code, 5);
    assert.equal(v.json.error, 'INTEGRITY_MISMATCH');
    assert.deepEqual(
      v.json.detail.differences,
      [{ kind: 'added', path: 'added.txt' }],
    );
  });

  test('删除文件 -> removed', () => {
    rmSync(path.join(ctx.artifact, 'empty.dat'));
    const v = verifyOf(ctx);
    assert.equal(v.code, 5);
    assert.deepEqual(
      v.json.detail.differences,
      [{ kind: 'removed', path: 'empty.dat' }],
    );
  });

  test('在子目录新增文件也被捕获', () => {
    writeFileSync(path.join(ctx.artifact, 'sub', 'x.txt'), 'x');
    const v = verifyOf(ctx);
    assert.equal(v.code, 5);
    assert.equal(v.json.detail.differences[0].path, 'sub/x.txt');
    assert.equal(v.json.detail.differences[0].kind, 'added');
  });

  test('任何失败都不会输出 VERIFIED', () => {
    writeFileSync(path.join(ctx.artifact, 'a.txt'), 'tampered');
    const v = verifyOf(ctx);
    assert.notEqual(v.code, 0);
    assert.notEqual(v.json?.status, 'VERIFIED');
    assert.ok(v.json?.error);
  });
});

// ---------------------------------------------------------------------------
// 签名 / 证明 / 密钥错误
// ---------------------------------------------------------------------------

describe('signature and key errors', () => {
  let ctx;
  beforeEach(() => {
    ctx = setupGeneratedArtifact();
  });

  test('使用错误公钥 -> KEY_NOT_FOUND(7)', () => {
    const otherKeys = path.join(ctx.root, 'keys2');
    run('keygen', '--out', otherKeys);
    const v = verifyOf(ctx, { key: path.join(otherKeys, 'public_key.pem') });
    assert.equal(v.code, 7);
    assert.equal(v.json.error, 'KEY_NOT_FOUND');
  });

  test('公钥文件不存在 -> KEY_NOT_FOUND(7)', () => {
    const v = verifyOf(ctx, { key: path.join(ctx.root, 'missing.pem') });
    assert.equal(v.code, 7);
    assert.equal(v.json.error, 'KEY_NOT_FOUND');
  });

  test('翻转签名字节 -> SIGNATURE_INVALID(6)', () => {
    const sigPath = path.join(ctx.out, 'proof.json.sig');
    const sig = readFileSync(sigPath);
    sig[0] ^= 0xff;
    const badSig = path.join(ctx.root, 'bad.sig');
    writeFileSync(badSig, sig);
    const v = verifyOf(ctx, { signature: badSig });
    assert.equal(v.code, 6);
    assert.equal(v.json.error, 'SIGNATURE_INVALID');
  });

  test('签名文件长度非法 -> PROOF_INVALID(4)', () => {
    const badSig = path.join(ctx.root, 'short.sig');
    writeFileSync(badSig, Buffer.alloc(63));
    let v = verifyOf(ctx, { signature: badSig });
    assert.equal(v.code, 4);
    assert.equal(v.json.error, 'PROOF_INVALID');

    writeFileSync(badSig, Buffer.alloc(65));
    v = verifyOf(ctx, { signature: badSig });
    assert.equal(v.code, 4);
  });

  test('证明 JSON 非法 -> PROOF_INVALID(4)', () => {
    const bad = path.join(ctx.root, 'bad.json');
    writeFileSync(bad, '{broken');
    const v = verifyOf(ctx, { proof: bad });
    assert.equal(v.code, 4);
    assert.equal(v.json.error, 'PROOF_INVALID');
  });

  test('证明缺字段 -> PROOF_INVALID(4)', () => {
    const bad = path.join(ctx.root, 'bad.json');
    const p = JSON.parse(readFileSync(path.join(ctx.out, 'proof.json'), 'utf8'));
    delete p.artifact_digest;
    writeFileSync(bad, JSON.stringify(p));
    const v = verifyOf(ctx, { proof: bad });
    assert.equal(v.code, 4);
    assert.equal(v.json.error, 'PROOF_INVALID');
  });

  test('证明字段被篡改但签名未改 -> SIGNATURE_INVALID(6)', () => {
    const bad = path.join(ctx.root, 'tampered-proof.json');
    const p = JSON.parse(readFileSync(path.join(ctx.out, 'proof.json'), 'utf8'));
    p.total_size += 1;
    writeFileSync(bad, JSON.stringify(p, null, 2) + '\n');
    const v = verifyOf(ctx, { proof: bad });
    assert.equal(v.code, 6);
    assert.equal(v.json.error, 'SIGNATURE_INVALID');
  });
});

// ---------------------------------------------------------------------------
// 输入错误
// ---------------------------------------------------------------------------

describe('input errors', () => {
  let ctx;
  beforeEach(() => {
    ctx = setupGeneratedArtifact();
  });

  test('产物路径不存在 -> INPUT_NOT_FOUND(2)', () => {
    const v = verifyOf(ctx, { artifact: path.join(ctx.root, 'nope') });
    assert.equal(v.code, 2);
    assert.equal(v.json.error, 'INPUT_NOT_FOUND');
  });

  test('证明文件不存在 -> INPUT_NOT_FOUND(2)', () => {
    const v = verifyOf(ctx, { proof: path.join(ctx.root, 'nope.json') });
    assert.equal(v.code, 2);
    assert.equal(v.json.error, 'INPUT_NOT_FOUND');
  });

  test('签名文件不存在 -> INPUT_NOT_FOUND(2)', () => {
    const v = verifyOf(ctx, { signature: path.join(ctx.root, 'nope.sig') });
    assert.equal(v.code, 2);
    assert.equal(v.json.error, 'INPUT_NOT_FOUND');
  });

  test('产物路径是文件而非目录 -> INPUT_NOT_FOUND(2)', () => {
    const file = path.join(ctx.root, 'file.txt');
    writeFileSync(file, 'x');
    const v = verifyOf(ctx, { artifact: file });
    assert.equal(v.code, 2);
    assert.equal(v.json.error, 'INPUT_NOT_FOUND');
  });

  test('输出目录与产物目录相同 -> 用法错误(1)，不产出任何文件', () => {
    const r = run(
      'generate', '--artifact', ctx.artifact,
      '--key', path.join(ctx.keys, 'private_key.pem'),
      '--out', ctx.artifact,
    );
    assert.equal(r.code, 1);
  });

  test('权限不足 -> PERMISSION_DENIED(3)（root 下跳过）', { skip:
    !('getuid' in process) || process.getuid() === 0
      ? '以 root 运行时权限位不生效'
      : false,
  }, () => {
    const target = path.join(ctx.artifact, 'a.txt');
    chmodSync(target, 0o000);
    const r = verifyOf(ctx);
    assert.equal(r.code, 3);
    assert.equal(r.json.error, 'PERMISSION_DENIED');
    chmodSync(target, 0o644);
  });
});

// ---------------------------------------------------------------------------
// 确定性 / 输出目录位置
// ---------------------------------------------------------------------------

describe('determinism and layout', () => {
  test('同一输入两次生成的 SBOM 字节完全相同，时间不影响摘要', () => {
    const ctx = setupGeneratedArtifact();
    const out2 = path.join(ctx.root, 'out2');
    const gen2 = run(
      'generate', '--artifact', ctx.artifact,
      '--key', path.join(ctx.keys, 'private_key.pem'), '--out', out2,
    );
    assert.equal(gen2.code, 0, gen2.stdout);
    const sbom1 = readFileSync(path.join(ctx.out, 'sbom.json'));
    const sbom2 = readFileSync(path.join(out2, 'sbom.json'));
    assert.ok(sbom1.equals(sbom2), 'SBOM 内容不一致');

    const p1 = JSON.parse(readFileSync(path.join(ctx.out, 'proof.json')));
    const p2 = JSON.parse(readFileSync(path.join(out2, 'proof.json')));
    assert.equal(p1.artifact_digest, p2.artifact_digest);
  });

  test('输出目录位于产物目录内部时自动排除，仍可验证通过', () => {
    const root = freshDir('nested-out');
    const artifact = path.join(root, 'art');
    mkdirSync(path.join(artifact, 'sub'), { recursive: true });
    writeFileSync(path.join(artifact, 'f.txt'), 'data');
    writeFileSync(path.join(artifact, 'sub', 'g.txt'), 'data2');
    const keys = path.join(root, 'keys');
    const out = path.join(artifact, 'attestation');
    run('keygen', '--out', keys);
    const gen = run(
      'generate', '--artifact', artifact,
      '--key', path.join(keys, 'private_key.pem'), '--out', out,
    );
    assert.equal(gen.code, 0, gen.stdout);
    const v = run(
      'verify', '--artifact', artifact,
      '--proof', path.join(out, 'proof.json'),
      '--signature', path.join(out, 'proof.json.sig'),
      '--key', path.join(keys, 'public_key.pem'),
    );
    assert.equal(v.code, 0, v.stdout);
    assert.equal(v.json.file_count, 2);
    const sbom = JSON.parse(readFileSync(path.join(out, 'sbom.json'), 'utf8'));
    assert.deepEqual(
      sbom.files.map((f) => f.path).sort(),
      ['f.txt', 'sub/g.txt'],
    );
  });
});

// ---------------------------------------------------------------------------
// 核心库单元测试
// ---------------------------------------------------------------------------

describe('core unit', () => {
  test('stableJSONStringify：字段按字典序、两空格缩进、以换行结束', () => {
    const text = stableJSONStringify({ b: 1, a: { z: 1, y: 2 }, c: [3, 2] });
    const lines = text.split('\n');
    assert.equal(lines[0], '{');
    assert.match(lines[1], /^  "a": \{/);
    // 嵌套对象同样排序
    assert.ok(text.indexOf('"y"') < text.indexOf('"z"'));
    assert.equal(lines[lines.length - 1], '');
    // 两次输出一致
    assert.equal(text, stableJSONStringify({ c: [3, 2], a: { y: 2, z: 1 }, b: 1 }));
  });

  test('parseProof 与 proofCanonical 往返一致（磁盘证明可直接验签）', () => {
    const ctx = setupGeneratedArtifact();
    const raw = readFileSync(path.join(ctx.out, 'proof.json'));
    const parsed = parseProof(raw);
    assert.equal(proofCanonical(parsed), raw.toString('utf8'));
  });

  test('computeArtifactDigest 对记录顺序敏感但排序后稳定', () => {
    const r1 = [
      { path: 'a', size: 1, sha256: 'x' },
      { path: 'b', size: 2, sha256: 'y' },
    ];
    const d1 = computeArtifactDigest(r1);
    const d2 = computeArtifactDigest([...r1].reverse());
    assert.notEqual(d1, d2); // 顺序编码进摘要
    assert.equal(d1, computeArtifactDigest(r1));
  });

  test('diffFiles 覆盖 added/removed/modified', () => {
    const base = [
      { path: 'keep', size: 1, sha256: 'h1' },
      { path: 'gone', size: 1, sha256: 'h2' },
      { path: 'mod', size: 1, sha256: 'h3' },
    ];
    const cur = [
      { path: 'keep', size: 1, sha256: 'h1' },
      { path: 'mod', size: 2, sha256: 'h4' },
      { path: 'new', size: 1, sha256: 'h5' },
    ];
    const changes = diffFiles(base, cur);
    assert.deepEqual(changes, [
      { path: 'gone', kind: 'removed' },
      { path: 'mod', kind: 'modified', fields: ['sha256', 'size'] },
      { path: 'new', kind: 'added' },
    ]);
  });
});
