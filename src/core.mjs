// Prov Guard 核心库：目录扫描、内容摘要、密钥/签名、稳定 JSON、错误模型。
// 仅依赖 Node.js 内置模块（fs/path/crypto），跨平台、无第三方依赖。
'use strict';

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

export const PROOF_VERSION = '1.0';
export const HASH_ALGORITHM = 'sha256';

// ---------------------------------------------------------------------------
// 错误模型
// ---------------------------------------------------------------------------

// 机器可读错误码（README 公开契约的一部分，不可随意改名）。
export const ErrorCode = {
  INPUT_NOT_FOUND: 'INPUT_NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  PROOF_INVALID: 'PROOF_INVALID',
  INTEGRITY_MISMATCH: 'INTEGRITY_MISMATCH',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
};

export class ProvError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'ProvError';
    this.code = code;
    this.detail = detail;
  }
}

export function fail(code, message, detail) {
  return new ProvError(code, message, detail);
}

// 文件系统错误 -> 公开错误码。missingCode 允许调用方为不同入口指定语义
// （例如公钥缺失映射为 KEY_NOT_FOUND）。
export function mapFsError(err, what, missingCode) {
  if (err.code === 'ENOENT') {
    return new ProvError(
      missingCode ?? ErrorCode.INPUT_NOT_FOUND,
      `${what}不存在`,
      { path: err.path },
    );
  }
  if (err.code === 'EACCES' || err.code === 'EPERM') {
    return new ProvError(ErrorCode.PERMISSION_DENIED, `${what}权限不足`, {
      path: err.path,
    });
  }
  return err;
}

// ---------------------------------------------------------------------------
// 稳定 JSON
// ---------------------------------------------------------------------------

// 按 key 字典序递归排序、两空格缩进、以 \n 结尾。
// 同一逻辑数据始终得到相同字节，因此可直接用于签名与磁盘输出。
export function stableJSONStringify(value) {
  return JSON.stringify(canonicalize(value), null, 2) + '\n';
}

function canonicalize(obj) {
  if (Array.isArray(obj)) {
    return obj.map(canonicalize);
  }
  if (obj !== null && typeof obj === 'object') {
    const out = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = canonicalize(obj[key]);
    }
    return out;
  }
  return obj;
}

// ---------------------------------------------------------------------------
// 目录扫描
// ---------------------------------------------------------------------------

// 扫描产物目录，返回按相对路径（统一正斜杠）字典序排列的文件记录：
// [{path,size,type,sha256}]。空目录生成空列表；零字节文件如实记录。
// excludedDirs 中的目录（通常是输出目录）位于产物目录内时，其自身及内容
// 不参与扫描。
export function scanDirectory(rootDir, excludedDirs) {
  const rootReal = path.resolve(rootDir);
  const excludeReal = (Array.isArray(excludedDirs) ? excludedDirs : [])
    .filter(Boolean)
    .map((p) => path.resolve(p))
    // 仅排除位于产物根目录之内的目录，避免产物外部的祖先目录误伤扫描。
    .filter((ex) => ex !== rootReal && isSameOrInside(ex, rootReal));
  const records = [];

  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      throw mapFsError(err, '产物目录');
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      if (excludeReal.some((ex) => isSameOrInside(abs, ex))) continue;
      if (entry.isDirectory()) {
        walk(abs);
      } else if (entry.isFile()) {
        records.push(buildRecord(rootReal, abs));
      }
      // 符号链接等非常规文件不计入清单，只统计常规文件。
    }
  };

  walk(rootReal);
  records.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return records;
}

function isSameOrInside(candidate, container) {
  const rel = path.relative(container, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function toPosixRelative(rootReal, absPath) {
  return path.relative(rootReal, absPath).split(path.sep).join('/');
}

function buildRecord(rootReal, absPath) {
  let data;
  try {
    data = readFileSync(absPath);
  } catch (err) {
    throw mapFsError(err, '产物文件');
  }
  return {
    path: path.relative(rootReal, absPath).split(path.sep).join('/'),
    size: data.length,
    type: guessType(absPath),
    // 直接对原始字节取摘要：任何字节变化都会改变该值。
    sha256: hashHex(data),
  };
}

// 基于扩展名的确定性文本/二进制分类，跨平台结果一致。
function guessType(filePath) {
  const textExts = new Set([
    '.txt', '.md', '.json', '.xml', '.html', '.htm', '.css', '.js', '.mjs',
    '.c', '.h', '.cc', '.cpp', '.py', '.sh', '.yml', '.yaml', '.toml',
    '.ini', '.cfg', '.conf', '.java', '.go', '.rs', '.ts', '.jsx', '.tsx',
    '.svg', '.csv', '.env', '.lock', '.sum', '.properties', '.rb', '.php',
  ]);
  return textExts.has(path.extname(filePath).toLowerCase()) ? 'text' : 'binary';
}

// ---------------------------------------------------------------------------
// 摘要
// ---------------------------------------------------------------------------

export function hashBytes(buf) {
  return createHash(HASH_ALGORITHM).update(buf).digest();
}

export function hashHex(buf) {
  return createHash(HASH_ALGORITHM).update(buf).digest('hex');
}

// 整个产物的稳定内容摘要：对排序后的文件记录流做哈希。
// 每行 file|<相对路径>|<字节大小>|<文件摘要>；任何字节变化或增删文件
// 都会改变结果。不包含时间字段。
export function computeArtifactDigest(records) {
  const h = createHash(HASH_ALGORITHM);
  for (const r of records) {
    h.update(`file|${r.path}|${r.size}|${r.sha256}\n`, 'utf8');
  }
  return h.digest('hex');
}

// ---------------------------------------------------------------------------
// 证明与清单
// ---------------------------------------------------------------------------

// 从目录构建证明对象与 SBOM 对象。timestamp 由调用方注入，便于复现与测试。
// 公钥指纹随证明记录，用于在验签失败时区分「错误公钥」与「签名/内容不符」。
export function buildModel(rootDir, excludedDirs, timestamp, publicKey) {
  const resolvedRoot = path.resolve(rootDir);
  const records = scanDirectory(resolvedRoot, excludedDirs);
  const artifactDigest = computeArtifactDigest(records);
  const name = path.basename(resolvedRoot);
  const totalSize = records.reduce((sum, r) => sum + r.size, 0);

  // 记录被排除目录相对于产物根的 POSIX 路径，使验证阶段可重现同一扫描集合；
  // 位于产物之外的目录不记录。
  const excludedRel = new Set();
  for (const exRaw of [].concat(excludedDirs ?? [])) {
    if (!exRaw) continue;
    const ex = path.resolve(exRaw);
    if (ex === resolvedRoot || !isSameOrInside(ex, resolvedRoot)) continue;
    excludedRel.add(toPosixRelative(resolvedRoot, ex));
  }
  const excludedList = [...excludedRel].sort();

  const proof = {
    version: PROOF_VERSION,
    generated_at: timestamp,
    artifact_name: name,
    artifact_digest: artifactDigest,
    signer_key_fingerprint: publicKey ? keyFingerprint(publicKey) : null,
    excluded_dirs: excludedList,
    total_size: totalSize,
    file_count: records.length,
    files: records.map((r) => ({
      path: r.path,
      size: r.size,
      sha256: r.sha256,
      type: r.type,
    })),
  };

  const sbom = {
    bom_format: 'provguard-sbom',
    version: PROOF_VERSION,
    artifact_name: name,
    artifact_digest: artifactDigest,
    file_count: records.length,
    total_size: totalSize,
    files: proof.files,
  };

  return { proof, sbom, records };
}

const REQUIRED_PROOF_FIELDS = [
  'version',
  'generated_at',
  'artifact_name',
  'artifact_digest',
  'signer_key_fingerprint',
  'excluded_dirs',
  'total_size',
  'file_count',
  'files',
];

export function parseProof(raw) {
  let obj;
  try {
    obj = JSON.parse(raw.toString('utf8'));
  } catch {
    throw fail(ErrorCode.PROOF_INVALID, '证明文件不是合法 JSON', null);
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw fail(ErrorCode.PROOF_INVALID, '证明文件结构非法', null);
  }
  for (const f of REQUIRED_PROOF_FIELDS) {
    if (!(f in obj)) {
      throw fail(ErrorCode.PROOF_INVALID, `证明缺少字段: ${f}`, {
        missing: f,
      });
    }
  }
  if (obj.version !== PROOF_VERSION) {
    throw fail(
      ErrorCode.PROOF_INVALID,
      `不支持的证明版本: ${String(obj.version)}`,
      null,
    );
  }
  if (typeof obj.generated_at !== 'string') {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 generated_at 字段非法', null);
  }
  if (typeof obj.artifact_name !== 'string') {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 artifact_name 字段非法', null);
  }
  if (
    typeof obj.artifact_digest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(obj.artifact_digest)
  ) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的产物摘要非法', null);
  }
  if (
    obj.signer_key_fingerprint !== null &&
    (typeof obj.signer_key_fingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(obj.signer_key_fingerprint))
  ) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的签名密钥指纹非法', null);
  }
  if (
    !Array.isArray(obj.excluded_dirs) ||
    obj.excluded_dirs.some((d) => typeof d !== 'string')
  ) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 excluded_dirs 字段非法', null);
  }
  if (typeof obj.total_size !== 'number' || !Number.isInteger(obj.total_size)) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 total_size 字段非法', null);
  }
  if (typeof obj.file_count !== 'number' || !Number.isInteger(obj.file_count)) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 file_count 字段非法', null);
  }
  if (!Array.isArray(obj.files)) {
    throw fail(ErrorCode.PROOF_INVALID, '证明的 files 字段不是数组', null);
  }
  obj.files.forEach((f, i) => {
    if (
      f === null ||
      typeof f !== 'object' ||
      typeof f.path !== 'string' ||
      typeof f.size !== 'number' ||
      !Number.isInteger(f.size) ||
      typeof f.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(f.sha256) ||
      typeof f.type !== 'string'
    ) {
      throw fail(ErrorCode.PROOF_INVALID, `证明的第 ${i} 项文件记录非法`, {
        index: i,
      });
    }
  });
  return obj;
}

// 用解析后的证明重构用于验签的规范字节（与生成时签名输入完全一致）。
export function proofCanonical(parsed) {
  return stableJSONStringify({
    version: parsed.version,
    generated_at: parsed.generated_at,
    artifact_name: parsed.artifact_name,
    artifact_digest: parsed.artifact_digest,
    signer_key_fingerprint: parsed.signer_key_fingerprint,
    excluded_dirs: parsed.excluded_dirs,
    total_size: parsed.total_size,
    file_count: parsed.file_count,
    files: parsed.files,
  });
}

// 逐项比较基线证明文件列表与当前扫描结果，返回 added/removed/modified。
export function diffFiles(baseline, current) {
  const changes = [];
  const oldMap = new Map(baseline.map((r) => [r.path, r]));
  const newMap = new Map(current.map((r) => [r.path, r]));

  for (const [p, r] of newMap) {
    const old = oldMap.get(p);
    if (!old) {
      changes.push({ path: p, kind: 'added' });
    } else if (old.sha256 !== r.sha256 || old.size !== r.size) {
      const fields = [];
      if (old.sha256 !== r.sha256) fields.push('sha256');
      if (old.size !== r.size) fields.push('size');
      changes.push({ path: p, kind: 'modified', fields });
    }
  }
  for (const p of oldMap.keys()) {
    if (!newMap.has(p)) changes.push({ path: p, kind: 'removed' });
  }
  changes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return changes;
}

// ---------------------------------------------------------------------------
// 密钥与签名（Ed25519，PEM；签名为固定 64 字节裸签名）
// ---------------------------------------------------------------------------

export function generateKeyPair() {
  return generateKeyPairSync('ed25519', {
    privateKey: { format: 'pem' },
    publicKey: { format: 'pem' },
  });
}

export function loadPrivateKey(pemPath) {
  const pem = readKeyPem(pemPath, '私钥');
  try {
    return createPrivateKey(pem);
  } catch {
    throw fail(ErrorCode.KEY_NOT_FOUND, '私钥内容无法解析为 Ed25519 密钥', {
      path: pemPath,
    });
  }
}

export function loadPublicKey(pemPath) {
  const pem = readKeyPem(pemPath, '公钥');
  try {
    return createPublicKey(pem);
  } catch {
    throw fail(ErrorCode.KEY_NOT_FOUND, '公钥内容无法解析为 Ed25519 密钥', {
      path: pemPath,
    });
  }
}

function readKeyPem(pemPath, what) {
  let pem;
  try {
    pem = readFileSync(pemPath);
  } catch (err) {
    // 密钥路径缺失归为密钥语义错误 KEY_NOT_FOUND，而非通用输入错误。
    throw mapFsError(err, what, ErrorCode.KEY_NOT_FOUND);
  }
  return pem;
}

// Ed25519 公钥指纹：原始 32 字节公钥的 SHA-256（十六进制）。
export function keyFingerprint(publicKey) {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const raw = spki.subarray(spki.length - 32); // Ed25519 SPKI 以 32 字节裸公钥结尾
  return hashHex(raw);
}

export function signProof(privateKey, canonicalBytes) {
  return cryptoSign(null, canonicalBytes, privateKey);
}

// 验签失败（内容不符/签名不符）返回 false；参数结构错误抛错由调用方兜底。
export function checkSignature(publicKey, canonicalBytes, signatureBuf) {
  try {
    return cryptoVerify(null, canonicalBytes, publicKey, signatureBuf);
  } catch {
    return false;
  }
}

export function loadSignature(sigPath) {
  let buf;
  try {
    buf = readFileSync(sigPath);
  } catch (err) {
    throw mapFsError(err, '签名文件');
  }
  if (buf.length !== 64) {
    throw fail(
      ErrorCode.PROOF_INVALID,
      '签名文件格式非法（Ed25519 裸签名应为 64 字节）',
      { path: sigPath, length: buf.length },
    );
  }
  return buf;
}

// ---------------------------------------------------------------------------
// 文件读写
// ---------------------------------------------------------------------------

export function ensureDir(dir) {
  try {
    mkdirSync(dir, { recursive: true });
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw fail(ErrorCode.PERMISSION_DENIED, '无法创建输出目录（权限不足）', {
        path: dir,
      });
    }
    throw err;
  }
}

export function writeOutputFile(filePath, data) {
  try {
    writeFileSync(filePath, data);
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw fail(ErrorCode.PERMISSION_DENIED, '写入输出文件权限不足', {
        path: filePath,
      });
    }
    throw err;
  }
}

export function chmod600(p) {
  try {
    chmodSync(p, 0o600);
  } catch {
    // 权限收窄失败不阻断主流程。
  }
}

export function assertExistingPath(p, what, { directory = false } = {}) {
  let st;
  try {
    st = statSync(p);
  } catch (err) {
    throw mapFsError(err, what);
  }
  if (directory && !st.isDirectory()) {
    throw fail(ErrorCode.INPUT_NOT_FOUND, `${what}不是目录`, { path: p });
  }
}
