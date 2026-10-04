#!/usr/bin/env node
// Prov Guard —— 软件供应链证明与完整性校验工具（零依赖，Node >= 18）。
//
// 子命令：
//   keygen   --key-dir <dir> [--name <prefix>]
//   generate --artifact <path> --key <private-key> --out <dir> [--bundle]
//   verify   --artifact <path> (--proof <file> --signature <file> | --bundle <file>) --key <public-key>
//            [--sbom <file> --sbom-signature <file>] [--policy <policy.json>]
//
// 所有输出均为 UTF-8；成功结果写 stdout，错误结果写 stderr。

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { constants as fsConstants, readFileSync, realpathSync } from 'node:fs';
import { access, mkdir, readdir, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROOF_VERSION = '1.0';
// 启用多方共签时证明版本升为 1.1；共签清单（proof/sbom.cosignatures.json）的 schemaVersion。
export const PROOF_VERSION_COSIGN = '1.1';
export const COSIGN_SCHEMA_VERSION = '1.0';
// 证明分发包 proof.bundle.json 的格式版本。
export const BUNDLE_VERSION = '1.0';
// 分发包成员的逻辑名（固定集合，按此顺序排列）；共签启用时追加两个共签清单成员。
export const BUNDLE_MEMBERS = Object.freeze([
  'proof',
  'proof-signature',
  'sbom',
  'sbom-signature',
]);
export const BUNDLE_COSIGN_MEMBERS = Object.freeze(['proof-cosignatures', 'sbom-cosignatures']);
export const BUNDLE_FILE_NAME = 'proof.bundle.json';

// ---------------------------------------------------------------------------
// 错误类型：携带机器可读错误码，CLI 边界统一转换为非零退出。
// ---------------------------------------------------------------------------

export const ERROR_CODES = Object.freeze({
  INPUT_NOT_FOUND: 'INPUT_NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  PROOF_INVALID: 'PROOF_INVALID',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  INTEGRITY_MISMATCH: 'INTEGRITY_MISMATCH',
  POLICY_INVALID: 'POLICY_INVALID',
  POLICY_VIOLATION: 'POLICY_VIOLATION',
  SYMLINK_INVALID: 'SYMLINK_INVALID',
  USAGE_ERROR: 'USAGE_ERROR',
});

class ProvError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'ProvError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

// 把 Node 底层错误归类为 INPUT_NOT_FOUND / PERMISSION_DENIED，其余原样抛出。
function wrapFsError(err, context) {
  if (err instanceof ProvError) return err;
  const where = context ? `${context}: ` : '';
  if (err && err.code === 'ENOENT') {
    return new ProvError(ERROR_CODES.INPUT_NOT_FOUND, `${where}路径不存在 (${err.path || 'unknown path'})`);
  }
  if (err && (err.code === 'EACCES' || err.code === 'EPERM')) {
    return new ProvError(ERROR_CODES.PERMISSION_DENIED, `${where}权限不足 (${err.path || 'unknown path'})`);
  }
  return err;
}

// ---------------------------------------------------------------------------
// 路径与摘要工具
// ---------------------------------------------------------------------------

// 清单中的相对路径统一使用正斜杠，保证跨平台稳定。
export function toPosix(relPath) {
  return relPath.split(sep).join('/');
}

// 稳定哈希：SHA-256，摘要对象按 key 排序后以 UTF-8 序列化（两空格缩进）。
export function stableJsonStringify(value) {
  return JSON.stringify(sortDeep(value), null, 2);
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep(value[key]);
    return out;
  }
  return value;
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

// 公钥指纹：对 SPKI 编码的 DER 字节取 SHA-256。写入证明并随证明一起签名，
// 验证时据此区分“使用了错误公钥”（指纹不一致）与“签名内容被篡改”（指纹一致但验签失败）。
export function keyFingerprint(keyObj) {
  return sha256Hex(keyObj.export({ type: 'spki', format: 'der' }));
}

// ---------------------------------------------------------------------------
// 产物扫描：递归列出全部常规文件（含符号链接解引用后的目标），
// 空目录自然产生空清单；零字节文件按真实文件记录。
// 符号链接安全规则（按真实路径判定）：
//   - 目标越出产物根目录                 -> SYMLINK_INVALID / outside-root；
//   - 目标为当前递归祖先链上的目录（含根目录自身），或链接互相成环（ELOOP）
//                                        -> SYMLINK_INVALID / cycle；
//   - 指向根目录内部普通文件/目录的链接按链接路径记录目标内容；
//     祖先链之外的重复目标允许展开（有向无环，不会形成回路）。
// 判定在读取目标内容之前完成，危险链接不会被解引用读取。
// ---------------------------------------------------------------------------

// 符号链接安全检查失败：携带相对路径与原因（cycle / outside-root）。
function symlinkError(fullPath, rootDir, reason) {
  const relPath = toPosix(relative(rootDir, fullPath));
  const message =
    reason === 'cycle'
      ? `符号链接形成回路: ${relPath}`
      : `符号链接越出产物根目录: ${relPath}`;
  return new ProvError(ERROR_CODES.SYMLINK_INVALID, message, { path: relPath, reason });
}

// 解析真实路径；底层错误按既有归类转换。
async function realPathOf(p, context) {
  try {
    return await realpath(p);
  } catch (err) {
    throw wrapFsError(err, context);
  }
}

async function walkFiles(rootDir) {
  const found = [];
  const rootReal = await realPathOf(rootDir, '读取产物目录');
  // chain 为当前递归路径上各级目录的真实路径，用于识别指回祖先的链接回路。
  async function walk(dir, chain) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err) {
      throw wrapFsError(err, '读取产物目录');
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full, [...chain, await realPathOf(full, '读取产物目录')]);
      } else if (entry.isFile()) {
        found.push(full);
      } else if (entry.isSymbolicLink()) {
        // 先解析真实目标并做安全判定，再按目标类型处理：
        // 指向目录则继续递归，指向文件则按链接路径记录。
        let targetReal;
        try {
          targetReal = await realpath(full);
        } catch (err) {
          // 链接互相指向成环（如 a -> b、b -> a）时 realpath 报 ELOOP。
          if (err && err.code === 'ELOOP') throw symlinkError(full, rootDir, 'cycle');
          throw wrapFsError(err, '读取符号链接');
        }
        if (!isWithin(targetReal, rootReal)) {
          throw symlinkError(full, rootDir, 'outside-root');
        }
        if (chain.includes(targetReal)) {
          throw symlinkError(full, rootDir, 'cycle');
        }
        let target;
        try {
          target = await stat(full);
        } catch (err) {
          throw wrapFsError(err, '读取符号链接');
        }
        if (target.isDirectory()) await walk(full, [...chain, targetReal]);
        else if (target.isFile()) found.push(full);
      }
      // 其他特殊文件（套接字/设备等）忽略。
    }
  }
  await walk(rootDir, [rootReal]);
  return found;
}

// 判断 root 是否位于 outDir 之内（用于从扫描结果排除输出目录自身）。
function isWithin(pathAbs, dirAbs) {
  const relPath = relative(dirAbs, pathAbs);
  return relPath === '' || (!!relPath && !relPath.startsWith('..') && !isAbsolute(relPath));
}

async function fileTypeFromPath(fullPath, data) {
  // 极简魔数嗅探，仅用于清单的 type 字段；不识别时回退为扩展名或 "data"。
  // 一律使用字节数组，避免多字节字符串经 UTF-8 编码后长度/取值不符。
  const startsWith = (bytes) =>
    data.length >= bytes.length && bytes.every((b, i) => data[i] === b);
  if (startsWith([0x1f, 0x8b])) return 'application/gzip';
  if (startsWith([0x50, 0x4b, 0x03, 0x04])) return 'application/zip';
  if (startsWith([0x25, 0x50, 0x44, 0x46, 0x2d])) return 'application/pdf'; // %PDF-
  if (startsWith([0x7f, 0x45, 0x4c, 0x46])) return 'application/x-elf';
  if (startsWith([0x4d, 0x5a])) return 'application/x-dosexec'; // MZ
  if (startsWith([0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  // 类脚本/文本：UTF BOM，或前 512 字节不含 NUL 则视为 text。
  if (
    startsWith([0xef, 0xbb, 0xbf]) ||
    startsWith([0xff, 0xfe]) ||
    startsWith([0xfe, 0xff])
  ) {
    return 'text/plain';
  }
  if (!data.subarray(0, 512).includes(0)) return 'text/plain';
  const ext = basename(fullPath).split('.').pop();
  return ext && ext !== basename(fullPath) ? `application/x-${ext.toLowerCase()}` : 'application/octet-stream';
}

// 构建 SBOM。时间字段不进入清单，文件摘要只依赖文件字节与相对路径。
// excludeDir 为输出目录的绝对路径（若位于产物内部则排除）。
export async function buildSbom(artifactPath, excludeDir) {
  const artifactAbs = resolve(artifactPath);
  let artifactStat;
  try {
    artifactStat = await stat(artifactAbs);
  } catch (err) {
    throw wrapFsError(err, '读取产物');
  }

  const rootDir = artifactStat.isDirectory() ? artifactAbs : dirname(artifactAbs);
  const excludeAbs = excludeDir ? resolve(excludeDir) : null;

  let files;
  if (artifactStat.isDirectory()) {
    files = await walkFiles(artifactAbs);
  } else {
    files = [artifactAbs];
  }

  const entries = [];
  for (const full of files) {
    if (excludeAbs && isWithin(full, excludeAbs)) continue;
    let data;
    try {
      data = await readFile(full);
    } catch (err) {
      throw wrapFsError(err, '读取产物文件');
    }
    const relPath = toPosix(relative(rootDir, full));
    entries.push({
      path: relPath,
      sha256: sha256Hex(data),
      size: data.length,
      type: await fileTypeFromPath(full, data),
    });
  }

  // 按相对路径排序，保证同一输入产生字节级一致的清单。
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return {
    schemaVersion: '1.0',
    artifactName: artifactStat.isDirectory() ? basename(artifactAbs) : basename(artifactAbs),
    rootType: artifactStat.isDirectory() ? 'directory' : 'file',
    files: entries,
  };
}

// 顶层产物摘要：对“排序后的文件条目列表”做稳定哈希。
// 任何字节变化、文件新增/删除/重命名都会改变该摘要。
export function computeArtifactDigest(sbom) {
  return sha256Hex(stableJsonStringify(sbom.files));
}

// ---------------------------------------------------------------------------
// 密钥与签名（Ed25519，PEM）
// ---------------------------------------------------------------------------

function readPrivateKey(keyPath) {
  let pem;
  try {
    pem = readFileSync(keyPath);
  } catch (err) {
    throw wrapFsError(err, '读取私钥');
  }
  let keyObj;
  try {
    keyObj = createPrivateKey({ key: pem, format: 'pem' });
  } catch {
    throw new ProvError(ERROR_CODES.KEY_NOT_FOUND, `私钥无法解析或格式不受支持: ${keyPath}`);
  }
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new ProvError(
      ERROR_CODES.KEY_NOT_FOUND,
      `私钥类型不是 Ed25519（实际为 ${keyObj.asymmetricKeyType}）: ${keyPath}`,
    );
  }
  return keyObj;
}

function readPublicKey(keyPath) {
  let pem;
  try {
    pem = readFileSync(keyPath);
  } catch (err) {
    throw wrapFsError(err, '读取公钥');
  }
  let keyObj;
  try {
    keyObj = createPublicKey({ key: pem, format: 'pem' });
  } catch {
    throw new ProvError(ERROR_CODES.KEY_NOT_FOUND, `公钥无法解析或格式不受支持: ${keyPath}`);
  }
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new ProvError(
      ERROR_CODES.KEY_NOT_FOUND,
      `公钥类型不是 Ed25519（实际为 ${keyObj.asymmetricKeyType}）: ${keyPath}`,
    );
  }
  return keyObj;
}

// 生成阶段时间戳采用 UTC ISO-8601；它只写入 proof，不参与任何摘要。
function nowIso() {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

export async function keygen({ keyDir, name = 'provguard' }) {
  const absDir = resolve(keyDir);
  try {
    await mkdir(absDir, { recursive: true });
  } catch (err) {
    throw wrapFsError(err, '创建密钥目录');
  }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privPath = join(absDir, `${name}.private.pem`);
  const pubPath = join(absDir, `${name}.public.pem`);
  try {
    await writeFile(
      privPath,
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    );
    await writeFile(
      pubPath,
      publicKey.export({ type: 'spki', format: 'pem' }),
      { mode: 0o644 },
    );
  } catch (err) {
    throw wrapFsError(err, '写入密钥');
  }
  return { privateKeyPath: privPath, publicKeyPath: pubPath };
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

export async function generate({ artifact, key, out, coKeys = [], bundle = false }) {
  // 输入检查：产物与私钥必须存在且可读。
  const artifactAbs = resolve(artifact);
  const keyAbs = resolve(key);
  const coSign = coKeys.length > 0;
  const coKeyAbsList = coKeys.map((p) => resolve(p));
  const inputs = [
    [artifactAbs, '产物'],
    [keyAbs, '私钥'],
  ];
  for (const p of coKeyAbsList) inputs.push([p, '共签私钥']);
  for (const [p, label] of inputs) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      throw wrapFsError(err, `读取${label}`);
    }
  }

  const outAbs = resolve(out);
  const parent = dirname(outAbs);
  try {
    await mkdir(parent, { recursive: true });
  } catch (err) {
    throw wrapFsError(err, '创建输出目录');
  }

  // 若输出目录尚不存在，先按真实路径创建，再据此排除。
  try {
    await mkdir(outAbs, { recursive: true });
  } catch (err) {
    throw wrapFsError(err, '创建输出目录');
  }
  let outReal;
  try {
    outReal = await realpath(outAbs);
  } catch (err) {
    throw wrapFsError(err, '解析输出目录');
  }

  const privateKey = readPrivateKey(keyAbs);
  // 由私钥导出对应公钥，记录其指纹到证明中，供验证区分错误公钥与签名失配。
  const signingPublicKey = createPublicKey(privateKey);
  const signerKeyFingerprint = keyFingerprint(signingPublicKey);

  // 共签私钥：逐一读取并校验为 Ed25519；指纹不得重复，也不得与主签名密钥相同，
  // 否则为 USAGE_ERROR。共签者按指纹升序排列，保证输出确定。
  const coSigners = [];
  if (coSign) {
    const seen = new Set([signerKeyFingerprint.toLowerCase()]);
    for (const p of coKeyAbsList) {
      const coKey = readPrivateKey(p);
      const fingerprint = keyFingerprint(createPublicKey(coKey));
      if (seen.has(fingerprint.toLowerCase())) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          '共签私钥重复或与主密钥相同（--co-key 必须互不相同且不同于 --key）',
        );
      }
      seen.add(fingerprint.toLowerCase());
      coSigners.push({ key: coKey, fingerprint });
    }
    coSigners.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
  }

  const sbom = await buildSbom(artifactAbs, outReal);
  const artifactDigest = computeArtifactDigest(sbom);

  // SBOM 规范字节：稳定 JSON（去尾换行后的 UTF-8）。proof 中的 sbomDigest 与
  // sbom.json.sig 绑定同一组字节，防止证明有效而 sbom.json 被整体替换。
  const sbomCanonical = stableJsonStringify(sbom);
  const sbomDigest = sha256Hex(sbomCanonical);

  const proof = {
    proofVersion: coSign ? PROOF_VERSION_COSIGN : PROOF_VERSION,
    artifactName: basename(artifactAbs),
    artifactDigest,
    fileName: basename(artifactAbs),
    size: sbom.files.reduce((n, f) => n + f.size, 0),
    generatedAt: nowIso(),
    signerKeyFingerprint,
    sbomDigest,
    files: sbom.files,
  };
  // 启用共签时证明声明共签者集合（按指纹升序、已去重），随证明一起被主签名保护。
  if (coSign) {
    proof.cosignerKeyFingerprints = coSigners.map((c) => c.fingerprint);
  }
  // 稳定字段顺序：proof 先按既定顺序构造，再整体排序输出。
  const proofJson = stableJsonStringify(proof) + '\n';
  const sbomJson = sbomCanonical + '\n';

  // 对证明的规范字节（不含尾部换行）签名，验证时使用同一规范形式。
  // Ed25519 为纯签名算法，不接受摘要算法参数，故用 sign(null, data, key)。
  const signature = cryptoSign(null, Buffer.from(proofJson.trimEnd(), 'utf8'), privateKey);
  const signatureB64 = signature.toString('base64') + '\n';
  // 对 SBOM 规范字节单独签名，Base64 加换行保存。
  const sbomSignature = cryptoSign(null, Buffer.from(sbomCanonical, 'utf8'), privateKey);
  const sbomSignatureB64 = sbomSignature.toString('base64') + '\n';

  const proofPath = join(outReal, 'proof.json');
  const sbomPath = join(outReal, 'sbom.json');
  const sigPath = join(outReal, 'proof.json.sig');
  const sbomSigPath = join(outReal, 'sbom.json.sig');
  // 共签清单：每个共签者对与主签名相同的证明规范字节签名（proof.cosignatures.json），
  // 并另对 SBOM 规范字节签名（sbom.cosignatures.json）。不提供 --co-key 时不创建这些文件。
  const proofCosigPath = coSign ? join(outReal, 'proof.cosignatures.json') : null;
  const sbomCosigPath = coSign ? join(outReal, 'sbom.cosignatures.json') : null;
  // 保留共签清单的写出字节，供可选分发包原样收录。
  let proofCosigJson = null;
  let sbomCosigJson = null;
  try {
    await atomicWrite(proofPath, proofJson);
    await atomicWrite(sbomPath, sbomJson);
    await atomicWrite(sigPath, signatureB64);
    await atomicWrite(sbomSigPath, sbomSignatureB64);
    if (coSign) {
      const proofBytes = Buffer.from(proofJson.trimEnd(), 'utf8');
      const sbomBytes = Buffer.from(sbomCanonical, 'utf8');
      const cosignManifest = (bytes) => ({
        schemaVersion: COSIGN_SCHEMA_VERSION,
        artifactDigest,
        sbomDigest,
        signers: coSigners.map((c) => ({
          keyFingerprint: c.fingerprint,
          signature: cryptoSign(null, bytes, c.key).toString('base64'),
        })),
      });
      proofCosigJson = stableJsonStringify(cosignManifest(proofBytes)) + '\n';
      sbomCosigJson = stableJsonStringify(cosignManifest(sbomBytes)) + '\n';
      await atomicWrite(proofCosigPath, proofCosigJson);
      await atomicWrite(sbomCosigPath, sbomCosigJson);
    }
  } catch (err) {
    throw wrapFsError(err, '写入证明产物');
  }

  // 可选分发包：在独立文件之外额外把各产物原样（含尾换行等原始字节）打包为
  // 单个 UTF-8 稳定 JSON。成员内容与磁盘文件字节逐一对应。
  let bundlePath = null;
  if (bundle) {
    bundlePath = join(outReal, BUNDLE_FILE_NAME);
    const memberBytes = new Map([
      ['proof', Buffer.from(proofJson, 'utf8')],
      ['proof-signature', Buffer.from(signatureB64, 'utf8')],
      ['sbom', Buffer.from(sbomJson, 'utf8')],
      ['sbom-signature', Buffer.from(sbomSignatureB64, 'utf8')],
    ]);
    if (coSign) {
      memberBytes.set('proof-cosignatures', Buffer.from(proofCosigJson, 'utf8'));
      memberBytes.set('sbom-cosignatures', Buffer.from(sbomCosigJson, 'utf8'));
    }
    try {
      await atomicWrite(bundlePath, buildBundle(memberBytes));
    } catch (err) {
      throw wrapFsError(err, '写入证明分发包');
    }
  }

  const result = {
    proofPath,
    sbomPath,
    signaturePath: sigPath,
    sbomSignaturePath: sbomSigPath,
    artifactDigest,
    sbomDigest,
    fileCount: sbom.files.length,
    proofVersion: proof.proofVersion,
  };
  if (bundle) result.bundlePath = bundlePath;
  if (coSign) {
    result.cosignerCount = coSigners.length;
    result.proofCosignaturesPath = proofCosigPath;
    result.sbomCosignaturesPath = sbomCosigPath;
  }
  return result;
}

// 同目录临时文件 + rename，避免半成品证明文件留在输出目录。
async function atomicWrite(target, contents) {
  const dir = dirname(target);
  const tmp = join(dir, `.${basename(target)}.${process.pid}.tmp`);
  await writeFile(tmp, contents, { mode: 0o644 });
  try {
    await rename(tmp, target);
  } catch (err) {
    await rm(tmp, { force: true });
    throw err;
  }
}

// ---------------------------------------------------------------------------
// 证明分发包（proof.bundle.json）
// ---------------------------------------------------------------------------

// 单个成员：原文件 Base64、SHA-256（十六进制）与字节长度。
function bundleMember(bytes) {
  return {
    sha256: sha256Hex(bytes),
    size: bytes.length,
    payload: bytes.toString('base64'),
  };
}

// 构建分发包：顶层 bundleVersion 与按逻辑名排序的 members。
// memberBytes 为 逻辑名 -> 原始文件字节（Buffer）。稳定 JSON 加尾换行写出。
function buildBundle(memberBytes) {
  const names = [...memberBytes.keys()].sort();
  const members = {};
  for (const name of names) {
    members[name] = bundleMember(memberBytes.get(name));
  }
  return stableJsonStringify({ bundleVersion: BUNDLE_VERSION, members }) + '\n';
}

// 严格 Base64 解码：非法字符/填充返回 null（Node 的 Buffer 会容忍非法输入，须自行拦截）。
function decodeBase64Strict(b64) {
  if (typeof b64 !== 'string' || b64.length === 0 || b64.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return null;
  // 等号只能出现在末尾，且最多两个。
  const pad = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  if (b64.indexOf('=') !== -1 && b64.indexOf('=') !== b64.length - pad) return null;
  return Buffer.from(b64, 'base64');
}

// 读取并严格校验分发包信封，解码全部成员，返回 逻辑名 -> 原始字节。
// 信封/JSON/版本/成员名/Base64/长度/摘要问题一律为 PROOF_INVALID；
// 成员集合是否与证明版本匹配由调用方在解析证明后用 assertBundleMembers 复核。
function readBundle(bundleText) {
  let bundle;
  try {
    bundle = JSON.parse(bundleText);
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包不是合法的 JSON');
  }
  if (bundle === null || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包顶层必须是 JSON 对象');
  }
  if (bundle.bundleVersion !== BUNDLE_VERSION) {
    throw new ProvError(
      ERROR_CODES.PROOF_INVALID,
      `分发包 bundleVersion 缺失或不受支持（应为 ${BUNDLE_VERSION}）`,
    );
  }
  if (bundle.members === null || typeof bundle.members !== 'object' || Array.isArray(bundle.members)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包 members 缺失或类型非法');
  }

  const knownNames = new Set([...BUNDLE_MEMBERS, ...BUNDLE_COSIGN_MEMBERS]);
  const decoded = new Map();
  for (const name of Object.keys(bundle.members)) {
    if (!knownNames.has(name)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员名未知或多余: ${name}`);
    }
    const m = bundle.members[name];
    if (m === null || typeof m !== 'object' || Array.isArray(m)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员不是 JSON 对象: ${name}`);
    }
    const bytes = decodeBase64Strict(m.payload);
    if (bytes === null) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员不是合法的 Base64 内容: ${name}`);
    }
    if (typeof m.size !== 'number' || !Number.isSafeInteger(m.size) || m.size < 0) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员字节长度非法: ${name}`);
    }
    if (m.size !== bytes.length) {
      throw new ProvError(
        ERROR_CODES.PROOF_INVALID,
        `分发包成员字节长度与 Base64 内容不符: ${name}`,
        { name, expected: m.size, actual: bytes.length },
      );
    }
    if (typeof m.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(m.sha256)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员 SHA-256 非法: ${name}`);
    }
    if (sha256Hex(bytes).toLowerCase() !== m.sha256.toLowerCase()) {
      throw new ProvError(
        ERROR_CODES.PROOF_INVALID,
        `分发包成员 SHA-256 与 Base64 内容不符: ${name}`,
      );
    }
    decoded.set(name, bytes);
  }
  return decoded;
}

// 成员集合必须恰好为四个基础成员；共签清单成对出现，且与证明版本一致
// （proofVersion 1.1 必须携带，1.0 不得携带），否则 PROOF_INVALID。
function assertBundleMembers(members, proof) {
  for (const name of BUNDLE_MEMBERS) {
    if (!members.has(name)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包缺少必需成员: ${name}`);
    }
  }
  const expectCosign = proof.proofVersion === PROOF_VERSION_COSIGN;
  const hasProofCosig = members.has('proof-cosignatures');
  const hasSbomCosig = members.has('sbom-cosignatures');
  if (hasProofCosig !== hasSbomCosig || hasProofCosig !== expectCosign) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包共签成员缺失或多余（须与证明版本一致且成对出现）');
  }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

export async function verify({
  artifact,
  proof: proofPath,
  signature: sigPath,
  key: pubKeyPath,
  sbom: sbomPath,
  sbomSignature: sbomSigPath,
  policy: policyPath,
  cosignatures: cosigDir,
  cosignerKeys,
  minCosigners,
  bundle: bundlePath,
}) {
  const artifactAbs = resolve(artifact);
  const keyAbs = resolve(pubKeyPath);
  const bundleMode = bundlePath !== undefined;

  // --sbom 与 --sbom-signature 必须成对出现；只给一者是用法错误。
  const sbomMode = sbomPath !== undefined || sbomSigPath !== undefined;
  if (sbomMode && (sbomPath === undefined || sbomSigPath === undefined)) {
    throw new ProvError(ERROR_CODES.USAGE_ERROR, '--sbom 与 --sbom-signature 必须成对提供');
  }
  // 分发包模式下，SBOM 及其签名固定取自包内成员，不允许再提供独立文件。
  if (bundleMode && sbomMode) {
    throw new ProvError(
      ERROR_CODES.USAGE_ERROR,
      '--bundle 与 --sbom、--sbom-signature、--proof、--signature、--cosignatures 互斥',
    );
  }
  const sbomAbs = sbomMode ? resolve(sbomPath) : null;
  const sbomSigAbs = sbomMode ? resolve(sbomSigPath) : null;

  // 共签校验三参数必须同时提供：--cosignatures、--cosigner-key（可重复）、--min-cosigners。
  // 分发包模式下没有 --cosignatures（清单在包内）：另两个参数仍需成对出现。
  const cosignMode =
    cosigDir !== undefined || cosignerKeys !== undefined || minCosigners !== undefined;
  if (bundleMode) {
    if (cosigDir !== undefined) {
      throw new ProvError(
        ERROR_CODES.USAGE_ERROR,
        '--bundle 与 --cosignatures 互斥（包模式共签清单取自包内）',
      );
    }
    if (cosignMode && (cosignerKeys === undefined || minCosigners === undefined)) {
      throw new ProvError(
        ERROR_CODES.USAGE_ERROR,
        '包模式下 --cosigner-key 与 --min-cosigners 必须同时提供',
      );
    }
  } else if (cosignMode && (cosigDir === undefined || cosignerKeys === undefined || minCosigners === undefined)) {
    throw new ProvError(
      ERROR_CODES.USAGE_ERROR,
      '--cosignatures、--cosigner-key 与 --min-cosigners 必须同时提供',
    );
  }
  const cosignerKeyList = cosignMode
    ? (Array.isArray(cosignerKeys) ? cosignerKeys : [cosignerKeys])
    : [];

  // 1) 所有输入必须存在且可读。
  const inputs = [
    [artifactAbs, '产物'],
    [keyAbs, '公钥'],
  ];
  if (bundleMode) {
    inputs.push([resolve(bundlePath), '证明分发包']);
  } else {
    inputs.push(
      [resolve(proofPath), '证明文件'],
      [resolve(sigPath), '签名文件'],
    );
  }
  if (sbomMode) {
    inputs.push([sbomAbs, 'SBOM 文件'], [sbomSigAbs, 'SBOM 签名文件']);
  }
  for (const [p, label] of inputs) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      throw wrapFsError(err, `读取${label}`);
    }
  }

  // 2) 公钥必须可解析且为 Ed25519 —— 错误/不支持的公钥归 KEY_NOT_FOUND。
  const publicKey = readPublicKey(keyAbs);

  // 3) 取得证明、主签名、SBOM、共签清单的原始字节。
  //    独立文件模式直接读盘；分发包模式解析信封并逐项校验 Base64/长度/SHA-256。
  let proofBytes;
  let sigBuf;
  let sbomBytes = null;
  let sbomSigBytes = null;
  // 共签清单延迟到第 8 步（签名、完整性、SBOM 全部通过之后）才读取与解析，
  // 与独立文件模式原有顺序保持一致；此处只暂存来源。
  let proofCosignSource = null;
  let sbomCosignSource = null;
  let proofLocation; // 证明所在位置：文件路径或分发包路径（用于推断产物排除目录）。

  if (bundleMode) {
    const bundleAbs = resolve(bundlePath);
    let bundleText;
    try {
      bundleText = await readFileUtf8(bundleAbs);
    } catch (err) {
      throw wrapFsError(err, '读取证明分发包');
    }
    const members = readBundle(bundleText);
    proofBytes = members.get('proof');

    // 证明先解析并做结构校验，再据此复核成员集合（共签成员须与证明版本一致）。
    let proofPreview;
    try {
      proofPreview = JSON.parse(proofBytes.toString('utf8'));
    } catch {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明文件不是合法的 JSON');
    }
    const previewError = validateProof(proofPreview);
    if (previewError) throw new ProvError(ERROR_CODES.PROOF_INVALID, previewError);
    assertBundleMembers(members, proofPreview);

    sigBuf = decodeSignatureBytes(members.get('proof-signature'), '签名文件');
    sbomBytes = members.get('sbom');
    sbomSigBytes = members.get('sbom-signature');
    if (proofPreview.proofVersion === PROOF_VERSION_COSIGN) {
      // 仅记下成员字节；结构与签名核校仍在第 8 步进行。
      proofCosignSource = { kind: 'bytes', bytes: members.get('proof-cosignatures') };
      sbomCosignSource = { kind: 'bytes', bytes: members.get('sbom-cosignatures') };
    }
    proofLocation = bundleAbs;
  } else {
    const proofAbs = resolve(proofPath);
    const sigAbs = resolve(sigPath);
    try {
      proofBytes = await readFile(proofAbs);
    } catch (err) {
      throw wrapFsError(err, '读取证明文件');
    }
    let sigBytes;
    try {
      sigBytes = await readFile(sigAbs);
    } catch (err) {
      throw wrapFsError(err, '读取签名文件');
    }
    sigBuf = decodeSignatureBytes(sigBytes, '签名文件');
    if (sbomMode) {
      try {
        [sbomBytes, sbomSigBytes] = await Promise.all([readFile(sbomAbs), readFile(sbomSigAbs)]);
      } catch (err) {
        throw wrapFsError(err, '读取 SBOM 文件');
      }
    }
    if (cosignMode) {
      // 仅记下清单路径；存在性检查与解析在第 8 步进行。
      const dir = resolve(cosigDir);
      proofCosignSource = { kind: 'file', path: join(dir, 'proof.cosignatures.json') };
      sbomCosignSource = { kind: 'file', path: join(dir, 'sbom.cosignatures.json') };
    }
    proofLocation = proofAbs;
  }

  // 4) 证明必须是可解析的 JSON 且结构合法 —— 否则 PROOF_INVALID。
  let proof;
  try {
    proof = JSON.parse(proofBytes.toString('utf8'));
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明文件不是合法的 JSON');
  }
  const proofError = validateProof(proof);
  if (proofError) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, proofError);
  }

  // 5) 重算证明的规范字节并验签。
  //    以收录的 proof 原样字节为真，重新序列化其解析结果用于验签；
  //    generate 写出的即为稳定规范形式，因此往返一致。
  //
  //    错误归类（三者互不相同）：
  //      - 提供的公钥与证明中记录的签钥指纹不一致  -> KEY_NOT_FOUND（错误公钥）
  //      - 公钥一致但签名验证失败                  -> SIGNATURE_INVALID（签名内容不匹配）
  //      - 签名本身格式非法（前面）                -> PROOF_INVALID
  const providedFingerprint = keyFingerprint(publicKey);
  if (providedFingerprint.toLowerCase() !== proof.signerKeyFingerprint.toLowerCase()) {
    throw new ProvError(
      ERROR_CODES.KEY_NOT_FOUND,
      '提供的公钥与证明记录的签名密钥不一致（可能使用了错误公钥）',
      {
        providedKeyFingerprint: providedFingerprint,
        proofKeyFingerprint: proof.signerKeyFingerprint,
      },
    );
  }

  const canonicalProof = stableJsonStringify(proof);
  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, Buffer.from(canonicalProof, 'utf8'), publicKey, sigBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    throw new ProvError(
      ERROR_CODES.SIGNATURE_INVALID,
      '签名与证明内容不匹配（证明可能被改动，或签名已损坏）',
    );
  }

  // 6) 签名通过后重新扫描产物并逐项比对 —— 任何差异均为 INTEGRITY_MISMATCH。
  //    排除输出目录：证明/签名/清单通常与产物相邻，验证时不得把它们计入产物。
  //    包模式以分发包所在目录作为排除目录（独立文件同样由其所在目录推断）。
  const excludeDir = inferExcludeDir(proofLocation, artifactAbs);
  const currentSbom = await buildSbom(artifactAbs, excludeDir);
  const currentDigest = computeArtifactDigest(currentSbom);

  const mismatches = diffManifest(proof, currentSbom, currentDigest);
  if (mismatches.length > 0) {
    throw new ProvError(
      ERROR_CODES.INTEGRITY_MISMATCH,
      `检测到 ${mismatches.length} 处完整性差异`,
      { mismatches },
    );
  }

  // 7) SBOM 校验：独立文件模式显式成对提供时进行；包模式始终进行（成员必在包内）。
  //    结构、proof.sbomDigest、SBOM 签名、清单一致性逐项核校。
  let sbomDigest;
  if (bundleMode || sbomMode) {
    sbomDigest = verifySbomBytes({ sbomBytes, sbomSigBytes, proof, publicKey });
  }

  // 8) 共签模式：在证明、SBOM 与产物完整性全部通过后，才读取/解析共签清单并校验
  //    各共签签名（与独立文件模式原有顺序一致：此前清单缺失/非法不应抢先报错）。
  //    包模式的清单取自包内成员；独立文件模式取自 --cosignatures 目录。
  let cosignerCount;
  if (cosignMode) {
    if (bundleMode && proof.proofVersion !== PROOF_VERSION_COSIGN) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包缺少共签清单成员（证明未启用共签）');
    }
    let proofCosignManifest;
    let sbomCosignManifest;
    if (bundleMode) {
      proofCosignManifest = parseCosignManifest(proofCosignSource.bytes, '证明共签清单');
      sbomCosignManifest = parseCosignManifest(sbomCosignSource.bytes, 'SBOM 共签清单');
    } else {
      for (const [src, label] of [
        [proofCosignSource, '证明共签清单'],
        [sbomCosignSource, 'SBOM 共签清单'],
      ]) {
        try {
          await access(src.path, fsConstants.R_OK);
        } catch (err) {
          throw wrapFsError(err, `读取${label}`);
        }
      }
      proofCosignManifest = await readCosignManifest(proofCosignSource.path, '证明共签清单');
      sbomCosignManifest = await readCosignManifest(sbomCosignSource.path, 'SBOM 共签清单');
    }
    cosignerCount = verifyCosignaturesBytes({
      proofManifest: proofCosignManifest,
      sbomManifest: sbomCosignManifest,
      cosignerKeyPaths: cosignerKeyList,
      minCosigners,
      proof,
      canonicalProof,
      currentSbom,
    });
  }

  // 9) 可选策略：仅在签名、完整性、SBOM、可选共签校验全部通过后加载并执行。
  //    策略文件自身缺失/不可读/非法按其错误码返回（INPUT_NOT_FOUND /
  //    PERMISSION_DENIED / POLICY_INVALID）；内容违规为 POLICY_VIOLATION。
  //    包模式 SBOM 恒在包内并已校验，requireSbom 视为满足。
  let policyStatus;
  if (policyPath !== undefined) {
    const policy = await loadPolicy(policyPath);
    const violations = evaluatePolicy(policy, proof, bundleMode || sbomMode);
    if (violations.length > 0) {
      throw new ProvError(
        ERROR_CODES.POLICY_VIOLATION,
        `策略校验未通过（${violations.length} 项违规）`,
        { violations },
      );
    }
    policyStatus = 'PASS';
  }

  const result = {
    status: 'VERIFIED',
    proofVersion: proof.proofVersion,
    artifactDigest: currentDigest,
    fileCount: currentSbom.files.length,
  };
  if (bundleMode || sbomMode) result.sbomDigest = sbomDigest;
  if (cosignMode) result.cosignerCount = cosignerCount;
  if (policyPath !== undefined) result.policyStatus = policyStatus;
  return result;
}

// SBOM 校验（以字节为输入）：结构 -> 摘要 -> 签名 -> 清单一致性。
// 独立文件模式（读盘后传入）与分发包模式（成员解码后传入）共用。
function verifySbomBytes({ sbomBytes, sbomSigBytes, proof, publicKey }) {
  // a) sbom.json 必须是可解析的 JSON 且结构合法 —— 否则 PROOF_INVALID。
  let sbom;
  try {
    sbom = JSON.parse(sbomBytes.toString('utf8'));
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, 'SBOM 文件不是合法的 JSON');
  }
  const sbomError = validateSbom(sbom);
  if (sbomError) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, sbomError);
  }

  // b) 证明必须携带合法的 sbomDigest 字段。
  if (typeof proof.sbomDigest !== 'string' || !/^[0-9a-f]{64}$/i.test(proof.sbomDigest)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明缺少合法的 sbomDigest 字段');
  }

  // c) 重算 SBOM 规范字节摘要并与证明比对 —— 不一致说明 sbom.json 被替换或改动。
  const canonicalSbom = stableJsonStringify(sbom);
  const recomputed = sha256Hex(canonicalSbom);
  if (recomputed.toLowerCase() !== proof.sbomDigest.toLowerCase()) {
    throw new ProvError(
      ERROR_CODES.INTEGRITY_MISMATCH,
      'sbom.json 与证明记录的 sbomDigest 不一致（SBOM 可能被替换）',
      { mismatches: [{ path: 'sbom.json', kind: 'content-modified' }] },
    );
  }

  // d) SBOM 签名：合法 Base64 且 64 字节 —— 否则 PROOF_INVALID；验签失败 SIGNATURE_INVALID。
  const sigBuf = decodeSignatureBytes(sbomSigBytes, 'SBOM 签名文件');
  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, Buffer.from(canonicalSbom, 'utf8'), publicKey, sigBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    throw new ProvError(
      ERROR_CODES.SIGNATURE_INVALID,
      'SBOM 签名与 sbom.json 内容不匹配（SBOM 可能被改动，或签名已损坏）',
    );
  }

  // e) SBOM 清单与证明清单逐项一致（证明与当前扫描已在前面比对，故三方一致）。
  const mismatches = diffSbomAgainstProof(sbom, proof);
  if (mismatches.length > 0) {
    throw new ProvError(
      ERROR_CODES.INTEGRITY_MISMATCH,
      `SBOM 与证明清单存在 ${mismatches.length} 处差异`,
      { mismatches },
    );
  }

  return recomputed;
}

// 解析签名文件字节：去空白后必须是合法 Base64 且恰好解码为 64 字节 Ed25519 签名。
function decodeSignatureBytes(sigBytes, label) {
  const sigB64 = sigBytes.toString('utf8').replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sigB64) || sigB64.length === 0) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}不是合法的 Base64 内容`);
  }
  const sigBuf = Buffer.from(sigB64, 'base64');
  if (sigBuf.length !== 64) {
    throw new ProvError(
      ERROR_CODES.PROOF_INVALID,
      `${label}长度非法（Ed25519 应为 64 字节，实际 ${sigBuf.length} 字节）`,
    );
  }
  return sigBuf;
}

// ---------------------------------------------------------------------------
// 共签校验（proof.cosignatures.json / sbom.cosignatures.json）
// ---------------------------------------------------------------------------

// 在证明、可选 SBOM 与产物完整性全部通过后调用。
// 校验顺序：清单可读性 -> 结构与绑定（PROOF_INVALID）-> SBOM 摘要复算
// （INTEGRITY_MISMATCH）-> 共签公钥归属（KEY_NOT_FOUND）-> 逐签名验签与
// 有效数量（SIGNATURE_INVALID）。返回有效共签者数量（按指纹去重）。
// 以清单对象为输入的共签校验核心，独立文件模式与分发包模式共用。
// 校验顺序：清单结构与绑定（PROOF_INVALID）-> SBOM 摘要复算
// （INTEGRITY_MISMATCH）-> 共签公钥归属（KEY_NOT_FOUND）-> 逐签名验签与
// 有效数量（SIGNATURE_INVALID）。返回有效共签者数量（按指纹去重）。
function verifyCosignaturesBytes({
  proofManifest,
  sbomManifest,
  cosignerKeyPaths,
  minCosigners,
  proof,
  canonicalProof,
  currentSbom,
}) {
  // 清单必须绑定当前证明：记录的产物/SBOM 摘要与证明一致。
  for (const [m, label] of [
    [proofManifest, '证明共签清单'],
    [sbomManifest, 'SBOM 共签清单'],
  ]) {
    if (
      m.artifactDigest.toLowerCase() !== proof.artifactDigest.toLowerCase() ||
      m.sbomDigest.toLowerCase() !== proof.sbomDigest.toLowerCase()
    ) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}与证明记录的摘要不一致`);
    }
  }

  // 清单签名者集合必须与证明声明的共签者集合一致，且不得包含主签名指纹。
  const declared = Array.isArray(proof.cosignerKeyFingerprints)
    ? proof.cosignerKeyFingerprints.map((fp) => fp.toLowerCase())
    : [];
  const mainFingerprint = proof.signerKeyFingerprint.toLowerCase();
  for (const [m, label] of [
    [proofManifest, '证明共签清单'],
    [sbomManifest, 'SBOM 共签清单'],
  ]) {
    const manifestSet = m.signers.map((s) => s.keyFingerprint.toLowerCase());
    if (manifestSet.includes(mainFingerprint)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}不得包含主签名密钥指纹`);
    }
    const sameSet =
      manifestSet.length === declared.length &&
      manifestSet.every((fp, i) => fp === declared[i]);
    if (!sameSet) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}签名者集合与证明声明的共签者不一致`);
    }
  }

  // 复算当前 SBOM 规范字节摘要并与证明比对 —— SBOM 变化优先报 INTEGRITY_MISMATCH。
  if (typeof proof.sbomDigest !== 'string' || !/^[0-9a-f]{64}$/i.test(proof.sbomDigest)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明缺少合法的 sbomDigest 字段');
  }
  const canonicalSbom = stableJsonStringify(currentSbom);
  if (sha256Hex(canonicalSbom).toLowerCase() !== proof.sbomDigest.toLowerCase()) {
    throw new ProvError(
      ERROR_CODES.INTEGRITY_MISMATCH,
      'SBOM 与证明记录的 sbomDigest 不一致（SBOM 可能被替换）',
      { mismatches: [{ path: 'sbom.json', kind: 'content-modified' }] },
    );
  }

  // 逐一校验提供的共签公钥：必须是证明声明的共签者，且其对证明与 SBOM 的签名均有效。
  const verified = new Set();
  for (const keyPath of cosignerKeyPaths) {
    const pub = readPublicKey(resolve(keyPath));
    const fp = keyFingerprint(pub).toLowerCase();
    if (!declared.includes(fp)) {
      throw new ProvError(
        ERROR_CODES.KEY_NOT_FOUND,
        '共签公钥未在证明声明的共签者集合中（未声明或错误公钥）',
        { providedKeyFingerprint: fp },
      );
    }
    const proofEntry = proofManifest.signers.find((s) => s.keyFingerprint.toLowerCase() === fp);
    const sbomEntry = sbomManifest.signers.find((s) => s.keyFingerprint.toLowerCase() === fp);
    const proofSigOk = verifyCosigSignature(proofEntry.signature, canonicalProof, pub);
    const sbomSigOk = verifyCosigSignature(sbomEntry.signature, canonicalSbom, pub);
    if (!proofSigOk || !sbomSigOk) {
      throw new ProvError(
        ERROR_CODES.SIGNATURE_INVALID,
        `共签签名与内容不匹配（指纹 ${fp}，${proofSigOk ? 'SBOM' : '证明'}签名失配）`,
      );
    }
    verified.add(fp);
  }

  if (verified.size < minCosigners) {
    throw new ProvError(
      ERROR_CODES.SIGNATURE_INVALID,
      `有效共签数量不足：需要至少 ${minCosigners} 个，实际 ${verified.size} 个`,
    );
  }
  return verified.size;
}

function verifyCosigSignature(signatureB64, canonicalBytes, publicKey) {
  try {
    return cryptoVerify(
      null,
      Buffer.from(canonicalBytes, 'utf8'),
      publicKey,
      Buffer.from(signatureB64.replace(/\s+/g, ''), 'base64'),
    );
  } catch {
    return false;
  }
}

async function readCosignManifest(path, label) {
  const text = await readFileUtf8(path);
  return parseCosignManifest(text, label);
}

function parseCosignManifest(textOrBytes, label) {
  let manifest;
  try {
    manifest = JSON.parse(textOrBytes.toString('utf8'));
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}不是合法的 JSON`);
  }
  const error = validateCosignManifest(manifest);
  if (error) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, `${label}${error}`);
  }
  return manifest;
}

// 共签清单结构校验：schemaVersion、摘要字段、按指纹严格升序（隐含去重）的 signers，
// 每项含合法指纹与可解码为 64 字节的 Base64 Ed25519 签名。
function validateCosignManifest(manifest) {
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return '顶层必须是 JSON 对象';
  }
  if (manifest.schemaVersion !== COSIGN_SCHEMA_VERSION) {
    return `schemaVersion 缺失或不受支持（应为 ${COSIGN_SCHEMA_VERSION}）`;
  }
  for (const k of ['artifactDigest', 'sbomDigest']) {
    if (typeof manifest[k] !== 'string' || !/^[0-9a-f]{64}$/i.test(manifest[k])) {
      return `字段缺失或类型非法: ${k}`;
    }
  }
  if (!Array.isArray(manifest.signers)) return '字段缺失或类型非法: signers';
  let prev = null;
  for (const s of manifest.signers) {
    if (s === null || typeof s !== 'object' || Array.isArray(s)) return 'signers 条目必须是对象';
    if (typeof s.keyFingerprint !== 'string' || !/^[0-9a-f]{64}$/i.test(s.keyFingerprint)) {
      return 'signers 条目 keyFingerprint 非法';
    }
    if (typeof s.signature !== 'string') return 'signers 条目 signature 非法';
    const b64 = s.signature.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length === 0) {
      return 'signers 条目 signature 不是合法的 Base64 内容';
    }
    if (Buffer.from(b64, 'base64').length !== 64) {
      return 'signers 条目签名长度非法（Ed25519 应为 64 字节）';
    }
    const lower = s.keyFingerprint.toLowerCase();
    if (prev !== null && lower <= prev) return 'signers 必须按指纹升序排列且不得重复';
    prev = lower;
  }
  return null;
}

function inferExcludeDir(proofAbs, artifactAbs) {
  // 证明文件所在目录若位于产物之内，则将其视为生成时的输出目录予以排除。
  const proofDir = dirname(proofAbs);
  if (isWithin(proofDir, artifactAbs)) return proofDir;
  return null;
}

async function readFileUtf8(p) {
  try {
    return (await readFile(p, 'utf8'));
  } catch (err) {
    throw wrapFsError(err, '读取文件');
  }
}

function validateProof(proof) {
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    return '证明文件顶层必须是 JSON 对象';
  }
  const needString = ['proofVersion', 'artifactName', 'artifactDigest', 'fileName', 'generatedAt', 'signerKeyFingerprint'];
  for (const k of needString) {
    if (typeof proof[k] !== 'string' || proof[k].length === 0) {
      return `证明字段缺失或类型非法: ${k}`;
    }
  }
  if (!/^[0-9a-f]{64}$/i.test(proof.artifactDigest)) {
    return '证明中的 artifactDigest 不是合法的 SHA-256 十六进制摘要';
  }
  if (!/^[0-9a-f]{64}$/i.test(proof.signerKeyFingerprint)) {
    return '证明中的 signerKeyFingerprint 不是合法的 SHA-256 十六进制摘要';
  }
  if (typeof proof.size !== 'number' || !Number.isFinite(proof.size) || proof.size < 0) {
    return '证明字段缺失或类型非法: size';
  }
  // 共签声明（proofVersion 1.1 起）：出现时必须是按指纹升序去重的合法指纹数组，
  // 且不得包含主签名密钥指纹；1.1 版本的证明必须携带该字段。
  if (proof.cosignerKeyFingerprints !== undefined) {
    if (!Array.isArray(proof.cosignerKeyFingerprints)) {
      return '证明字段缺失或类型非法: cosignerKeyFingerprints';
    }
    let prev = null;
    for (const fp of proof.cosignerKeyFingerprints) {
      if (typeof fp !== 'string' || !/^[0-9a-f]{64}$/i.test(fp)) {
        return '证明中的 cosignerKeyFingerprints 存在非法的 SHA-256 十六进制指纹';
      }
      const lower = fp.toLowerCase();
      if (prev !== null && lower <= prev) {
        return '证明中的 cosignerKeyFingerprints 必须按指纹升序排列且不得重复';
      }
      prev = lower;
    }
    if (
      proof.cosignerKeyFingerprints
        .map((fp) => fp.toLowerCase())
        .includes(proof.signerKeyFingerprint.toLowerCase())
    ) {
      return '证明中的 cosignerKeyFingerprints 不得包含主签名密钥指纹';
    }
  }
  if (proof.proofVersion === PROOF_VERSION_COSIGN && proof.cosignerKeyFingerprints === undefined) {
    return '证明字段缺失或类型非法: cosignerKeyFingerprints';
  }
  if (!Array.isArray(proof.files)) return '证明字段缺失或类型非法: files';
  return validateFileEntries(proof.files);
}

// 清单条目校验：proof.files 与 sbom.files 共用同一套规则。
function validateFileEntries(files) {
  const seen = new Set();
  for (const f of files) {
    if (f === null || typeof f !== 'object') return '清单条目必须是对象';
    if (typeof f.path !== 'string' || f.path.length === 0) return '清单条目 path 非法';
    if (f.path.includes('\\')) return `清单相对路径必须使用正斜杠: ${f.path}`;
    if (f.path.startsWith('/') || f.path.split('/').includes('..')) {
      return `清单相对路径越界: ${f.path}`;
    }
    if (seen.has(f.path)) return `清单路径重复: ${f.path}`;
    seen.add(f.path);
    if (!/^[0-9a-f]{64}$/i.test(f.sha256)) return `清单条目摘要非法: ${f.path}`;
    if (typeof f.size !== 'number' || !Number.isFinite(f.size) || f.size < 0) {
      return `清单条目大小非法: ${f.path}`;
    }
    if (typeof f.type !== 'string' || f.type.length === 0) return `清单条目类型非法: ${f.path}`;
  }
  return null;
}

function validateSbom(sbom) {
  if (sbom === null || typeof sbom !== 'object' || Array.isArray(sbom)) {
    return 'SBOM 顶层必须是 JSON 对象';
  }
  for (const k of ['schemaVersion', 'artifactName', 'rootType']) {
    if (typeof sbom[k] !== 'string' || sbom[k].length === 0) {
      return `SBOM 字段缺失或类型非法: ${k}`;
    }
  }
  if (!Array.isArray(sbom.files)) return 'SBOM 字段缺失或类型非法: files';
  return validateFileEntries(sbom.files);
}

// 返回差异列表；每条 {path, kind}。顶层摘要差异兜底。
function diffManifest(proof, currentSbom, currentDigest) {
  const mismatches = [];
  const proofFiles = new Map(proof.files.map((f) => [f.path, f]));
  const currentFiles = new Map(currentSbom.files.map((f) => [f.path, f]));

  for (const [path, pf] of proofFiles) {
    const cur = currentFiles.get(path);
    if (!cur) {
      mismatches.push({ path, kind: 'missing' }); // 证明中存在、产物中已删除
      continue;
    }
    if (cur.sha256.toLowerCase() !== pf.sha256.toLowerCase()) {
      mismatches.push({ path, kind: 'content-modified' });
    } else if (cur.size !== pf.size) {
      mismatches.push({ path, kind: 'size-mismatch' });
    }
  }
  for (const path of currentFiles.keys()) {
    if (!proofFiles.has(path)) {
      mismatches.push({ path, kind: 'added' }); // 产物中新出现的文件
    }
  }

  if (proof.artifactDigest.toLowerCase() !== currentDigest.toLowerCase() && mismatches.length === 0) {
    // 理论上不会发生（逐文件比对已覆盖），作为顶层摘要兜底。
    mismatches.push({ path: '.', kind: 'artifact-digest-mismatch' });
  }
  if (proof.fileName !== currentSbom.artifactName) {
    mismatches.push({ path: '.', kind: 'artifact-name-mismatch' });
  }

  mismatches.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : 1));
  return mismatches;
}

// SBOM 清单与证明清单逐项比对；以证明为基准，kind 语义与 diffManifest 一致。
function diffSbomAgainstProof(sbom, proof) {
  const mismatches = [];
  const sbomFiles = new Map(sbom.files.map((f) => [f.path, f]));
  const proofFiles = new Map(proof.files.map((f) => [f.path, f]));

  for (const [path, pf] of proofFiles) {
    const sf = sbomFiles.get(path);
    if (!sf) {
      mismatches.push({ path, kind: 'missing' }); // 证明中存在、SBOM 中缺失
      continue;
    }
    if (sf.sha256.toLowerCase() !== pf.sha256.toLowerCase()) {
      mismatches.push({ path, kind: 'content-modified' });
    } else if (sf.size !== pf.size) {
      mismatches.push({ path, kind: 'size-mismatch' });
    }
  }
  for (const path of sbomFiles.keys()) {
    if (!proofFiles.has(path)) {
      mismatches.push({ path, kind: 'added' }); // SBOM 中新出现的条目
    }
  }
  if (sbom.artifactName !== proof.artifactName) {
    mismatches.push({ path: '.', kind: 'artifact-name-mismatch' });
  }

  mismatches.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : 1));
  return mismatches;
}

// ---------------------------------------------------------------------------
// 策略（policy.json）
// ---------------------------------------------------------------------------

export const POLICY_VERSION = '1.0';

// 严格解析 UTC ISO-8601：仅接受以 Z 结尾、年月日时分秒（秒可带任意位小数）
// 均为数字且取值合法的时间；其余一律视为非法（包括 +00:00 偏移写法）。
// 毫秒以下的精度截断；同时校验真实日历（如不接受 2 月 30 日）。
export function parseUtcIso(value) {
  if (typeof value !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac] = m;
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(Number(y), month)) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  const ms = frac === undefined ? 0 : Number(frac.slice(0, 3).padEnd(3, '0'));
  return Date.UTC(Number(y), month - 1, day, hour, minute, second, ms);
}

function daysInMonth(year, month) {
  // month: 1-12
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  }
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

function isNonNegSafeInt(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

// 读取并严格校验策略文件。
// 缺失 -> INPUT_NOT_FOUND；不可读 -> PERMISSION_DENIED；
// JSON 不可解析/非对象/未知字段/非法类型或取值/时间区间倒置 -> POLICY_INVALID。
async function loadPolicy(policyPath) {
  const policyAbs = resolve(policyPath);
  let text;
  try {
    text = await readFileUtf8(policyAbs);
  } catch (err) {
    throw wrapFsError(err, '读取策略文件');
  }
  let policy;
  try {
    policy = JSON.parse(text);
  } catch {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略文件不是合法的 JSON');
  }
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略顶层必须是 JSON 对象');
  }

  const allowed = new Set([
    'policyVersion',
    'proofNotBefore',
    'proofNotAfter',
    'allowedKeyFingerprints',
    'requireSbom',
    'maxFileCount',
    'maxSize',
  ]);
  for (const key of Object.keys(policy)) {
    if (!allowed.has(key)) {
      throw new ProvError(ERROR_CODES.POLICY_INVALID, `策略包含未知字段: ${key}`);
    }
  }

  // policyVersion 必填，字符串且固定为 "1.0"。
  if (policy.policyVersion === undefined) {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略缺少必填字段: policyVersion');
  }
  if (typeof policy.policyVersion !== 'string') {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略字段类型非法: policyVersion');
  }
  if (policy.policyVersion !== POLICY_VERSION) {
    throw new ProvError(
      ERROR_CODES.POLICY_INVALID,
      `不支持的策略版本: ${policy.policyVersion}`,
    );
  }

  // 时间字段可选；出现时必须是合法 UTC ISO-8601 字符串。
  for (const k of ['proofNotBefore', 'proofNotAfter']) {
    if (policy[k] !== undefined && parseUtcIso(policy[k]) === null) {
      throw new ProvError(ERROR_CODES.POLICY_INVALID, `策略字段取值非法: ${k}`);
    }
  }

  // 指纹白名单可选；缺省不约束，显式给出时必须为非空 SHA-256 十六进制数组。
  if (policy.allowedKeyFingerprints !== undefined) {
    if (!Array.isArray(policy.allowedKeyFingerprints)) {
      throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略字段类型非法: allowedKeyFingerprints');
    }
    if (policy.allowedKeyFingerprints.length === 0) {
      throw new ProvError(
        ERROR_CODES.POLICY_INVALID,
        '策略字段 allowedKeyFingerprints 不允许为空数组',
      );
    }
    for (const fp of policy.allowedKeyFingerprints) {
      if (typeof fp !== 'string' || !/^[0-9a-f]{64}$/i.test(fp)) {
        throw new ProvError(
          ERROR_CODES.POLICY_INVALID,
          '策略字段 allowedKeyFingerprints 中存在非法的 SHA-256 十六进制指纹',
        );
      }
    }
  }

  if (policy.requireSbom !== undefined && typeof policy.requireSbom !== 'boolean') {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略字段类型非法: requireSbom');
  }
  for (const k of ['maxFileCount', 'maxSize']) {
    if (policy[k] !== undefined && !isNonNegSafeInt(policy[k])) {
      throw new ProvError(ERROR_CODES.POLICY_INVALID, `策略字段取值非法: ${k}`);
    }
  }

  // 时间区间不得倒置；相等（闭区间单点）允许。
  if (policy.proofNotBefore !== undefined && policy.proofNotAfter !== undefined) {
    if (parseUtcIso(policy.proofNotBefore) > parseUtcIso(policy.proofNotAfter)) {
      throw new ProvError(
        ERROR_CODES.POLICY_INVALID,
        '策略时间区间非法：proofNotBefore 晚于 proofNotAfter',
      );
    }
  }

  return policy;
}

// 在签名、完整性、可选 SBOM 校验全部通过后执行策略。
// 返回违规列表（已按时间、密钥、SBOM、文件数、大小排序）；空列表表示通过。
// 每条违规形如 { rule, observed }。
function evaluatePolicy(policy, proof, sbomMode) {
  const violations = [];
  const push = (rule, observed) => violations.push({ rule, observed });

  // 1) 时间窗口：proof.generatedAt 必须落在闭区间；字段非法单独记。
  const generatedAtMs = parseUtcIso(proof.generatedAt);
  if (generatedAtMs === null) {
    push('generated-at-invalid', proof.generatedAt);
  } else {
    if (policy.proofNotBefore !== undefined && generatedAtMs < parseUtcIso(policy.proofNotBefore)) {
      push('proof-not-before', proof.generatedAt);
    }
    if (policy.proofNotAfter !== undefined && generatedAtMs > parseUtcIso(policy.proofNotAfter)) {
      push('proof-not-after', proof.generatedAt);
    }
  }

  // 2) 密钥指纹必须命中白名单（大小写不敏感）。
  if (policy.allowedKeyFingerprints !== undefined) {
    const trusted = policy.allowedKeyFingerprints.map((fp) => fp.toLowerCase());
    if (!trusted.includes(proof.signerKeyFingerprint.toLowerCase())) {
      push('allowed-key-fingerprints', proof.signerKeyFingerprint);
    }
  }

  // 3) requireSbom：必须成对提供 --sbom/--sbom-signature；其有效性已在前面校验。
  //    requireSbom 为 false 时不禁用额外提供的 SBOM（沿用既有校验）。
  if (policy.requireSbom === true && !sbomMode) {
    push('require-sbom', 'absent');
  }

  // 4) 文件数上限。
  if (policy.maxFileCount !== undefined && proof.files.length > policy.maxFileCount) {
    push('max-file-count', proof.files.length);
  }

  // 5) 总大小上限。
  if (policy.maxSize !== undefined && proof.size > policy.maxSize) {
    push('max-size', proof.size);
  }

  return violations;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { _: [] };
  // 可重复参数：每次出现都追加到数组；其余参数保持“后出现覆盖先出现”。
  const repeatable = new Set(['co-key', 'cosigner-key']);
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      const hasValue = next !== undefined && !next.startsWith('--');
      const value = hasValue ? next : true;
      if (hasValue) i += 1;
      if (repeatable.has(key)) {
        if (args[key] === undefined) args[key] = [];
        args[key].push(value);
      } else {
        args[key] = value;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function usage() {
  return [
    'Prov Guard —— 软件供应链证明与完整性校验工具',
    '',
    '用法:',
    '  provguard keygen   --key-dir <dir> [--name <prefix>]',
    '  provguard generate --artifact <path> --key <private.pem> --out <dir> \\',
    '                      [--co-key <private.pem> ...] [--bundle]',
    '  provguard verify   --artifact <path> --key <public.pem> \\',
    '                      (--proof <proof.json> --signature <proof.json.sig> | \\',
    '                       --bundle <proof.bundle.json>) \\',
    '                      [--sbom <sbom.json> --sbom-signature <sbom.json.sig>] \\',
    '                      [--cosignatures <dir> --cosigner-key <public.pem> ... \\',
    '                       --min-cosigners <n>] \\',
    '                      [--policy <policy.json>]',
    '',
    'generate 输出: proof.json / proof.json.sig / sbom.json / sbom.json.sig',
    '启用共签时额外输出: proof.cosignatures.json / sbom.cosignatures.json',
    '使用 --bundle 时再额外输出: proof.bundle.json（上述文件的单文件分发包）',
    '成功状态: VERIFIED；错误码见 README。',
  ].join('\n');
}

function printMachineError(err) {
  const payload = {
    status: 'ERROR',
    errorCode: err instanceof ProvError ? err.code : 'INTERNAL_ERROR',
    message: err && err.message ? err.message : String(err),
  };
  if (err && err.details !== undefined) payload.details = err.details;
  return stableJsonStringify(payload);
}

async function main(argv) {
  const args = parseArgs(argv);
  const command = args._[0];

  try {
    if (!command || command === 'help' || command === '--help' || command === '-h') {
      process.stdout.write(`${usage()}\n`);
      return 0;
    }

    if (command === 'keygen') {
      if (!args['key-dir']) {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '缺少必填参数 --key-dir');
      }
      const r = await keygen({ keyDir: args['key-dir'], name: args.name || 'provguard' });
      process.stdout.write(
        `${stableJsonStringify({ status: 'KEYGEN_OK', ...r })}\n`,
      );
      return 0;
    }

    if (command === 'generate') {
      const missing = ['artifact', 'key', 'out'].filter((k) => typeof args[k] !== 'string');
      if (missing.length) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          `缺少必填参数: ${missing.map((m) => `--${m}`).join(', ')}`,
        );
      }
      // --co-key 可重复；出现时每个都必须带私钥路径。
      const coKeys = args['co-key'] === undefined ? [] : args['co-key'];
      if (coKeys.some((k) => typeof k !== 'string')) {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--co-key 需要提供共签私钥文件路径');
      }
      // --bundle 为布尔开关，不取值。
      if (args.bundle !== undefined && args.bundle !== true) {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--bundle 是开关参数，不接受取值');
      }
      const r = await generate({
        artifact: args.artifact,
        key: args.key,
        out: args.out,
        coKeys,
        bundle: args.bundle === true,
      });
      const out = {
        status: 'GENERATED',
        proofVersion: r.proofVersion,
        artifactDigest: r.artifactDigest,
        fileCount: r.fileCount,
        proofPath: r.proofPath,
        sbomPath: r.sbomPath,
        signaturePath: r.signaturePath,
        sbomSignaturePath: r.sbomSignaturePath,
      };
      if (r.bundlePath !== undefined) out.bundlePath = r.bundlePath;
      if (r.cosignerCount !== undefined) {
        out.cosignerCount = r.cosignerCount;
        out.proofCosignaturesPath = r.proofCosignaturesPath;
        out.sbomCosignaturesPath = r.sbomCosignaturesPath;
      }
      process.stdout.write(`${stableJsonStringify(out)}\n`);
      return 0;
    }

    if (command === 'verify') {
      // --artifact 与 --key 在两种模式下均必填。
      const baseMissing = ['artifact', 'key'].filter((k) => typeof args[k] !== 'string');
      if (baseMissing.length) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          `缺少必填参数: ${baseMissing.map((m) => `--${m}`).join(', ')}`,
        );
      }

      // 分发包模式：--bundle 与独立文件输入互斥。
      const hasBundle = args.bundle !== undefined;
      const standaloneInputs = ['proof', 'signature', 'sbom', 'sbom-signature', 'cosignatures'];
      if (hasBundle) {
        if (typeof args.bundle !== 'string') {
          throw new ProvError(ERROR_CODES.USAGE_ERROR, '--bundle 需要提供分发包文件路径');
        }
        const mixed = standaloneInputs.filter((k) => args[k] !== undefined);
        if (mixed.length) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            `--bundle 与 --${mixed[0]} 等独立文件参数互斥`,
          );
        }
      } else {
        const missing = ['proof', 'signature'].filter((k) => typeof args[k] !== 'string');
        if (missing.length) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            `缺少必填参数: ${missing.map((m) => `--${m}`).join(', ')}（或改用 --bundle）`,
          );
        }
      }
      // --sbom 与 --sbom-signature 必须成对出现（仅独立文件模式可达）。
      const hasSbom = typeof args.sbom === 'string';
      const hasSbomSig = typeof args['sbom-signature'] === 'string';
      if (hasSbom !== hasSbomSig) {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--sbom 与 --sbom-signature 必须成对提供');
      }
      // --policy 为可选单值参数；出现时必须带文件路径。
      const hasPolicy = args.policy !== undefined;
      if (hasPolicy && typeof args.policy !== 'string') {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--policy 需要提供策略文件路径');
      }
      // 共签校验：
      //   独立文件模式 —— --cosignatures、--cosigner-key（可重复）、--min-cosigners 必须同时提供；
      //   包模式       —— 没有 --cosignatures（清单在包内），--cosigner-key 与 --min-cosigners
      //                  仍须成对，且 min 为不超过公钥数量的正整数。
      const cosigKeysRaw = args['cosigner-key'];
      const anyCosign =
        args.cosignatures !== undefined || cosigKeysRaw !== undefined || args['min-cosigners'] !== undefined;
      let cosignOpts = {};
      if (anyCosign) {
        const keyListOk =
          Array.isArray(cosigKeysRaw) &&
          cosigKeysRaw.length > 0 &&
          cosigKeysRaw.every((k) => typeof k === 'string');
        const minRaw = args['min-cosigners'];
        const minOk =
          typeof minRaw === 'string' && /^\d+$/.test(minRaw) && Number.isSafeInteger(Number(minRaw)) && Number(minRaw) >= 1;
        const dirOk = hasBundle || typeof args.cosignatures === 'string';
        if (!dirOk || !keyListOk || !minOk) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            hasBundle
              ? '包模式下 --cosigner-key（可重复）与 --min-cosigners（正整数）必须同时提供'
              : '--cosignatures、--cosigner-key（可重复）与 --min-cosigners（正整数）必须同时提供',
          );
        }
        if (Number(minRaw) > cosigKeysRaw.length) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            '--min-cosigners 超过提供的共签公钥数量',
          );
        }
        cosignOpts = {
          cosignerKeys: cosigKeysRaw,
          minCosigners: Number(minRaw),
        };
        if (!hasBundle) cosignOpts.cosignatures = args.cosignatures;
      }
      const r = await verify({
        artifact: args.artifact,
        key: args.key,
        bundle: hasBundle ? args.bundle : undefined,
        proof: hasBundle ? undefined : args.proof,
        signature: hasBundle ? undefined : args.signature,
        sbom: hasSbom ? args.sbom : undefined,
        sbomSignature: hasSbomSig ? args['sbom-signature'] : undefined,
        policy: hasPolicy ? args.policy : undefined,
        ...cosignOpts,
      });
      process.stdout.write(`${stableJsonStringify(r)}\n`);
      return 0;
    }

    throw new ProvError(ERROR_CODES.USAGE_ERROR, `未知子命令: ${command}`);
  } catch (err) {
    // stderr 仅输出机器可读 JSON；用法帮助走 stdout，避免污染错误流。
    process.stderr.write(`${printMachineError(err)}\n`);
    if (err instanceof ProvError && err.code === ERROR_CODES.USAGE_ERROR) {
      process.stdout.write(`\n${usage()}\n`);
    }
    return 1;
  }
}

// 仅作为脚本直接运行时执行 main；被测试 import 时不执行。
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

export { main, ProvError, ERROR_CODES as CODES };
