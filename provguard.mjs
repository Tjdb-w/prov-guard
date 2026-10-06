#!/usr/bin/env node
// Prov Guard —— 软件供应链证明与完整性校验工具（零依赖，Node >= 18）。
//
// 子命令：
//   keygen   --key-dir <dir> [--name <prefix>]
//   generate --artifact <path> --key <private-key> --out <dir> [--bundle]
//   policy-sign --policy <policy.json> --key <private.pem> --signature <policy.json.sig>
//   verify   --artifact <path> --proof <file> --signature <file> --key <public-key>
//            [--sbom <file> --sbom-signature <file>] [--policy <policy.json>]
//            [--policy-signature <policy.json.sig> --policy-key <public.pem>]
//   verify   --artifact <path> --bundle <proof.bundle.json> --key <public-key>
//            [--cosigner-key <public-key> ... --min-cosigners <n>] [--policy <policy.json>]
//            [--policy-signature <policy.json.sig> --policy-key <public.pem>]
//   gate     --artifact <path> --attestation <gate.attestation.json>
//            --sbom <gate.sbom.json> --policy <gate.policy.json>
//
// gate 为独立发布门禁：只接受本地公开文件（不读取密钥或凭证；验签公钥内嵌于
// 证明），不改动其他子命令的文件格式、标准输出、退出码与异常处理。
// gate 全部错误在 stderr 输出错误码：InputError（退出 2）/ PolicyError（退出 2）/
// VerificationError（退出 3）；策略拒绝为正常 denied 报告（退出 4），全部通过为
// allowed 报告（退出 0）。
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
// 证明分发包（proof.bundle.json）版本与成员逻辑名。
export const BUNDLE_VERSION = '1.0';
export const BUNDLE_BASE_MEMBERS = Object.freeze(['proof', 'proof-signature', 'sbom', 'sbom-signature']);
export const BUNDLE_COSIGN_MEMBERS = Object.freeze(['proof-cosignatures', 'sbom-cosignatures']);

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
  // 证明分发包：--bundle 时在输出目录额外写出 proof.bundle.json（不影响既有文件）。
  const bundlePath = bundle ? join(outReal, 'proof.bundle.json') : null;
  try {
    await atomicWrite(proofPath, proofJson);
    await atomicWrite(sbomPath, sbomJson);
    await atomicWrite(sigPath, signatureB64);
    await atomicWrite(sbomSigPath, sbomSignatureB64);
    let proofCosigJson = null;
    let sbomCosigJson = null;
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
    if (bundle) {
      const entries = [
        ['proof', proofJson],
        ['proof-signature', signatureB64],
        ['sbom', sbomJson],
        ['sbom-signature', sbomSignatureB64],
      ];
      if (coSign) {
        entries.push(['proof-cosignatures', proofCosigJson], ['sbom-cosignatures', sbomCosigJson]);
      }
      await atomicWrite(bundlePath, buildBundleJson(entries));
    }
  } catch (err) {
    throw wrapFsError(err, '写入证明产物');
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
  if (coSign) {
    result.cosignerCount = coSigners.length;
    result.proofCosignaturesPath = proofCosigPath;
    result.sbomCosignaturesPath = sbomCosigPath;
  }
  if (bundle) {
    result.bundlePath = bundlePath;
  }
  return result;
}

// ---------------------------------------------------------------------------
// policy-sign：为既有策略文件生成独立的 Ed25519 签名。
// 不改写策略、私钥或任何证明产物；签名覆盖 policy.json 的 UTF-8 稳定 JSON
// 字节（键名排序、两空格缩进、末尾换行），Base64 加换行保存，重复生成逐字节一致。
// 校验顺序：策略与私钥可读 -> 策略 JSON 合法（POLICY_INVALID）-> 私钥可解析且为
// Ed25519（KEY_NOT_FOUND）-> 写签名（写失败 PERMISSION_DENIED）。
// ---------------------------------------------------------------------------

export async function policySign({ policy: policyPath, key: keyPath, signature: sigPath }) {
  const policyAbs = resolve(policyPath);
  const keyAbs = resolve(keyPath);
  const sigAbs = resolve(sigPath);
  // 输入检查：策略与私钥必须存在且可读。
  for (const [p, label] of [
    [policyAbs, '策略文件'],
    [keyAbs, '私钥'],
  ]) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      throw wrapFsError(err, `读取${label}`);
    }
  }

  // 以磁盘字节为真解析并校验策略结构，再重算稳定 JSON 字节作为签名输入。
  let policyText;
  try {
    policyText = await readFileUtf8(policyAbs);
  } catch (err) {
    throw wrapFsError(err, '读取策略文件');
  }
  let policy;
  try {
    policy = JSON.parse(policyText);
  } catch {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, '策略文件不是合法的 JSON');
  }
  // 复用既有严格校验：未知字段、取值与 policyVersion 非法均为 POLICY_INVALID。
  const policyError = validatePolicyObject(policy);
  if (policyError) {
    throw new ProvError(ERROR_CODES.POLICY_INVALID, policyError);
  }

  const privateKey = readPrivateKey(keyAbs);
  const signerFingerprint = keyFingerprint(createPublicKey(privateKey));

  const canonicalBytes = Buffer.from(stableJsonStringify(policy) + '\n', 'utf8');
  const signatureB64 = cryptoSign(null, canonicalBytes, privateKey).toString('base64') + '\n';
  try {
    await atomicWrite(sigAbs, signatureB64);
  } catch (err) {
    throw wrapFsError(err, '写入策略签名文件');
  }

  return {
    policyPath: policyAbs,
    signaturePath: sigAbs,
    policySignerFingerprint: signerFingerprint,
  };
}

// ---------------------------------------------------------------------------
// 证明分发包（proof.bundle.json）：把一套证明产物打包为单个稳定 JSON 文件。
// members 按逻辑名排序（stableJsonStringify 按键名排序），每项保存原文件字节的
// Base64、SHA-256 与字节长度；原样保留文件字节（含签名输入的规范字节），
// 因此除 generatedAt、proof 及其签名外，重复生成的包内容逐字节稳定。
// ---------------------------------------------------------------------------

function bundleMember(content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  return { data: buf.toString('base64'), sha256: sha256Hex(buf), size: buf.length };
}

function buildBundleJson(entries) {
  const members = {};
  for (const [name, content] of entries) members[name] = bundleMember(content);
  return stableJsonStringify({ bundleVersion: BUNDLE_VERSION, members }) + '\n';
}

// 解析并校验分发包结构，返回 { members: Map<逻辑名, Buffer>, hasCosignMembers }。
// JSON 不可解析、bundleVersion 非 1.0、成员缺失或多余、Base64 非法、
// 长度或 SHA-256 不符均为 PROOF_INVALID。
function parseBundle(text) {
  let bundle;
  try {
    bundle = JSON.parse(text);
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明分发包不是合法的 JSON');
  }
  if (bundle === null || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明分发包顶层必须是 JSON 对象');
  }
  if (bundle.bundleVersion !== BUNDLE_VERSION) {
    throw new ProvError(
      ERROR_CODES.PROOF_INVALID,
      `分发包 bundleVersion 缺失或不受支持（应为 ${BUNDLE_VERSION}）`,
    );
  }
  const rawMembers = bundle.members;
  if (rawMembers === null || typeof rawMembers !== 'object' || Array.isArray(rawMembers)) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包字段缺失或类型非法: members');
  }
  const known = new Set([...BUNDLE_BASE_MEMBERS, ...BUNDLE_COSIGN_MEMBERS]);
  for (const name of Object.keys(rawMembers)) {
    if (!known.has(name)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包含有多余成员: ${name}`);
    }
  }
  for (const name of BUNDLE_BASE_MEMBERS) {
    if (!(name in rawMembers)) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, `分发包缺少成员: ${name}`);
    }
  }
  // 共签成员必须成对出现（与生成时的输出一致）。
  const hasProofCosig = BUNDLE_COSIGN_MEMBERS[0] in rawMembers;
  const hasSbomCosig = BUNDLE_COSIGN_MEMBERS[1] in rawMembers;
  if (hasProofCosig !== hasSbomCosig) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '分发包共签成员必须成对出现');
  }
  const members = new Map();
  for (const [name, m] of Object.entries(rawMembers)) {
    members.set(name, decodeBundleMember(name, m));
  }
  return { members, hasCosignMembers: hasProofCosig };
}

function decodeBundleMember(name, member) {
  const bad = (why) => new ProvError(ERROR_CODES.PROOF_INVALID, `分发包成员 ${name} ${why}`);
  if (member === null || typeof member !== 'object' || Array.isArray(member)) {
    throw bad('必须是对象');
  }
  if (typeof member.data !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(member.data)) {
    throw bad('的 data 不是合法的 Base64 内容');
  }
  if (typeof member.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(member.sha256)) {
    throw bad('的 sha256 不是合法的 SHA-256 十六进制摘要');
  }
  if (!isNonNegSafeInt(member.size)) {
    throw bad('的 size 非法（应为非负安全整数）');
  }
  const buf = Buffer.from(member.data, 'base64');
  if (buf.length !== member.size) {
    throw bad('的字节长度与 size 不符');
  }
  if (sha256Hex(buf).toLowerCase() !== member.sha256.toLowerCase()) {
    throw bad('的 SHA-256 与内容不符');
  }
  return buf;
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
  policySignature: policySigPath,
  policyKey: policyKeyPath,
  cosignatures: cosigDir,
  cosignerKeys,
  minCosigners,
  bundle: bundlePath,
}) {
  const bundleMode = bundlePath !== undefined;
  const artifactAbs = resolve(artifact);
  const keyAbs = resolve(pubKeyPath);
  const bundleAbs = bundleMode ? resolve(bundlePath) : null;
  const proofAbs = bundleMode ? null : resolve(proofPath);
  const sigAbs = bundleMode ? null : resolve(sigPath);

  // --sbom 与 --sbom-signature 必须成对出现；只给一者是用法错误。
  // 包模式自带 SBOM 与其签名成员，视为始终启用 SBOM 校验。
  let sbomMode = true;
  let sbomAbs = null;
  let sbomSigAbs = null;
  if (!bundleMode) {
    sbomMode = sbomPath !== undefined || sbomSigPath !== undefined;
    if (sbomMode && (sbomPath === undefined || sbomSigPath === undefined)) {
      throw new ProvError(ERROR_CODES.USAGE_ERROR, '--sbom 与 --sbom-signature 必须成对提供');
    }
    sbomAbs = sbomMode ? resolve(sbomPath) : null;
    sbomSigAbs = sbomMode ? resolve(sbomSigPath) : null;
  }

  // 共签校验参数必须成套：独立文件模式为 --cosignatures、--cosigner-key（可重复）、
  // --min-cosigners 三者；包模式清单位于包内，只需后两者。
  const cosignMode =
    cosigDir !== undefined || cosignerKeys !== undefined || minCosigners !== undefined;
  if (cosignMode) {
    const pairOk = cosignerKeys !== undefined && minCosigners !== undefined;
    const sourceOk = bundleMode || cosigDir !== undefined;
    if (!pairOk || !sourceOk) {
      throw new ProvError(
        ERROR_CODES.USAGE_ERROR,
        bundleMode
          ? '--cosigner-key 与 --min-cosigners 必须同时提供'
          : '--cosignatures、--cosigner-key 与 --min-cosigners 必须同时提供',
      );
    }
  }
  const cosignerKeyList = cosignMode
    ? (Array.isArray(cosignerKeys) ? cosignerKeys : [cosignerKeys])
    : [];

  // 策略签名：--policy-signature 与 --policy-key 必须同时给且必须与 --policy 同时给
  // （缺一/无 --policy 由 CLI 层判为 USAGE_ERROR；库入口同样拒绝不完整参数）。
  const policySignMode = policySigPath !== undefined || policyKeyPath !== undefined;
  if (policySignMode && (policySigPath === undefined || policyKeyPath === undefined || policyPath === undefined)) {
    throw new ProvError(
      ERROR_CODES.USAGE_ERROR,
      '--policy-signature 与 --policy-key 必须与 --policy 同时提供',
    );
  }
  const policySigAbs = policySignMode ? resolve(policySigPath) : null;
  const policyKeyAbs = policySignMode ? resolve(policyKeyPath) : null;

  // 1) 所有输入必须存在且可读。
  const inputs = [[artifactAbs, '产物']];
  if (bundleMode) {
    inputs.push([bundleAbs, '证明分发包']);
  } else {
    inputs.push([proofAbs, '证明文件'], [sigAbs, '签名文件']);
  }
  inputs.push([keyAbs, '公钥']);
  if (!bundleMode && sbomMode) {
    inputs.push([sbomAbs, 'SBOM 文件'], [sbomSigAbs, 'SBOM 签名文件']);
  }
  // 策略、策略签名与策略公钥在最后的策略阶段才读取（与既有“篡改优先于策略”一致），
  // 不加入此处的早期输入检查。
  for (const [p, label] of inputs) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      throw wrapFsError(err, `读取${label}`);
    }
  }

  // 2) 公钥必须可解析且为 Ed25519 —— 错误/不支持的公钥归 KEY_NOT_FOUND。
  const publicKey = readPublicKey(keyAbs);

  // 3) 证明来源：包模式先解析并校验分发包结构，再取出各成员原始字节；
  //    独立文件模式直接读取对应文件。
  let bundleMembers = null;
  let hasCosignMembers = false;
  let proofText;
  let sigText;
  let sbomText = null;
  let sbomSigText = null;
  if (bundleMode) {
    const bundleText = await readFileUtf8(bundleAbs);
    const parsed = parseBundle(bundleText);
    bundleMembers = parsed.members;
    hasCosignMembers = parsed.hasCosignMembers;
    proofText = bundleMembers.get('proof').toString('utf8');
    sigText = bundleMembers.get('proof-signature').toString('utf8');
    sbomText = bundleMembers.get('sbom').toString('utf8');
    sbomSigText = bundleMembers.get('sbom-signature').toString('utf8');
  } else {
    try {
      proofText = await readFileUtf8(proofAbs);
    } catch (err) {
      throw wrapFsError(err, '读取证明文件');
    }
  }
  // 证明文件必须是可解析的 JSON 且结构合法 —— 否则 PROOF_INVALID。
  let proof;
  try {
    proof = JSON.parse(proofText);
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明文件不是合法的 JSON');
  }
  const proofError = validateProof(proof);
  if (proofError) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, proofError);
  }

  // 包模式：共签成员与证明声明必须一致 —— 声明了共签者而缺少共签成员，
  // 或未声明却携带共签成员，均为成员缺失/多余（PROOF_INVALID）。
  if (bundleMode) {
    const declared = proof.cosignerKeyFingerprints !== undefined;
    if (declared && !hasCosignMembers) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明声明了共签者，但分发包缺少共签成员');
    }
    if (!declared && hasCosignMembers) {
      throw new ProvError(ERROR_CODES.PROOF_INVALID, '证明未声明共签者，但分发包含有共签成员');
    }
  }

  // 4) 签名必须是合法 Base64 且长度符合 Ed25519（64 字节）—— 否则 PROOF_INVALID。
  if (!bundleMode) {
    sigText = await readFileUtf8(sigAbs);
  }
  const sigB64 = sigText.replace(/\s+/g, '');
  let sigBuf;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sigB64) || sigB64.length === 0) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '签名文件不是合法的 Base64 内容');
  }
  try {
    sigBuf = Buffer.from(sigB64, 'base64');
  } catch {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, '签名文件无法解码为字节');
  }
  if (sigBuf.length !== 64) {
    throw new ProvError(
      ERROR_CODES.PROOF_INVALID,
      `签名长度非法（Ed25519 应为 64 字节，实际 ${sigBuf.length} 字节）`,
    );
  }

  // 5) 重算证明的规范字节并验签。
  //    以磁盘上的 proof.json 原样为真，重新序列化其解析结果用于验签；
  //    generate 写出的即为稳定规范形式，因此往返一致。
  //
  //    错误归类（三者互不相同）：
  //      - 提供的公钥与证明中记录的签钥指纹不一致  -> KEY_NOT_FOUND（错误公钥）
  //      - 公钥一致但签名验证失败                  -> SIGNATURE_INVALID（签名内容不匹配）
  //      - 签名文件本身格式非法（前面）            -> PROOF_INVALID
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
  //    排除输出目录：证明/签名/清单（或分发包）通常与产物相邻，验证时不得把它们计入产物。
  const excludeDir = inferExcludeDir(bundleMode ? bundleAbs : proofAbs, artifactAbs);
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

  // 7) SBOM 校验：结构、proof.sbomDigest、SBOM 签名，
  //    并确认 SBOM 清单与证明清单（进而与当前扫描）逐项一致。
  //    包模式始终执行（成员来自分发包）；独立文件模式仅在成对提供时执行。
  let sbomDigest;
  if (sbomMode) {
    if (!bundleMode) {
      sbomText = await readFileUtf8(sbomAbs);
      sbomSigText = await readFileUtf8(sbomSigAbs);
    }
    sbomDigest = await verifySbom({ sbomText, sbomSigText, proof, publicKey });
  }

  // 8) 共签模式：在证明、可选 SBOM 与产物完整性全部通过后，校验共签清单与各共签签名。
  let cosignerCount;
  if (cosignMode) {
    let proofManifestText;
    let sbomManifestText;
    if (bundleMode) {
      if (!hasCosignMembers) {
        throw new ProvError(
          ERROR_CODES.PROOF_INVALID,
          '分发包缺少共签成员（proof-cosignatures / sbom-cosignatures）',
        );
      }
      proofManifestText = bundleMembers.get('proof-cosignatures').toString('utf8');
      sbomManifestText = bundleMembers.get('sbom-cosignatures').toString('utf8');
    }
    cosignerCount = await verifyCosignatures({
      cosigDir,
      proofManifestText,
      sbomManifestText,
      cosignerKeyPaths: cosignerKeyList,
      minCosigners,
      proof,
      canonicalProof,
      currentSbom,
    });
  }

  // 9) 可选策略：仅在签名、完整性、可选 SBOM、可选共签校验全部通过后加载并执行。
  //    启用策略签名时先验签再评估规则：
  //      策略/签名/公钥缺失 -> INPUT_NOT_FOUND；不可读 -> PERMISSION_DENIED；
  //      策略 JSON、未知字段、取值或 policyVersion 非法 -> POLICY_INVALID；
  //      公钥无法解析或非 Ed25519 -> KEY_NOT_FOUND；
  //      策略合法但签名 Base64、长度、内容或公钥不符 -> SIGNATURE_INVALID；
  //      规则不满足 -> POLICY_VIOLATION。
  let policyStatus;
  let policySignerFingerprint;
  if (policyPath !== undefined) {
    const policy = await loadPolicy(policyPath);
    if (policySignMode) {
      policySignerFingerprint = await verifyPolicySignature({
        policy,
        sigAbs: policySigAbs,
        keyAbs: policyKeyAbs,
      });
    }
    const violations = evaluatePolicy(policy, proof, sbomMode);
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
  if (sbomMode) result.sbomDigest = sbomDigest;
  if (cosignMode) result.cosignerCount = cosignerCount;
  if (policyPath !== undefined) {
    result.policyStatus = policyStatus;
    if (policySignMode) result.policySignerFingerprint = policySignerFingerprint;
  }
  return result;
}

// 策略签名校验：在策略结构校验通过后调用。
// 顺序：签名文件与公钥均须存在且可读（INPUT_NOT_FOUND / PERMISSION_DENIED）->
// 公钥可解析且为 Ed25519（KEY_NOT_FOUND）-> 签名为合法 Base64 且 64 字节 ->
// 对策略规范字节验签（内容、签名或公钥不符均为 SIGNATURE_INVALID）。
// 返回策略签名公钥的指纹。
async function verifyPolicySignature({ policy, sigAbs, keyAbs }) {
  for (const [p, label] of [
    [sigAbs, '策略签名文件'],
    [keyAbs, '策略公钥'],
  ]) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      throw wrapFsError(err, `读取${label}`);
    }
  }
  const policyPublicKey = readPublicKey(keyAbs);
  const fingerprint = keyFingerprint(policyPublicKey);

  let sigText;
  try {
    sigText = await readFileUtf8(sigAbs);
  } catch (err) {
    throw wrapFsError(err, '读取策略签名文件');
  }
  const sigB64 = sigText.replace(/\s+/g, '');
  let sigBuf;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sigB64) || sigB64.length === 0) {
    throw new ProvError(ERROR_CODES.SIGNATURE_INVALID, '策略签名文件不是合法的 Base64 内容');
  }
  try {
    sigBuf = Buffer.from(sigB64, 'base64');
  } catch {
    throw new ProvError(ERROR_CODES.SIGNATURE_INVALID, '策略签名文件无法解码为字节');
  }
  if (sigBuf.length !== 64) {
    throw new ProvError(
      ERROR_CODES.SIGNATURE_INVALID,
      `策略签名长度非法（Ed25519 应为 64 字节，实际 ${sigBuf.length} 字节）`,
    );
  }

  // 签名输入与 policy-sign 完全一致：稳定 JSON（键名排序、两空格缩进）加末尾换行。
  const canonicalBytes = Buffer.from(stableJsonStringify(policy) + '\n', 'utf8');
  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, canonicalBytes, policyPublicKey, sigBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    throw new ProvError(
      ERROR_CODES.SIGNATURE_INVALID,
      '策略签名与策略内容不匹配（策略可能被改动，或签名/公钥不符）',
    );
  }
  return fingerprint;
}

// SBOM 校验：结构 -> 摘要 -> 签名 -> 清单一致性。
// sbomText / sbomSigText 为 SBOM 与其签名文件的原始文本（独立文件或分发包成员）。
async function verifySbom({ sbomText, sbomSigText, proof, publicKey }) {
  // a) sbom.json 必须是可解析的 JSON 且结构合法 —— 否则 PROOF_INVALID。
  let sbom;
  try {
    sbom = JSON.parse(sbomText);
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
  const sigB64 = sbomSigText.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sigB64) || sigB64.length === 0) {
    throw new ProvError(ERROR_CODES.PROOF_INVALID, 'SBOM 签名文件不是合法的 Base64 内容');
  }
  const sigBuf = Buffer.from(sigB64, 'base64');
  if (sigBuf.length !== 64) {
    throw new ProvError(
      ERROR_CODES.PROOF_INVALID,
      `SBOM 签名长度非法（Ed25519 应为 64 字节，实际 ${sigBuf.length} 字节）`,
    );
  }
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

// ---------------------------------------------------------------------------
// 共签校验（proof.cosignatures.json / sbom.cosignatures.json）
// ---------------------------------------------------------------------------

// 在证明、可选 SBOM 与产物完整性全部通过后调用。
// 校验顺序：清单可读性 -> 结构与绑定（PROOF_INVALID）-> SBOM 摘要复算
// （INTEGRITY_MISMATCH）-> 共签公钥归属（KEY_NOT_FOUND）-> 逐签名验签与
// 有效数量（SIGNATURE_INVALID）。返回有效共签者数量（按指纹去重）。
async function verifyCosignatures({ cosigDir, proofManifestText, sbomManifestText, cosignerKeyPaths, minCosigners, proof, canonicalProof, currentSbom }) {
  let proofManifest;
  let sbomManifest;
  if (proofManifestText !== undefined) {
    // 包模式：清单字节来自分发包成员，无需访问文件系统。
    proofManifest = parseCosignManifest(proofManifestText, '证明共签清单');
    sbomManifest = parseCosignManifest(sbomManifestText, 'SBOM 共签清单');
  } else {
    const dir = resolve(cosigDir);
    const proofManifestAbs = join(dir, 'proof.cosignatures.json');
    const sbomManifestAbs = join(dir, 'sbom.cosignatures.json');
    for (const [p, label] of [
      [proofManifestAbs, '证明共签清单'],
      [sbomManifestAbs, 'SBOM 共签清单'],
    ]) {
      try {
        await access(p, fsConstants.R_OK);
      } catch (err) {
        throw wrapFsError(err, `读取${label}`);
      }
    }
    proofManifest = parseCosignManifest(await readFileUtf8(proofManifestAbs), '证明共签清单');
    sbomManifest = parseCosignManifest(await readFileUtf8(sbomManifestAbs), 'SBOM 共签清单');
  }

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

function parseCosignManifest(text, label) {
  let manifest;
  try {
    manifest = JSON.parse(text);
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
// 1.1 起支持发布准入的文件级约束（requiredFiles / forbiddenFiles）。
export const POLICY_VERSION_FILE_RULES = '1.1';
export const POLICY_VERSIONS = Object.freeze([POLICY_VERSION, POLICY_VERSION_FILE_RULES]);

// 文件级策略路径合法性：键/值必须为非空字符串，使用正斜杠的相对路径，
// 不得为绝对路径、含反斜杠、空路径段或以点目录（. / ..）作为路径段。
// 路径按清单的 Unicode 原样精确匹配（大小写敏感），不做归一化。
function isValidPolicyRelPath(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (value.includes('\\')) return false;
  if (value.startsWith('/')) return false;
  const segments = value.split('/');
  if (segments.some((seg) => seg.length === 0)) return false;
  if (segments.includes('.') || segments.includes('..')) return false;
  return true;
}

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
  const error = validatePolicyObject(policy);
  if (error) throw new ProvError(ERROR_CODES.POLICY_INVALID, error);
  return policy;
}

// 策略对象的严格结构校验：返回错误说明字符串，合法时返回 null。
// 非对象、未知字段、非法类型或取值、policyVersion 非 "1.0"/"1.1"、时间区间倒置、
// 文件级路径/摘要非法、forbiddenFiles 重复或与 requiredFiles 重叠均为非法。
function validatePolicyObject(policy) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    return '策略顶层必须是 JSON 对象';
  }

  const allowed = new Set([
    'policyVersion',
    'proofNotBefore',
    'proofNotAfter',
    'allowedKeyFingerprints',
    'requireSbom',
    'maxFileCount',
    'maxSize',
    // 1.1 文件级发布准入规则。
    'requiredFiles',
    'forbiddenFiles',
  ]);
  for (const key of Object.keys(policy)) {
    if (!allowed.has(key)) {
      return `策略包含未知字段: ${key}`;
    }
  }

  // policyVersion 必填，字符串且仅接受 "1.0" 与 "1.1"。
  if (policy.policyVersion === undefined) {
    return '策略缺少必填字段: policyVersion';
  }
  if (typeof policy.policyVersion !== 'string') {
    return '策略字段类型非法: policyVersion';
  }
  if (!POLICY_VERSIONS.includes(policy.policyVersion)) {
    return `不支持的策略版本: ${policy.policyVersion}`;
  }
  const isV11 = policy.policyVersion === POLICY_VERSION_FILE_RULES;

  // 文件级字段仅允许出现在 1.1：1.0 携带任一即视为非法字段。
  if (!isV11 && (policy.requiredFiles !== undefined || policy.forbiddenFiles !== undefined)) {
    return '策略 1.0 不支持字段: requiredFiles / forbiddenFiles（需要 policyVersion 1.1）';
  }

  // 时间字段可选；出现时必须是合法 UTC ISO-8601 字符串。
  for (const k of ['proofNotBefore', 'proofNotAfter']) {
    if (policy[k] !== undefined && parseUtcIso(policy[k]) === null) {
      return `策略字段取值非法: ${k}`;
    }
  }

  // 指纹白名单可选；缺省不约束，显式给出时必须为非空 SHA-256 十六进制数组。
  if (policy.allowedKeyFingerprints !== undefined) {
    if (!Array.isArray(policy.allowedKeyFingerprints)) {
      return '策略字段类型非法: allowedKeyFingerprints';
    }
    if (policy.allowedKeyFingerprints.length === 0) {
      return '策略字段 allowedKeyFingerprints 不允许为空数组';
    }
    for (const fp of policy.allowedKeyFingerprints) {
      if (typeof fp !== 'string' || !/^[0-9a-f]{64}$/i.test(fp)) {
        return '策略字段 allowedKeyFingerprints 中存在非法的 SHA-256 十六进制指纹';
      }
    }
  }

  if (policy.requireSbom !== undefined && typeof policy.requireSbom !== 'boolean') {
    return '策略字段类型非法: requireSbom';
  }
  for (const k of ['maxFileCount', 'maxSize']) {
    if (policy[k] !== undefined && !isNonNegSafeInt(policy[k])) {
      return `策略字段取值非法: ${k}`;
    }
  }

  // 时间区间不得倒置；相等（闭区间单点）允许。
  if (policy.proofNotBefore !== undefined && policy.proofNotAfter !== undefined) {
    if (parseUtcIso(policy.proofNotBefore) > parseUtcIso(policy.proofNotAfter)) {
      return '策略时间区间非法：proofNotBefore 晚于 proofNotAfter';
    }
  }

  // 1.1 文件级发布准入规则。
  if (isV11) {
    const fileRuleError = validateFileRules(policy);
    if (fileRuleError) return fileRuleError;
  }

  return null;
}

// requiredFiles：非空对象，键为清单正斜杠相对路径，值为 64 位**小写**十六进制 SHA-256。
// forbiddenFiles：非空路径数组，路径合法且不得重复；两组路径不得重叠。
function validateFileRules(policy) {
  const requiredPaths = new Set();
  if (policy.requiredFiles !== undefined) {
    const req = policy.requiredFiles;
    if (req === null || typeof req !== 'object' || Array.isArray(req)) {
      return '策略字段类型非法: requiredFiles';
    }
    if (Object.keys(req).length === 0) {
      return '策略字段 requiredFiles 不允许为空对象';
    }
    for (const [path, digest] of Object.entries(req)) {
      if (!isValidPolicyRelPath(path)) {
        return `策略字段 requiredFiles 路径非法: ${path}`;
      }
      if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
        return `策略字段 requiredFiles 摘要非法（应为 64 位小写十六进制 SHA-256）: ${path}`;
      }
      requiredPaths.add(path);
    }
  }

  if (policy.forbiddenFiles !== undefined) {
    if (!Array.isArray(policy.forbiddenFiles)) {
      return '策略字段类型非法: forbiddenFiles';
    }
    if (policy.forbiddenFiles.length === 0) {
      return '策略字段 forbiddenFiles 不允许为空数组';
    }
    const seen = new Set();
    for (const path of policy.forbiddenFiles) {
      if (!isValidPolicyRelPath(path)) {
        return `策略字段 forbiddenFiles 路径非法: ${path}`;
      }
      if (seen.has(path)) {
        return `策略字段 forbiddenFiles 路径重复: ${path}`;
      }
      seen.add(path);
      if (requiredPaths.has(path)) {
        return `策略文件约束重叠（同一路径不得同时出现在 requiredFiles 与 forbiddenFiles）: ${path}`;
      }
    }
  }

  return null;
}

// 在签名、完整性、可选 SBOM 校验全部通过后执行策略。
// 返回违规列表（已按时间、密钥、SBOM、文件数、大小、文件级规则排序）；空列表表示通过。
// 1.1 文件级规则内部依次为 required-file-missing、required-file-digest-mismatch、
// forbidden-file-present，同类按路径的 UTF-16 码元升序。每条违规形如 { rule, observed }。
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

  // 6) 1.1 文件级发布准入规则。至此完整性已通过，proof.files 与当前产物逐项一致，
  //    直接以清单（path -> sha256）为真做 Unicode 原样、大小写敏感的精确匹配。
  if (policy.requiredFiles !== undefined || policy.forbiddenFiles !== undefined) {
    const byPath = new Map(proof.files.map((f) => [f.path, f]));
    const requiredMissing = [];
    const requiredDigest = [];
    const forbiddenPresent = [];
    if (policy.requiredFiles !== undefined) {
      for (const [path, expectedDigest] of Object.entries(policy.requiredFiles)) {
        const entry = byPath.get(path);
        if (!entry) {
          requiredMissing.push(path);
        } else if (entry.sha256.toLowerCase() !== expectedDigest.toLowerCase()) {
          // observed 为清单中该路径的实际摘要（生成时写出的小写十六进制）。
          requiredDigest.push([path, entry.sha256]);
        }
      }
    }
    if (policy.forbiddenFiles !== undefined) {
      for (const path of policy.forbiddenFiles) {
        if (byPath.has(path)) forbiddenPresent.push(path);
      }
    }
    // 同类按路径 UTF-16 码元升序（JS 默认字符串比较）。
    const byUtf16 = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    requiredMissing.sort(byUtf16);
    requiredDigest.sort(([a], [b]) => byUtf16(a, b));
    forbiddenPresent.sort(byUtf16);
    for (const path of requiredMissing) push('required-file-missing', path);
    for (const [, actualDigest] of requiredDigest) {
      push('required-file-digest-mismatch', actualDigest);
    }
    for (const path of forbiddenPresent) push('forbidden-file-present', path);
  }

  return violations;
}

// ---------------------------------------------------------------------------
// gate：独立发布门禁（不依赖、不改变既有 keygen/generate/policy-sign/verify）
// ---------------------------------------------------------------------------
//
// 输入（均为本地公开文件，不读取任何私钥或凭证；验签公钥内嵌于证明）：
//   --artifact     产物路径（单个文件或目录，按与 generate/verify 相同的规则扫描）
//   --attestation 自包含签名证明（gate attestation），结构见 GATE_ATTESTATION_VERSION
//   --sbom         发布物料清单：文件级 SBOM（schemaVersion 1.0）加 components
//                  （每个组件含 name 与 license）
//   --policy       发布策略：非空 conditions 数组
//
// 处理顺序：读取并解析四类输入 -> 用证明内嵌公钥验证证明签名 -> 重扫产物并核对
// 证明中的产物摘要 -> 校验 SBOM 摘要并与证明、当前产物三方对账 -> 逐项评估策略
// 条件 -> 在 stdout 写出确定性 JSON 报告。成功（allowed/denied）不额外写任何文件。
//
// 错误可观察结果（唯一）：
//   InputError        退出 2：路径不存在/不可读、JSON 语法错误、缺少必需字段
//   PolicyError       退出 2：策略为空、含未知条件类型或条件取值不符合定义
//   VerificationError 退出 3：证明内嵌公钥非法、签名无效、证明中的产物摘要与实际
//                     产物不一致、证明或 SBOM 无法与产物建立对应关系
//   denied 报告       退出 4：证明有效但违反来源/身份/摘要/包名/许可证约束
//   allowed 报告      退出 0：全部条件通过

export const GATE_ATTESTATION_VERSION = '1.0';
export const GATE_SBOM_VERSION = '1.0';
export const GATE_POLICY_VERSION = '1.0';
export const GATE_REPORT_VERSION = '1.0';

export const GATE_ERROR_CODES = Object.freeze({
  INPUT: 'InputError',
  POLICY: 'PolicyError',
  VERIFICATION: 'VerificationError',
});

// 门禁策略条件类型（固定顺序即报告中 conditions 的输出顺序）。
export const GATE_CONDITION_TYPES = Object.freeze([
  'sourceReference',
  'signerIdentity',
  'artifactDigest',
  'allowedPackages',
  'allowedLicenses',
]);

class GateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'GateError';
    this.code = code;
  }
}

function gateInputError(message) {
  return new GateError(GATE_ERROR_CODES.INPUT, message);
}

function gatePolicyError(message) {
  return new GateError(GATE_ERROR_CODES.POLICY, message);
}

function gateVerificationError(message) {
  return new GateError(GATE_ERROR_CODES.VERIFICATION, message);
}

// 门禁输入读取：路径必须存在且可读（含符号链接安全的产物扫描），JSON 必须可解析。
// 路径层问题一律归 InputError。
async function gateReadInputs({ artifact, attestation, sbom, policy }) {
  const artifactAbs = resolve(artifact);
  const attestationAbs = resolve(attestation);
  const sbomAbs = resolve(sbom);
  const policyAbs = resolve(policy);
  for (const [p, label] of [
    [artifactAbs, '产物'],
    [attestationAbs, '证明文件'],
    [sbomAbs, '软件物料清单'],
    [policyAbs, '发布策略'],
  ]) {
    try {
      await access(p, fsConstants.R_OK);
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        throw gateInputError(`${label}路径不存在 (${p})`);
      }
      if (err && (err.code === 'EACCES' || err.code === 'EPERM')) {
        throw gateInputError(`${label}不可读（权限不足）: ${p}`);
      }
      throw gateInputError(`${label}无法读取: ${p}`);
    }
  }

  let attestationText;
  let sbomText;
  let policyText;
  try {
    [attestationText, sbomText, policyText] = await Promise.all([
      readFileUtf8(attestationAbs),
      readFileUtf8(sbomAbs),
      readFileUtf8(policyAbs),
    ]);
  } catch {
    throw gateInputError('输入文件无法读取');
  }

  const attestationParsed = parseGateJson(attestationText, '证明文件');
  const sbomParsed = parseGateJson(sbomText, '软件物料清单');
  const policyParsed = parseGateJson(policyText, '发布策略');

  return {
    artifactAbs,
    attestationAbs,
    sbomAbs,
    policyAbs,
    attestation: attestationParsed,
    sbom: sbomParsed,
    policy: policyParsed,
  };
}

function parseGateJson(text, label) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw gateInputError(`${label}不是合法的 JSON（语法错误）`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw gateInputError(`${label}顶层必须是 JSON 对象`);
  }
  return value;
}

function isSha256Hex(v) {
  return typeof v === 'string' && /^[0-9a-f]{64}$/i.test(v);
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

// 证明结构校验：缺少必需字段或字段类型非法均为 InputError。
function validateGateAttestation(attestation) {
  if (attestation.attestationVersion !== GATE_ATTESTATION_VERSION) {
    throw gateInputError(
      `证明缺少或不支持 attestationVersion（应为 "${GATE_ATTESTATION_VERSION}"）`,
    );
  }
  for (const k of ['subject', 'source', 'signer']) {
    if (attestation[k] === null || typeof attestation[k] !== 'object' || Array.isArray(attestation[k])) {
      throw gateInputError(`证明缺少必需字段或类型非法: ${k}`);
    }
  }
  const subject = attestation.subject;
  if (!isSha256Hex(subject.artifactDigest)) {
    throw gateInputError('证明 subject.artifactDigest 缺失或不是合法的 SHA-256 十六进制摘要');
  }
  if (!isSha256Hex(subject.sbomDigest)) {
    throw gateInputError('证明 subject.sbomDigest 缺失或不是合法的 SHA-256 十六进制摘要');
  }
  if (!isNonEmptyString(subject.artifactName)) {
    throw gateInputError('证明 subject.artifactName 缺失或不是非空字符串');
  }
  if (!isNonEmptyString(attestation.source.repository)) {
    throw gateInputError('证明 source.repository 缺失或不是非空字符串');
  }
  if (!isNonEmptyString(attestation.source.reference)) {
    throw gateInputError('证明 source.reference 缺失或不是非空字符串');
  }
  if (!isNonEmptyString(attestation.signer.issuer)) {
    throw gateInputError('证明 signer.issuer 缺失或不是非空字符串');
  }
  if (!isNonEmptyString(attestation.signer.subject)) {
    throw gateInputError('证明 signer.subject 缺失或不是非空字符串');
  }
  for (const k of ['signature', 'publicKey']) {
    if (!isNonEmptyString(attestation[k])) {
      throw gateInputError(`证明缺少必需字段或类型非法: ${k}`);
    }
  }
  if (attestation.claims !== null && typeof attestation.claims === 'object' && !Array.isArray(attestation.claims)) {
    // claims 为可选的附加声明，不参与门禁判定；存在时仅要求为对象。
  } else if (attestation.claims !== undefined) {
    throw gateInputError('证明字段 claims 类型非法（应为 JSON 对象）');
  }
}

// 发布物料清单结构校验：沿用既有文件级 SBOM 规则，另要求非空 components
// （每项含非空 name 与 license；id/version 可选）。
function validateGateSbom(sbom) {
  const sbomError = validateSbom(sbom);
  if (sbomError) throw gateInputError(`软件物料清单${sbomError}`);
  if (sbom.schemaVersion !== GATE_SBOM_VERSION) {
    throw gateInputError(
      `软件物料清单 schemaVersion 缺失或不受支持（应为 "${GATE_SBOM_VERSION}"）`,
    );
  }
  if (!Array.isArray(sbom.components)) {
    throw gateInputError('软件物料清单缺少必需字段或类型非法: components');
  }
  const seen = new Set();
  for (let i = 0; i < sbom.components.length; i += 1) {
    const c = sbom.components[i];
    if (c === null || typeof c !== 'object' || Array.isArray(c)) {
      throw gateInputError(`软件物料清单 components[${i}] 必须是对象`);
    }
    if (!isNonEmptyString(c.name)) {
      throw gateInputError(`软件物料清单 components[${i}].name 缺失或不是非空字符串`);
    }
    if (!isNonEmptyString(c.license)) {
      throw gateInputError(`软件物料清单 components[${i}].license 缺失或不是非空字符串`);
    }
    const dedupKey = `${c.name}\u0000${c.license}`;
    if (seen.has(dedupKey)) {
      throw gateInputError(`软件物料清单 components 存在重复的 name+license 条目: ${c.name}`);
    }
    seen.add(dedupKey);
  }
}

// 策略结构校验：policyVersion 固定；conditions 必须为非空数组，每个条件为对象且
// 含受支持的 type，取值符合该条件定义。任何不符均为 PolicyError。
function validateGatePolicy(policy) {
  for (const key of Object.keys(policy)) {
    if (key !== 'policyVersion' && key !== 'conditions') {
      throw gatePolicyError(`发布策略包含无法识别的顶层字段: ${key}`);
    }
  }
  if (policy.policyVersion !== GATE_POLICY_VERSION) {
    throw gatePolicyError(
      `发布策略缺少或不支持 policyVersion（应为 "${GATE_POLICY_VERSION}"）`,
    );
  }
  if (!Array.isArray(policy.conditions)) {
    throw gatePolicyError('发布策略必须包含非空 conditions 数组');
  }
  if (policy.conditions.length === 0) {
    throw gatePolicyError('发布策略不能为空策略（conditions 至少包含一个条件）');
  }
  for (let i = 0; i < policy.conditions.length; i += 1) {
    const cond = policy.conditions[i];
    if (cond === null || typeof cond !== 'object' || Array.isArray(cond)) {
      throw gatePolicyError(`conditions[${i}] 必须是对象`);
    }
    if (!GATE_CONDITION_TYPES.includes(cond.type)) {
      throw gatePolicyError(
        `conditions[${i}] 包含无法识别的条件类型: ${JSON.stringify(cond.type)}`,
      );
    }
    validateGateCondition(cond, i);
  }
}

// 单个条件取值校验；各类型允许的键严格限定，多余键同样视为取值不符。
function validateGateCondition(cond, i) {
  const where = `conditions[${i}]（${cond.type}）`;
  const fail = (msg) => gatePolicyError(`${where} ${msg}`);
  const expectStringArray = (key, { nonEmpty = true } = {}) => {
    if (!Array.isArray(cond[key])) throw fail(`字段 ${key} 必须是字符串数组`);
    if (nonEmpty && cond[key].length === 0) throw fail(`字段 ${key} 不允许为空数组`);
    const seen = new Set();
    for (const v of cond[key]) {
      if (!isNonEmptyString(v)) throw fail(`字段 ${key} 的每一项必须是非空字符串`);
      if (seen.has(v)) throw fail(`字段 ${key} 存在重复取值: ${v}`);
      seen.add(v);
    }
  };
  switch (cond.type) {
    case 'sourceReference': {
      allowedKeys(cond, ['type', 'reference', 'anyOf'], fail);
      if (cond.reference === undefined && cond.anyOf === undefined) {
        throw fail('必须提供 reference 或 anyOf 之一');
      }
      if (cond.reference !== undefined && cond.anyOf !== undefined) {
        throw fail('reference 与 anyOf 互斥，只能提供其一');
      }
      if (cond.reference !== undefined) {
        if (!isNonEmptyString(cond.reference)) throw fail('字段 reference 必须是非空字符串');
      } else {
        expectStringArray('anyOf');
      }
      break;
    }
    case 'signerIdentity': {
      allowedKeys(cond, ['type', 'issuer', 'subject', 'anyOf'], fail);
      if (cond.anyOf !== undefined) {
        if (cond.issuer !== undefined || cond.subject !== undefined) {
          throw fail('anyOf 与 issuer/subject 互斥，只能提供其一');
        }
        if (!Array.isArray(cond.anyOf) || cond.anyOf.length === 0) {
          throw fail('字段 anyOf 必须是非空对象数组');
        }
        const seen = new Set();
        for (let j = 0; j < cond.anyOf.length; j += 1) {
          const id = cond.anyOf[j];
          if (id === null || typeof id !== 'object' || Array.isArray(id)) {
            throw fail(`anyOf[${j}] 必须是对象`);
          }
          if (!isNonEmptyString(id.issuer) || !isNonEmptyString(id.subject)) {
            throw fail(`anyOf[${j}] 必须同时含非空字符串 issuer 与 subject`);
          }
          const key = `${id.issuer}\u0000${id.subject}`;
          if (seen.has(key)) throw fail('anyOf 存在重复的 issuer+subject 条目');
          seen.add(key);
        }
      } else {
        if (!isNonEmptyString(cond.issuer)) throw fail('字段 issuer 必须是非空字符串');
        if (!isNonEmptyString(cond.subject)) throw fail('字段 subject 必须是非空字符串');
      }
      break;
    }
    case 'artifactDigest': {
      allowedKeys(cond, ['type', 'sha256'], fail);
      if (!isSha256Hex(cond.sha256)) {
        throw fail('字段 sha256 必须是 64 位十六进制 SHA-256 摘要');
      }
      break;
    }
    case 'allowedPackages': {
      allowedKeys(cond, ['type', 'packages'], fail);
      expectStringArray('packages');
      break;
    }
    case 'allowedLicenses': {
      allowedKeys(cond, ['type', 'licenses'], fail);
      expectStringArray('licenses');
      break;
    }
    default:
      throw fail('条件类型不受支持');
  }
}

function allowedKeys(cond, allowed, fail) {
  for (const key of Object.keys(cond)) {
    if (!allowed.includes(key)) throw fail(`包含无法识别的字段: ${key}`);
  }
}

// 证明签名验证：内嵌 SPKI PEM 公钥必须可解析且为 Ed25519；signature 必须是
// 合法 Base64 且长度为 64 字节；对证明载荷的规范字节验签。任一失败均为
// VerificationError（公钥是证明的组成部分，非法公钥等同证明不可信）。
function verifyGateAttestationSignature(attestation) {
  let publicKey;
  try {
    publicKey = createPublicKey({ key: attestation.publicKey, format: 'pem' });
  } catch {
    throw gateVerificationError('证明内嵌公钥无法解析或格式不受支持');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw gateVerificationError(
      `证明内嵌公钥类型不是 Ed25519（实际为 ${publicKey.asymmetricKeyType}）`,
    );
  }
  const sigB64 = attestation.signature.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sigB64) || sigB64.length === 0) {
    throw gateVerificationError('证明签名不是合法的 Base64 内容');
  }
  const sigBuf = Buffer.from(sigB64, 'base64');
  if (sigBuf.length !== 64) {
    throw gateVerificationError(
      `证明签名长度非法（Ed25519 应为 64 字节，实际 ${sigBuf.length} 字节）`,
    );
  }
  // 签名输入为去掉 signature/publicKey 后证明载荷的规范字节（与出具方约定一致）。
  const payload = { ...attestation };
  delete payload.signature;
  delete payload.publicKey;
  const canonical = stableJsonStringify(payload);
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.from(canonical, 'utf8'), publicKey, sigBuf);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw gateVerificationError('证明签名无效（证明内容可能被改动，或签名已损坏）');
  }
  return {
    signerKeyFingerprint: keyFingerprint(publicKey),
  };
}

// 证明 -> 产物 -> SBOM 三方对账。任一步无法建立对应关系均为 VerificationError。
// 返回经核实的 { artifactDigest, sbomDigest, packageCount, fileCount }。
async function verifyGateCorrespondence({ artifactAbs, attestation, sbom }) {
  // 1) 重扫产物并与证明中的产物摘要比对（与 verify 相同的排除与扫描规则）。
  const currentSbom = await buildSbom(artifactAbs, null).catch((err) => {
    if (err instanceof ProvError && err.code === ERROR_CODES.SYMLINK_INVALID) {
      throw gateVerificationError(`产物扫描失败：${err.message}`);
    }
    throw gateInputError(err && err.message ? err.message : '产物无法读取');
  });
  const currentDigest = computeArtifactDigest(currentSbom);
  if (currentDigest.toLowerCase() !== attestation.subject.artifactDigest.toLowerCase()) {
    throw gateVerificationError('证明中的产物摘要与实际产物不一致（产物可能已被改动）');
  }

  // 2) SBOM 文件清单必须与当前产物逐项一致（借此把 SBOM 绑定到产物）。
  const fileMismatches = diffSbomAgainstProof(
    sbom,
    { artifactName: attestation.subject.artifactName, files: currentSbom.files },
  );
  if (fileMismatches.length > 0) {
    throw gateVerificationError(
      `软件物料清单无法与产物建立对应关系（存在 ${fileMismatches.length} 处清单差异）`,
    );
  }

  // 3) SBOM 摘要必须与证明记录一致（证明与 SBOM 相互绑定）。
  const sbomDigest = sha256Hex(stableJsonStringify(sbom));
  if (sbomDigest.toLowerCase() !== attestation.subject.sbomDigest.toLowerCase()) {
    throw gateVerificationError('软件物料清单摘要与证明记录的 sbomDigest 不一致（清单可能被替换）');
  }

  return {
    artifactDigest: currentDigest,
    sbomDigest,
    fileCount: currentSbom.files.length,
    packageCount: sbom.components.length,
  };
}

// 逐项评估策略条件。返回与 conditions 同序的结果数组；每个条件至多产生一条结果。
function evaluateGateConditions({ policy, attestation, sbom, observed }) {
  const results = [];
  for (const cond of policy.conditions) {
    results.push(evaluateGateCondition(cond, attestation, sbom, observed));
  }
  return results;
}

function evaluateGateCondition(cond, attestation, sbom, observed) {
  const base = { condition: cond.type };
  switch (cond.type) {
    case 'sourceReference': {
      const actual = attestation.source.reference;
      let expected;
      let pass;
      if (cond.reference !== undefined) {
        expected = cond.reference;
        pass = cond.reference === actual;
      } else {
        expected = cond.anyOf;
        pass = cond.anyOf.includes(actual);
      }
      return {
        ...base,
        expected,
        observed: actual,
        result: pass ? 'pass' : 'denied',
      };
    }
    case 'signerIdentity': {
      const actual = { issuer: attestation.signer.issuer, subject: attestation.signer.subject };
      let pass;
      let expected;
      if (cond.anyOf !== undefined) {
        expected = cond.anyOf;
        pass = cond.anyOf.some((id) => id.issuer === actual.issuer && id.subject === actual.subject);
      } else {
        expected = { issuer: cond.issuer, subject: cond.subject };
        pass = cond.issuer === actual.issuer && cond.subject === actual.subject;
      }
      return { ...base, expected, observed: actual, result: pass ? 'pass' : 'denied' };
    }
    case 'artifactDigest': {
      const actual = observed.artifactDigest;
      return {
        ...base,
        expected: cond.sha256.toLowerCase(),
        observed: actual,
        result: actual === cond.sha256.toLowerCase() ? 'pass' : 'denied',
      };
    }
    case 'allowedPackages': {
      const allowed = new Set(cond.packages);
      const actual = sbom.components.map((c) => c.name).sort(compareUtf16);
      const disallowed = actual.filter((name) => !allowed.has(name));
      return {
        ...base,
        expected: [...cond.packages].sort(compareUtf16),
        observed: { packageCount: actual.length, disallowedPackages: disallowed },
        result: disallowed.length === 0 ? 'pass' : 'denied',
      };
    }
    case 'allowedLicenses': {
      const allowed = new Set(cond.licenses);
      // 观测值为各包实际许可证：name -> license，按包名排序，确定性输出。
      const observedLicenses = {};
      for (const c of [...sbom.components].sort((a, b) => compareUtf16(a.name, b.name))) {
        observedLicenses[c.name] = c.license;
      }
      const disallowed = [...new Set(
        sbom.components.filter((c) => !allowed.has(c.license)).map((c) => c.license),
      )].sort(compareUtf16);
      return {
        ...base,
        expected: [...cond.licenses].sort(compareUtf16),
        observed: { licenses: observedLicenses, disallowedLicenses: disallowed },
        result: disallowed.length === 0 ? 'pass' : 'denied',
      };
    }
    default:
      // 结构校验阶段已拒绝未知类型，此处不可达。
      throw gatePolicyError(`无法识别的条件类型: ${cond.type}`);
  }
}

function compareUtf16(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// 报告经 stableJsonStringify 输出（与本工具其他 JSON 一致：UTF-8、两空格缩进、
// 键名固定按字典序），末尾换行；同一组输入字节下报告逐字节确定
// （无时间戳、无随机值、不额外落盘）。
function buildGateReport({ decision, conditions, observed, attestationAbs, sbomAbs, signer }) {
  const report = {
    reportVersion: GATE_REPORT_VERSION,
    status: decision,
    artifact: {
      digest: observed.artifactDigest,
    },
    attestation: {
      path: attestationAbs,
      source: {
        repository: observed.sourceRepository,
        reference: observed.sourceReference,
      },
      signer: {
        issuer: observed.signer.issuer,
        subject: observed.signer.subject,
        keyFingerprint: signer.signerKeyFingerprint,
      },
    },
    sbom: {
      path: sbomAbs,
      digest: observed.sbomDigest,
      fileCount: observed.fileCount,
      packageCount: observed.packageCount,
    },
    conditions,
  };
  return `${stableJsonStringify(report)}\n`;
}

// 门禁主入口：返回 { exitCode, reportText }；所有失败以 GateError 抛出。
export async function gate({ artifact, attestation, sbom, policy }) {
  // 1) 读取并解析四类输入（InputError）。
  const inputs = await gateReadInputs({ artifact, attestation, sbom, policy });

  // 2) 结构校验：证明/SBOM 缺字段为 InputError；策略问题为 PolicyError。
  //    先做输入结构检查，再做策略检查，使“策略为空/未知类型”稳定报 PolicyError。
  validateGateAttestation(inputs.attestation);
  validateGateSbom(inputs.sbom);
  validateGatePolicy(inputs.policy);

  // 3) 验证证明签名（VerificationError）。
  const signer = verifyGateAttestationSignature(inputs.attestation);

  // 4) 证明摘要 -> 实际产物、SBOM -> 产物、SBOM 摘要 -> 证明（VerificationError）。
  const verified = await verifyGateCorrespondence({
    artifactAbs: inputs.artifactAbs,
    attestation: inputs.attestation,
    sbom: inputs.sbom,
  });

  // 5) 逐项比对策略（约束违反不是系统错误，只决定 allowed/denied）。
  const observed = {
    ...verified,
    sourceRepository: inputs.attestation.source.repository,
    sourceReference: inputs.attestation.source.reference,
    signer: {
      issuer: inputs.attestation.signer.issuer,
      subject: inputs.attestation.signer.subject,
    },
  };
  const conditions = evaluateGateConditions({
    policy: inputs.policy,
    attestation: inputs.attestation,
    sbom: inputs.sbom,
    observed,
  });
  const decision = conditions.every((c) => c.result === 'pass') ? 'allowed' : 'denied';

  const reportText = buildGateReport({
    decision,
    conditions,
    observed,
    attestationAbs: inputs.attestationAbs,
    sbomAbs: inputs.sbomAbs,
    signer,
  });
  return {
    exitCode: decision === 'allowed' ? 0 : 4,
    status: decision,
    reportText,
  };
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
    '  provguard policy-sign --policy <policy.json> --key <private.pem> \\',
    '                      --signature <policy.json.sig>',
    '  provguard verify   --artifact <path> --proof <proof.json> \\',
    '                      --signature <proof.json.sig> --key <public.pem> \\',
    '                      [--sbom <sbom.json> --sbom-signature <sbom.json.sig>] \\',
    '                      [--cosignatures <dir> --cosigner-key <public.pem> ... \\',
    '                       --min-cosigners <n>] \\',
    '                      [--policy <policy.json>] \\',
    '                      [--policy-signature <policy.json.sig> --policy-key <public.pem>]',
    '  provguard verify   --artifact <path> --bundle <proof.bundle.json> \\',
    '                      --key <public.pem> \\',
    '                      [--cosigner-key <public.pem> ... --min-cosigners <n>] \\',
    '                      [--policy <policy.json>] \\',
    '                      [--policy-signature <policy.json.sig> --policy-key <public.pem>]',
    '  provguard gate     --artifact <path> --attestation <gate.attestation.json> \\',
    '                      --sbom <gate.sbom.json> --policy <gate.policy.json>',
    '',
    'generate 输出: proof.json / proof.json.sig / sbom.json / sbom.json.sig',
    '启用共签时额外输出: proof.cosignatures.json / sbom.cosignatures.json',
    '使用 --bundle 时额外输出: proof.bundle.json（单文件证明分发包）',
    'policy-sign 输出: policy.json.sig（策略的 Ed25519 签名，不改动策略与密钥）',
    'gate: 独立发布门禁；成功在 stdout 输出 allowed（退出 0）或 denied（退出 4）报告，',
    '      InputError/PolicyError 退出 2，VerificationError 退出 3，均写 stderr。',
    '其余命令成功状态: VERIFIED；错误码见 README。',
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
      // --bundle 为开关：出现时额外写出 proof.bundle.json，不接受取值。
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
      if (r.cosignerCount !== undefined) {
        out.cosignerCount = r.cosignerCount;
        out.proofCosignaturesPath = r.proofCosignaturesPath;
        out.sbomCosignaturesPath = r.sbomCosignaturesPath;
      }
      if (r.bundlePath !== undefined) {
        out.bundlePath = r.bundlePath;
      }
      process.stdout.write(`${stableJsonStringify(out)}\n`);
      return 0;
    }

    if (command === 'policy-sign') {
      const missing = ['policy', 'key', 'signature'].filter((k) => typeof args[k] !== 'string');
      if (missing.length) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          `缺少必填参数: ${missing.map((m) => `--${m}`).join(', ')}`,
        );
      }
      const r = await policySign({
        policy: args.policy,
        key: args.key,
        signature: args.signature,
      });
      process.stdout.write(
        `${stableJsonStringify({
          status: 'POLICY_SIGNED',
          policyPath: r.policyPath,
          signaturePath: r.signaturePath,
          policySignerFingerprint: r.policySignerFingerprint,
        })}\n`,
      );
      return 0;
    }

    if (command === 'verify') {
      // 包模式：--bundle 与独立文件入口（--proof/--signature/--sbom/
      // --sbom-signature/--cosignatures）互斥，混用为 USAGE_ERROR。
      const bundleMode = args.bundle !== undefined;
      if (bundleMode && typeof args.bundle !== 'string') {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--bundle 需要提供证明分发包路径');
      }
      if (bundleMode) {
        const conflicts = ['proof', 'signature', 'sbom', 'sbom-signature', 'cosignatures'].filter(
          (k) => args[k] !== undefined,
        );
        if (conflicts.length) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            `--bundle 与 ${conflicts.map((k) => `--${k}`).join('、')} 互斥`,
          );
        }
      }
      const required = bundleMode ? ['artifact', 'key'] : ['artifact', 'proof', 'signature', 'key'];
      const missing = required.filter((k) => typeof args[k] !== 'string');
      if (missing.length) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          `缺少必填参数: ${missing.map((m) => `--${m}`).join(', ')}`,
        );
      }
      // --policy 为可选单值参数；出现时必须带文件路径。
      const hasPolicy = args.policy !== undefined;
      if (hasPolicy && typeof args.policy !== 'string') {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--policy 需要提供策略文件路径');
      }
      // --policy-signature 与 --policy-key 必须成对出现，且必须与 --policy 同时提供；
      // 缺值（后无路径）或只给一者均为 USAGE_ERROR。
      const polSigRaw = args['policy-signature'];
      const polKeyRaw = args['policy-key'];
      const anyPolicySign = polSigRaw !== undefined || polKeyRaw !== undefined;
      if (anyPolicySign || hasPolicy) {
        if (anyPolicySign && !hasPolicy) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            '--policy-signature 与 --policy-key 必须与 --policy 同时提供',
          );
        }
      }
      if (anyPolicySign && (typeof polSigRaw !== 'string' || typeof polKeyRaw !== 'string')) {
        throw new ProvError(
          ERROR_CODES.USAGE_ERROR,
          '--policy-signature 与 --policy-key 必须同时提供且都需要文件路径',
        );
      }
      // --sbom 与 --sbom-signature 必须成对出现（仅独立文件模式；包模式自带 SBOM 成员）。
      const hasSbom = typeof args.sbom === 'string';
      const hasSbomSig = typeof args['sbom-signature'] === 'string';
      if (!bundleMode && hasSbom !== hasSbomSig) {
        throw new ProvError(ERROR_CODES.USAGE_ERROR, '--sbom 与 --sbom-signature 必须成对提供');
      }
      // 共签校验：独立文件模式需 --cosignatures + --cosigner-key（可重复）+ --min-cosigners；
      // 包模式清单位于包内，只需 --cosigner-key + --min-cosigners。min 为不超过公钥数量的正整数。
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
        const dirOk = bundleMode || typeof args.cosignatures === 'string';
        if (!dirOk || !keyListOk || !minOk) {
          throw new ProvError(
            ERROR_CODES.USAGE_ERROR,
            bundleMode
              ? '--cosigner-key（可重复）与 --min-cosigners（正整数）必须同时提供'
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
        if (!bundleMode) cosignOpts.cosignatures = args.cosignatures;
      }
      const r = await verify({
        artifact: args.artifact,
        key: args.key,
        ...(bundleMode
          ? { bundle: args.bundle }
          : {
              proof: args.proof,
              signature: args.signature,
              sbom: hasSbom ? args.sbom : undefined,
              sbomSignature: hasSbomSig ? args['sbom-signature'] : undefined,
            }),
        policy: hasPolicy ? args.policy : undefined,
        ...(anyPolicySign
          ? { policySignature: polSigRaw, policyKey: polKeyRaw }
          : {}),
        ...cosignOpts,
      });
      process.stdout.write(`${stableJsonStringify(r)}\n`);
      return 0;
    }

    if (command === 'gate') {
      // 门禁四要素均为必填；缺参按门禁输入问题处理（InputError，退出 2），
      // 不沿用既有 USAGE_ERROR/退出 1，保证门禁结果集仅为 0/2/3/4。
      const missing = ['artifact', 'attestation', 'sbom', 'policy'].filter(
        (k) => typeof args[k] !== 'string',
      );
      if (missing.length) {
        throw gateInputError(
          `缺少必填参数或参数值非法: ${missing.map((m) => `--${m}`).join(', ')}`,
        );
      }
      const r = await gate({
        artifact: args.artifact,
        attestation: args.attestation,
        sbom: args.sbom,
        policy: args.policy,
      });
      process.stdout.write(r.reportText);
      return r.exitCode;
    }

    throw new ProvError(ERROR_CODES.USAGE_ERROR, `未知子命令: ${command}`);
  } catch (err) {
    // gate 子命令使用独立的错误码与退出码（2/3），不与既有命令的退出码混用。
    if (err instanceof GateError) {
      process.stderr.write(
        `${stableJsonStringify({
          status: 'ERROR',
          errorCode: err.code,
          message: err.message,
        })}\n`,
      );
      return err.code === GATE_ERROR_CODES.VERIFICATION ? 3 : 2;
    }
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
