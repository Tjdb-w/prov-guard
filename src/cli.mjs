#!/usr/bin/env node
// Prov Guard CLI：keygen / generate / verify。
// 所有面向使用者的输出均为 UTF-8 JSON（稳定字段顺序、两空格缩进）；
// 错误一律以非零退出码结束，绝不伪装成功。
'use strict';

import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  ErrorCode,
  ProvError,
  assertExistingPath,
  buildModel,
  checkSignature,
  computeArtifactDigest,
  diffFiles,
  ensureDir,
  fail,
  generateKeyPair,
  keyFingerprint,
  loadPrivateKey,
  loadPublicKey,
  loadSignature,
  mapFsError,
  parseProof,
  proofCanonical,
  signProof,
  stableJSONStringify,
  writeOutputFile,
  chmod600,
} from './core.mjs';

// 错误码 -> 退出码（稳定、可脚本判断）。
const EXIT_CODES = {
  USAGE: 1,
  [ErrorCode.INPUT_NOT_FOUND]: 2,
  [ErrorCode.PERMISSION_DENIED]: 3,
  [ErrorCode.PROOF_INVALID]: 4,
  [ErrorCode.INTEGRITY_MISMATCH]: 5,
  [ErrorCode.SIGNATURE_INVALID]: 6,
  [ErrorCode.KEY_NOT_FOUND]: 7,
  INTERNAL: 70,
};

function main(argv) {
  const [command, ...rest] = argv;
  switch (command) {
    case 'keygen':
      return cmdKeygen(rest);
    case 'generate':
      return cmdGenerate(rest);
    case 'verify':
      return cmdVerify(rest);
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      printUsage();
      return 0;
    default:
      emitError('USAGE', `未知子命令: ${command}`, null);
      return EXIT_CODES.USAGE;
  }
}

// ---------------------------------------------------------------------------
// 参数解析
// ---------------------------------------------------------------------------

function parseFlags(args, required) {
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    if (!token.startsWith('--') || token === '--') {
      throw new ProvError('USAGE', `无法识别的参数: ${token}`, null);
    }
    const name = token.slice(2);
    const value = args[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new ProvError('USAGE', `参数 --${name} 缺少取值`, null);
    }
    flags[name] = value;
    i++;
  }
  for (const name of required) {
    if (typeof flags[name] !== 'string') {
      throw new ProvError('USAGE', `缺少必需参数 --${name}`, null);
    }
  }
  return flags;
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

function cmdKeygen(args) {
  const flags = parseFlags(args, ['out']);
  const outDir = path.resolve(flags.out);
  ensureDir(outDir);

  const { privateKey, publicKey } = generateKeyPair();
  const privPath = path.join(outDir, 'private_key.pem');
  const pubPath = path.join(outDir, 'public_key.pem');
  writeOutputFile(
    privPath,
    privateKey.export({ format: 'pem', type: 'pkcs8' }),
  );
  writeOutputFile(pubPath, publicKey.export({ format: 'pem', type: 'spki' }));
  chmod600(privPath);

  emit({
    status: 'KEYS_GENERATED',
    private_key: privPath,
    public_key: pubPath,
  });
  return 0;
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

function cmdGenerate(args) {
  const flags = parseFlags(args, ['artifact', 'key', 'out']);
  const artifactDir = path.resolve(flags.artifact);
  const keyPath = path.resolve(flags.key);
  const outDir = path.resolve(flags.out);

  // 先校验输入（产物目录、私钥），再创建输出目录。
  assertExistingPath(artifactDir, '产物路径', { directory: true });
  if (outDir === artifactDir) {
    throw new ProvError(
      'USAGE',
      '输出目录不能与产物目录相同，请使用独立的输出目录',
      { out: flags.out },
    );
  }
  const privateKey = loadPrivateKey(keyPath);
  const publicKey = createPublicKey(privateKey);

  ensureDir(outDir);

  const timestamp = new Date().toISOString();
  const { proof, sbom } = buildModel(
    artifactDir,
    outDir,
    timestamp,
    publicKey,
  );
  const canonical = proofCanonical(proof);
  const signature = signProof(privateKey, canonical);

  const proofPath = path.join(outDir, 'proof.json');
  const sigPath = path.join(outDir, 'proof.json.sig');
  const sbomPath = path.join(outDir, 'sbom.json');
  // proof.json 写出的即签名时使用的规范字节，验签时重构结果逐字节一致。
  writeOutputFile(proofPath, canonical);
  writeOutputFile(sigPath, signature);
  writeOutputFile(sbomPath, stableJSONStringify(sbom));

  emit({
    status: 'GENERATED',
    proof: proofPath,
    signature: sigPath,
    sbom: sbomPath,
    version: proof.version,
    artifact_digest: proof.artifact_digest,
    file_count: proof.file_count,
    generated_at: proof.generated_at,
  });
  return 0;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

function cmdVerify(args) {
  const flags = parseFlags(args, ['artifact', 'proof', 'signature', 'key']);
  const artifactDir = path.resolve(flags.artifact);
  const proofPath = path.resolve(flags.proof);
  const sigPath = path.resolve(flags.signature);
  const keyPath = path.resolve(flags.key);

  // 1) 存在性检查（顺序：产物 -> 证明 -> 签名 -> 公钥）。
  assertExistingPath(artifactDir, '产物路径', { directory: true });
  let rawProof;
  try {
    rawProof = readFileSync(proofPath);
  } catch (err) {
    throw mapFsError(err, '证明文件');
  }
  loadSignature(sigPath); // 路径缺失 -> INPUT_NOT_FOUND；长度非法 -> PROOF_INVALID
  const publicKey = loadPublicKey(keyPath); // 缺失/无法解析 -> KEY_NOT_FOUND

  // 2) 格式可解析性检查（非法证明/签名 -> PROOF_INVALID）。
  const parsedProof = parseProof(rawProof);
  const signatureBuf = loadSignature(sigPath);

  // 3) 公钥与证明记录的签名者不一致，视为没有可用的正确密钥。
  const providedFingerprint = keyFingerprint(publicKey);
  if (
    parsedProof.signer_key_fingerprint !== null &&
    parsedProof.signer_key_fingerprint !== providedFingerprint
  ) {
    throw fail(ErrorCode.KEY_NOT_FOUND, '公钥与证明记录的签名密钥不匹配', {
      expected_fingerprint: parsedProof.signer_key_fingerprint,
      provided_fingerprint: providedFingerprint,
    });
  }

  // 4) 验签：证明内容或签名不匹配 -> SIGNATURE_INVALID。
  const canonical = proofCanonical(parsedProof);
  if (!checkSignature(publicKey, canonical, signatureBuf)) {
    throw fail(
      ErrorCode.SIGNATURE_INVALID,
      '签名校验失败：签名与证明内容不匹配',
      null,
    );
  }

  // 5) 重新扫描产物并逐项比较：字节变化、新增、删除 -> INTEGRITY_MISMATCH。
  //    按证明记录的相对路径重建生成时的排除集合（通常即输出目录）。
  const excludeDirs = parsedProof.excluded_dirs.map((rel) =>
    path.resolve(artifactDir, rel.split('/').join(path.sep)),
  );
  const { records } = buildModel(
    artifactDir,
    excludeDirs,
    parsedProof.generated_at,
    publicKey,
  );
  const currentDigest = computeArtifactDigest(records);
  const changes = diffFiles(parsedProof.files, records);

  if (changes.length > 0 || currentDigest !== parsedProof.artifact_digest) {
    throw fail(
      ErrorCode.INTEGRITY_MISMATCH,
      '产物完整性校验失败：检测到篡改',
      {
        expected_artifact_digest: parsedProof.artifact_digest,
        actual_artifact_digest: currentDigest,
        differences: changes,
      },
    );
  }

  emit({
    status: 'VERIFIED',
    version: parsedProof.version,
    artifact_digest: parsedProof.artifact_digest,
    file_count: records.length,
  });
  return 0;
}

// ---------------------------------------------------------------------------
// 输出辅助
// ---------------------------------------------------------------------------

function emit(obj) {
  process.stdout.write(stableJSONStringify(obj));
}

function emitError(code, message, detail) {
  const payload = { error: code, message };
  if (detail !== null && detail !== undefined) payload.detail = detail;
  process.stdout.write(stableJSONStringify(payload));
}

function printUsage() {
  process.stdout.write(
    [
      'Prov Guard - 软件供应链证明与完整性校验工具',
      '',
      '用法:',
      '  provguard keygen   --out <密钥输出目录>',
      '  provguard generate --artifact <产物目录> --key <私钥PEM> --out <输出目录>',
      '  provguard verify   --artifact <产物目录> --proof <proof.json>',
      '                     --signature <proof.json.sig> --key <公钥PEM>',
      '',
      'generate 输出: proof.json / proof.json.sig / sbom.json',
      'verify 成功输出 status=VERIFIED；失败输出 error=<错误码> 并以非零码退出。',
      '',
    ].join('\n'),
  );
}

// 顶层兜底：已知错误映射公开错误码，未知错误归为 INTERNAL。
let exitCode;
try {
  exitCode = main(process.argv.slice(2));
} catch (err) {
  if (err instanceof ProvError) {
    emitError(err.code, err.message, err.detail ?? null);
    exitCode = EXIT_CODES[err.code] ?? EXIT_CODES.INTERNAL;
  } else {
    emitError('INTERNAL', err?.message ?? String(err), null);
    exitCode = EXIT_CODES.INTERNAL;
  }
}
process.exit(exitCode);
