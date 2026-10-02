# Prov Guard

软件供应链证明与完整性校验工具：为构建产物生成并验证签名与证明，检测篡改并输出软件物料清单。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现零依赖命令行工具（Node.js，仅使用内置模块，Node >= 18）：

- Ed25519 密钥生成；
- 构建产物的内容摘要、JSON 证明、独立签名文件与软件物料清单（SBOM）生成；
- 证明验证：签名校验 + 逐文件完整性比对，覆盖字节改动、文件新增与删除；
- 机器可读的错误码与非零退出码。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。

## 输出与路径约定

- JSON 输出一律 UTF-8、稳定字段顺序（按键名排序）、两空格缩进。
- 清单中的相对路径统一使用正斜杠（`/`），跨平台一致。
- 时间字段（`generatedAt`）只写入证明，不参与产物摘要或任何文件摘要。
- 空目录自然产生空文件列表；零字节文件按真实文件记录。

## 运行环境

- Node.js >= 18（使用内置 `node:crypto` 的 Ed25519，无需安装依赖）。

## 命令

入口为 `provguard.mjs`：

```
node provguard.mjs <子命令> [参数]
```

### 1. 生成密钥

```
node provguard.mjs keygen --key-dir <目录> [--name <前缀>]
```

在目录中生成 `<前缀>.private.pem`（私钥，0600）与 `<前缀>.public.pem`（公钥，0644）。
默认前缀为 `provguard`。

### 2. 生成证明与物料清单

```
node provguard.mjs generate --artifact <产物路径> --key <私钥.pem> --out <输出目录>
```

- `--artifact`：单个文件或目录；目录会被递归扫描。
- `--key`：Ed25519 私钥 PEM。
- `--out`：输出目录（不存在会创建）；若该目录位于产物内部，会从扫描结果中排除自身。

输出目录内容：

| 文件 | 说明 |
| --- | --- |
| `proof.json` | 证明：证明版本、产物名、稳定产物摘要、SBOM 摘要（`sbomDigest`）、总大小、生成时间、签名公钥指纹、逐文件清单 |
| `proof.json.sig` | 对证明规范字节的 Ed25519 签名（Base64），可单独保存与分发 |
| `sbom.json` | 软件物料清单：`schemaVersion` / `artifactName` / `rootType`，并按相对路径列出每个文件的 `path` / `sha256` / `size` / `type` |
| `sbom.json.sig` | 对 `sbom.json` 规范字节（去尾换行后的 UTF-8 规范 JSON）的 Ed25519 签名（Base64） |

`sbomDigest` 是对 `sbom.json` 规范字节（去尾换行）的 SHA-256，随证明一起签名；
因此替换或改动 `sbom.json` 会在验证时被发现。

产物摘要是对“排序后的完整文件清单”做 SHA-256，因此任何字节变化、文件新增、删除或重命名都会改变摘要。
同一产物在未改动时，跨多次生成的清单与产物摘要字节级一致（仅 `generatedAt` 变化，且不影响摘要）。

### 3. 验证

```
node provguard.mjs verify \
  --artifact <产物路径> \
  --proof <proof.json> \
  --signature <proof.json.sig> \
  --key <公钥.pem> \
  [--sbom <sbom.json> --sbom-signature <sbom.json.sig>]
```

验证顺序：检查输入存在且可读 → 解析公钥 → 解析并校验证明结构 → 校验签名格式 →
比对签名公钥指纹并验签 → 重新扫描产物并逐项（摘要、文件名、大小、清单条目）比对。

`--sbom` 与 `--sbom-signature` 为成对参数，必须同时提供（只给一者返回 `USAGE_ERROR`）。
二者齐全时，在上述检查通过后继续校验 SBOM：解析并校验 `sbom.json` 结构（字段、相对路径、
SHA-256 格式）→ 重算其规范字节摘要并与证明中的 `sbomDigest` 比对 → 校验 `sbom.json.sig`
签名 → 确认 SBOM 的 `files`、证明的 `files` 与当前扫描结果逐项一致。缺省不提供时，
verify 行为与之前一致（旧版不含 `sbomDigest` 的证明仍可验证）。

成功时 stdout 输出（启用 SBOM 校验时额外包含 `sbomDigest`）：

```json
{
  "status": "VERIFIED",
  "proofVersion": "1.0",
  "artifactDigest": "<sha256>",
  "fileCount": 4,
  "sbomDigest": "<sha256，仅启用 SBOM 校验时>"
}
```

## 错误码

任何失败都以**非零退出码**结束，并在 stderr 输出机器可读 JSON：

```json
{
  "status": "ERROR",
  "errorCode": "<错误码>",
  "message": "<简短说明>",
  "details": {}
}
```

| 错误码 | 触发条件 |
| --- | --- |
| `INPUT_NOT_FOUND` | 产物、证明、签名或公钥路径不存在 |
| `PERMISSION_DENIED` | 输入不可读或输出不可写（权限不足） |
| `KEY_NOT_FOUND` | 公钥/私钥无法解析、不是 Ed25519，或验证时提供的公钥与证明记录的签名密钥不一致（错误公钥） |
| `PROOF_INVALID` | 证明或 SBOM 的 JSON 不可解析或结构非法（含摘要格式非法）；签名文件不是合法 Base64 或长度非法 |
| `SIGNATURE_INVALID` | 公钥正确但签名与证明/SBOM 内容不匹配（内容被改动或签名损坏） |
| `INTEGRITY_MISMATCH` | 验签通过后，产物相对证明存在字节改动、文件新增或删除，或 SBOM 摘要/清单与证明不一致；`details.mismatches` 给出差异路径与类型（`content-modified` / `size-mismatch` / `added` / `missing` / `artifact-digest-mismatch` / `artifact-name-mismatch` / `sbom-digest-mismatch`） |
| `USAGE_ERROR` | 缺少必填参数、未知子命令，或 `--sbom` 与 `--sbom-signature` 未成对提供 |

错误不会被伪装成成功：只有在签名有效且全部清单条目逐项一致时才输出 `VERIFIED`。

## 示例

```
node provguard.mjs keygen --key-dir keys
node provguard.mjs generate --artifact dist/ --key keys/provguard.private.pem --out attestation/
node provguard.mjs verify   --artifact dist/ \
  --proof attestation/proof.json \
  --signature attestation/proof.json.sig \
  --key keys/provguard.public.pem \
  --sbom attestation/sbom.json \
  --sbom-signature attestation/sbom.json.sig
```

## 测试

```
node --test
```

测试以子进程驱动 CLI，覆盖正常往返、确定性、空目录与零字节文件、输出目录自排除，
以及字节篡改、新增/删除、错误公钥、非法签名、非法证明、缺失路径与私钥不可解析等错误路径。
