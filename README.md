# Prov Guard

软件供应链证明与完整性校验工具：为构建产物生成并验证签名与证明，检测篡改并输出软件物料清单。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现零依赖命令行工具（Node.js，仅使用内置模块，Node >= 18）：

- Ed25519 密钥生成；
- 构建产物的内容摘要、JSON 证明、独立签名文件与软件物料清单（SBOM）生成；
- SBOM 纳入签名保护：`proof.json` 记录 `sbomDigest`，`sbom.json.sig` 对 SBOM 规范字节单独签名，防止证明有效而 `sbom.json` 被替换；
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
| `proof.json` | 证明：证明版本、产物名、稳定产物摘要、总大小、生成时间、签名公钥指纹、SBOM 摘要（`sbomDigest`）、逐文件清单 |
| `proof.json.sig` | 对证明规范字节的 Ed25519 签名（Base64），可单独保存与分发 |
| `sbom.json` | 软件物料清单：`schemaVersion` / `artifactName` / `rootType`，并按相对路径列出每个文件的 `path` / `sha256` / `size` / `type` |
| `sbom.json.sig` | 对 `sbom.json` 去尾换行后的 UTF-8 规范 JSON 的 Ed25519 签名（Base64 加换行） |

`sbomDigest` 是对 SBOM 规范字节（去尾换行的稳定 JSON）的 SHA-256，随证明一起签名；
`sbom.json.sig` 再对同一组字节单独签名，因此替换 `sbom.json` 无法在不暴露的情况下通过验证。

产物摘要是对“排序后的完整文件清单”做 SHA-256，因此任何字节变化、文件新增、删除或重命名都会改变摘要。
同一产物在未改动时，跨多次生成的清单与产物摘要字节级一致（仅 `generatedAt` 变化，且不影响摘要）。

### 3. 验证

```
node provguard.mjs verify \
  --artifact <产物路径> \
  --proof <proof.json> \
  --signature <proof.json.sig> \
  --key <公钥.pem> \
  [--sbom <sbom.json> --sbom-signature <sbom.json.sig>] \
  [--policy <policy.json>]
```

验证顺序：检查输入存在且可读 → 解析公钥 → 解析并校验证明结构 → 校验签名格式 →
比对签名公钥指纹并验签 → 重新扫描产物并逐项（摘要、文件名、大小、清单条目）比对。

`--sbom` 与 `--sbom-signature` 为成对可选参数：只给一者返回 `USAGE_ERROR`；二者齐全时，
在上述检查之后继续校验 `sbom.json` 的字段、相对路径与 SHA-256 格式，重算 SBOM 摘要并与
证明中的 `sbomDigest` 比对，验证 `sbom.json.sig` 签名，最后确认 SBOM 清单、证明清单与
当前扫描逐项一致。缺省不提供这两个参数时，验证行为与之前完全一致。

成功时 stdout 输出（启用 SBOM 校验时额外包含 `sbomDigest`，启用策略时额外包含 `policyStatus`）：

```json
{
  "status": "VERIFIED",
  "proofVersion": "1.0",
  "artifactDigest": "<sha256>",
  "fileCount": 4
}
```

### 4. 验证策略（可选）

`verify --policy <policy.json>` 在签名、完整性与可选 SBOM 校验**全部通过之后**评估额外策略；
不提供 `--policy` 时行为与之前完全一致。策略文件为 UTF-8 JSON 对象，仅允许以下字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `policyVersion` | 字符串 | **必填**，只接受 `"1.0"` |
| `proofNotBefore` | UTC ISO-8601 时间 | 缺省不限制；`proof.generatedAt` 不得早于该时刻 |
| `proofNotAfter` | UTC ISO-8601 时间 | 缺省不限制；`proof.generatedAt` 不得晚于该时刻 |
| `allowedKeyFingerprints` | 字符串数组 | 缺省不约束；给出时必须非空，元素为 64 位 SHA-256 十六进制（大小写不敏感），`signerKeyFingerprint` 须命中其一 |
| `requireSbom` | 布尔 | 为 `true` 时必须成对提供 `--sbom`/`--sbom-signature` 且校验通过；为 `false` 时不禁止额外 SBOM |
| `maxFileCount` | 非负安全整数 | `proof.files.length` 上限（含边界） |
| `maxSize` | 非负安全整数 | `proof.size` 上限（含边界） |

时间区间为闭区间；`proofNotBefore` 晚于 `proofNotAfter` 视为策略非法。
未知字段、非法类型或取值、JSON 不可解析或顶层非对象均为 `POLICY_INVALID`；
策略文件缺失为 `INPUT_NOT_FOUND`，不可读为 `PERMISSION_DENIED`。

策略通过时 `VERIFIED` 输出增加 `"policyStatus": "PASS"`；未通过时 stderr 输出
`errorCode: "POLICY_VIOLATION"`，`details.violations` 按 时间 → 密钥 → SBOM → 文件数 → 大小
排序，每条含 `rule` 与 `observed`：

| rule | 含义 |
| --- | --- |
| `generated-at-invalid` | `proof.generatedAt` 不是可解析的 UTC ISO-8601 时间 |
| `generated-at-before-not-before` | 生成时间早于 `proofNotBefore` |
| `generated-at-after-not-after` | 生成时间晚于 `proofNotAfter` |
| `key-fingerprint-not-allowed` | 签名密钥指纹不在信任列表 |
| `sbom-required` | 策略要求 SBOM 但未提供 |
| `file-count-exceeded` | 文件数超过 `maxFileCount` |
| `size-exceeded` | 总大小超过 `maxSize` |

策略只在全部既有校验通过后评估：伪造、篡改仍按原错误码返回，不会产生部分成功输出。

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
| `INPUT_NOT_FOUND` | 产物、证明、签名、SBOM 或其签名、公钥、策略文件路径不存在 |
| `PERMISSION_DENIED` | 输入不可读或输出不可写（权限不足） |
| `KEY_NOT_FOUND` | 公钥/私钥无法解析、不是 Ed25519，或验证时提供的公钥与证明记录的签名密钥不一致（错误公钥） |
| `PROOF_INVALID` | 证明或 SBOM 的 JSON 不可解析、结构或摘要非法；签名文件不是合法 Base64 或长度非法 |
| `SIGNATURE_INVALID` | 公钥正确但签名与证明/SBOM 内容不匹配（内容被改动或签名损坏） |
| `INTEGRITY_MISMATCH` | 验签通过后，产物相对证明存在字节改动、文件新增/删除/重命名，或 `sbom.json` 与证明记录的 `sbomDigest` 不一致；`details.mismatches` 给出差异路径与类型（`content-modified` / `size-mismatch` / `added` / `missing` / `artifact-digest-mismatch` / `artifact-name-mismatch`） |
| `POLICY_INVALID` | 策略文件 JSON 不可解析或顶层非对象、含未知字段、字段类型或取值非法、`proofNotBefore` 晚于 `proofNotAfter` |
| `POLICY_VIOLATION` | 全部既有校验通过但策略未通过；`details.violations` 按 时间 → 密钥 → SBOM → 文件数 → 大小 给出各条 `rule` 与 `observed` |
| `USAGE_ERROR` | 缺少必填参数、未知子命令，或 `--sbom` 与 `--sbom-signature` 只给一者 |

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
