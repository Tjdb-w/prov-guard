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
- 可选验证策略（`--policy`）：时间窗口、签名密钥指纹白名单、强制 SBOM、文件数与总大小上限；
  策略版本 `1.1` 额外支持发布准入的文件级约束（`requiredFiles` 必需文件及内容 SHA-256、
  `forbiddenFiles` 禁止文件，按清单 Unicode 路径精确匹配）；
- 可选多方共签：`generate --co-key` 附加共签私钥（证明版本升为 1.1 并声明共签者指纹，
  额外输出 `proof.cosignatures.json` / `sbom.cosignatures.json`）；
  `verify --cosignatures/--cosigner-key/--min-cosigners` 校验共签并输出 `cosignerCount`；
- 可选策略签名：`policy-sign` 用 Ed25519 私钥为既有 `policy.json` 生成独立签名
  （`policy.json.sig`），不改写策略、私钥或证明；验证时以 `--policy-signature` +
  `--policy-key` 确认策略来自指定密钥，通过后输出 `policySignerFingerprint`；
- 可选证明分发包：`generate --bundle` 在输出目录照常写出全部独立文件，并额外生成
  `proof.bundle.json`（单文件分发包）；`verify --bundle` 直接从包验证，独立文件入口保留；
- 独立发布门禁 `gate`：根据产物、自包含签名证明、软件物料清单与发布策略判定产物是否
  可发布，输出确定性 JSON 报告（`allowed` / `denied`），不改动既有命令的默认行为；
- 目录扫描的符号链接安全处理：指向产物根目录内部文件/目录的链接按链接路径记录目标内容；
  形成回路或越出产物根目录的链接以 `SYMLINK_INVALID` 失败，不会继续递归或读取外部内容；
- 机器可读的错误码与非零退出码。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。

## 输出与路径约定

- JSON 输出一律 UTF-8、稳定字段顺序（按键名排序）、两空格缩进。
- 清单中的相对路径统一使用正斜杠（`/`），跨平台一致。
- 时间字段（`generatedAt`）只写入证明，不参与产物摘要或任何文件摘要。
- 空目录自然产生空文件列表；零字节文件按真实文件记录。
- 目录内的符号链接按真实路径判定：指向根目录内部普通文件或目录的链接，按链接路径记录
  目标内容（目录链接会展开其下文件）；链接形成回路（指回祖先目录或互相成环）或目标越出
  产物根目录时，扫描以 `SYMLINK_INVALID` 失败，不继续递归、不读取外部内容。

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
node provguard.mjs generate --artifact <产物路径> --key <私钥.pem> --out <输出目录> [--co-key <共签私钥.pem> ...] [--bundle]
```

- `--artifact`：单个文件或目录；目录会被递归扫描。
- `--key`：Ed25519 私钥 PEM（主签名密钥，生成证明与签名）。
- `--out`：输出目录（不存在会创建）；若该目录位于产物内部，会从扫描结果中排除自身。
- `--co-key`：可选、可重复的共签私钥 PEM。每个共签者对与主签名相同的证明规范字节签名，
  并另对 SBOM 规范字节签名。重复的 `--co-key` 或与主密钥相同返回 `USAGE_ERROR`。
  不提供 `--co-key` 时行为与之前完全一致，不创建共签清单（也不创建空清单）。
- `--bundle`：可选开关。启用时在输出目录照常写出下表全部独立文件，并额外生成
  `proof.bundle.json`；成功 JSON 增加 `bundlePath`。不启用时输出、语义与错误码完全不变。

输出目录内容：

| 文件 | 说明 |
| --- | --- |
| `proof.json` | 证明：证明版本、产物名、稳定产物摘要、总大小、生成时间、签名公钥指纹、SBOM 摘要（`sbomDigest`）、逐文件清单；启用共签时 `proofVersion` 为 `"1.1"` 并增加按指纹升序去重的 `cosignerKeyFingerprints` |
| `proof.json.sig` | 对证明规范字节的 Ed25519 签名（Base64），可单独保存与分发 |
| `sbom.json` | 软件物料清单：`schemaVersion` / `artifactName` / `rootType`，并按相对路径列出每个文件的 `path` / `sha256` / `size` / `type` |
| `sbom.json.sig` | 对 `sbom.json` 去尾换行后的 UTF-8 规范 JSON 的 Ed25519 签名（Base64 加换行） |
| `proof.cosignatures.json` | 仅启用共签时输出：各共签者对证明规范字节的签名清单 |
| `sbom.cosignatures.json` | 仅启用共签时输出：各共签者对 SBOM 规范字节的签名清单 |
| `proof.bundle.json` | 仅 `--bundle` 时输出：单文件证明分发包（见下） |

`proof.bundle.json` 为 UTF-8 稳定 JSON（两空格缩进、键名排序、末尾换行），结构：

```json
{
  "bundleVersion": "1.0",
  "members": {
    "proof":            { "data": "<base64>", "sha256": "<hex>", "size": 1234 },
    "proof-signature":  { "data": "<base64>", "sha256": "<hex>", "size": 88 },
    "sbom":             { "data": "<base64>", "sha256": "<hex>", "size": 2345 },
    "sbom-signature":   { "data": "<base64>", "sha256": "<hex>", "size": 88 }
  }
}
```

- `members` 按逻辑名排序；启用共签时额外包含 `proof-cosignatures` 与 `sbom-cosignatures`。
- 每个成员保存对应原文件字节的 Base64、SHA-256 与字节长度，原样保留签名输入的
  规范字节（含文件末尾换行），验证时按原字节重建各文件内容。
- 除 `generatedAt`、`proof` 及其签名外，对同一产物重复生成的包保持成员顺序、字段顺序
  与编码逐字节稳定（`sbom`、`sbom-signature` 与共签成员完全一致）。
- 空目录、零字节文件、输出目录自排除与产物摘要行为与独立文件模式一致。

两个共签清单均含 `schemaVersion`（`"1.0"`）、`artifactDigest`、`sbomDigest` 与按指纹升序的
`signers`；每项含 `keyFingerprint` 与 Base64 Ed25519 `signature`，签名者集合与证明声明的
`cosignerKeyFingerprints` 一致。启用共签时成功 JSON 额外包含 `cosignerCount` 与两个清单路径。

`sbomDigest` 是对 SBOM 规范字节（去尾换行的稳定 JSON）的 SHA-256，随证明一起签名；
`sbom.json.sig` 再对同一组字节单独签名，因此替换 `sbom.json` 无法在不暴露的情况下通过验证。

产物摘要是对“排序后的完整文件清单”做 SHA-256，因此任何字节变化、文件新增、删除或重命名都会改变摘要。
同一产物在未改动时，跨多次生成的清单与产物摘要字节级一致（仅 `generatedAt` 变化，且不影响摘要）。

### 3. 为策略签名（可选 `policy-sign`）

```
node provguard.mjs policy-sign --policy <policy.json> --key <私钥.pem> --signature <policy.json.sig>
```

- 三个参数均为必填，缺任一返回 `USAGE_ERROR`。
- 用 Ed25519 私钥对策略的 UTF-8 稳定 JSON 字节（键名排序、两空格缩进、末尾换行）签名，
  输出 Base64 加单个末尾换行的 `policy.json.sig`；与既有签名文件格式一致。
- **不改写**策略文件、私钥或任何证明产物；同一策略与密钥重复签名逐字节一致。
- 磁盘上的策略无需已是规范格式：命令先解析并按稳定形式重序列化后再签名，验证侧用同一
  规范形式验签。策略 JSON 不可解析、含未知字段、取值或 `policyVersion` 非法报
  `POLICY_INVALID`；私钥无法解析或不是 Ed25519 报 `KEY_NOT_FOUND`；策略/私钥缺失报
  `INPUT_NOT_FOUND`、不可读报 `PERMISSION_DENIED`；签名输出不可写报 `PERMISSION_DENIED`。

成功时 stdout 输出（字段按名排序）：

```json
{
  "status": "POLICY_SIGNED",
  "policyPath": "<绝对路径>",
  "signaturePath": "<绝对路径>",
  "policySignerFingerprint": "<签名公钥的 SHA-256 指纹>"
}
```

### 4. 验证

```
node provguard.mjs verify \
  --artifact <产物路径> \
  --proof <proof.json> \
  --signature <proof.json.sig> \
  --key <公钥.pem> \
  [--sbom <sbom.json> --sbom-signature <sbom.json.sig>] \
  [--cosignatures <目录> --cosigner-key <公钥.pem> ... --min-cosigners <n>] \
  [--policy <policy.json>] \
  [--policy-signature <policy.json.sig> --policy-key <策略公钥.pem>]
```

验证顺序：检查输入存在且可读 → 解析公钥 → 解析并校验证明结构 → 校验签名格式 →
比对签名公钥指纹并验签 → 重新扫描产物并逐项（摘要、文件名、大小、清单条目）比对 →
（可选）SBOM 校验 →（可选）共签校验 →（可选）策略校验（启用策略签名时先校验策略本身
与其签名，再执行策略规则）。

`--sbom` 与 `--sbom-signature` 为成对可选参数：只给一者返回 `USAGE_ERROR`；二者齐全时，
在上述检查之后继续校验 `sbom.json` 的字段、相对路径与 SHA-256 格式，重算 SBOM 摘要并与
证明中的 `sbomDigest` 比对，验证 `sbom.json.sig` 签名，最后确认 SBOM 清单、证明清单与
当前扫描逐项一致。缺省不提供这两个参数时，验证行为与之前完全一致。

`--cosignatures <目录>`、可重复的 `--cosigner-key <公钥.pem>` 与 `--min-cosigners <正整数>`
为共签校验参数，三者必须同时提供，缺少任一或 `min` 超过公钥数量返回 `USAGE_ERROR`。
共签校验在证明、可选 SBOM 与产物完整性全部通过后执行：读取目录下的
`proof.cosignatures.json` 与 `sbom.cosignatures.json`（缺失/不可读报 `INPUT_NOT_FOUND` /
`PERMISSION_DENIED`），校验清单结构、与证明的摘要绑定及签名者集合一致性
（含主签名指纹、指纹重复、字段缺失或格式非法均为 `PROOF_INVALID`），复算 SBOM 摘要
（变化优先报 `INTEGRITY_MISMATCH`），随后要求每个 `--cosigner-key` 都是证明声明的共签者
（未声明或错误公钥报 `KEY_NOT_FOUND`）且其对证明与 SBOM 的签名均有效
（签名不匹配或有效数量不足 `min` 报 `SIGNATURE_INVALID`，数量按指纹去重）。
全部通过后输出 `VERIFIED` 并增加 `cosignerCount`；之后才执行可选策略。

`--policy-signature <policy.json.sig>` 与 `--policy-key <策略公钥.pem>` 为成对可选参数，
必须与 `--policy` 同时提供；缺值、只给一者或未提供 `--policy` 均返回 `USAGE_ERROR`。
启用后，策略文件先按既有规则解析校验（非法为 `POLICY_INVALID`），再校验其签名：
签名/公钥路径缺失报 `INPUT_NOT_FOUND`、不可读报 `PERMISSION_DENIED`；策略公钥无法解析或
非 Ed25519 报 `KEY_NOT_FOUND`；策略合法但签名不是合法 Base64、长度不是 64 字节、与策略
规范字节不符或公钥不匹配，均报 `SIGNATURE_INVALID`。签名通过后才执行策略规则，违规仍为
`POLICY_VIOLATION`（`violations` 内容与排序不变）。全部通过时成功 JSON 额外包含
`policySignerFingerprint`（即实际验签所用策略公钥的 SHA-256 指纹）；不启用策略签名时
输出与之前完全一致。

成功时 stdout 输出（启用 SBOM 校验时额外包含 `sbomDigest`；启用共签校验时额外包含
`cosignerCount`；提供 `--policy` 且通过时额外包含 `"policyStatus": "PASS"`，
启用策略签名时再额外包含 `policySignerFingerprint`）：

```json
{
  "status": "VERIFIED",
  "proofVersion": "1.0",
  "artifactDigest": "<sha256>",
  "fileCount": 4
}
```

#### 分发包验证（`--bundle`）

```
node provguard.mjs verify \
  --artifact <产物路径> \
  --bundle <proof.bundle.json> \
  --key <公钥.pem> \
  [--cosigner-key <公钥.pem> ... --min-cosigners <n>] \
  [--policy <policy.json>] \
  [--policy-signature <policy.json.sig> --policy-key <策略公钥.pem>]
```

- `--bundle` 与 `--proof`、`--signature`、`--sbom`、`--sbom-signature`、`--cosignatures`
  互斥，混用返回 `USAGE_ERROR`；`--artifact` 与 `--key`（主签名公钥）仍为必填。
- 包内自带 SBOM 与其签名，视为始终启用 SBOM 校验，成功输出包含 `sbomDigest`；
  共签清单位于包内，共签校验只需 `--cosigner-key` 与 `--min-cosigners`（二者必须同时提供）。
- 验证顺序与成功字段和独立文件模式一致：先校验包结构（JSON 可解析、`bundleVersion`
  为 `"1.0"`、成员无缺失或多余、Base64 合法、长度与 SHA-256 相符，违反均为
  `PROOF_INVALID`），再按证明 → 签名 → 产物完整性 → SBOM → 共签 → 策略的顺序执行，
  各阶段错误码与独立文件模式相同。

### 5. 验证策略（可选 `--policy`，可再加策略签名）

不传 `--policy` 时行为完全不变。启用策略签名（`--policy-signature` + `--policy-key`）
只额外增加“策略来自指定密钥”的签名校验，策略文件格式与规则完全不变。策略文件为 UTF-8
JSON 对象，`policyVersion` 仅接受 `"1.0"` 与 `"1.1"`；仅允许以下字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `policyVersion` | 字符串 | **必填**，`"1.0"` 或 `"1.1"` |
| `proofNotBefore` | UTC ISO-8601 字符串 | 允许的最早 `proof.generatedAt`（闭区间，可选） |
| `proofNotAfter` | UTC ISO-8601 字符串 | 允许的最晚 `proof.generatedAt`（闭区间，可选） |
| `allowedKeyFingerprints` | 字符串数组 | 受信任签名公钥指纹白名单（64 位 SHA-256 十六进制，可选；缺省不约束，**显式空数组不接受**） |
| `requireSbom` | 布尔 | 为 `true` 时必须成对提供 `--sbom`/`--sbom-signature` 且校验通过（可选，缺省 false） |
| `maxFileCount` | 非负安全整数 | `proof.files.length` 上限（可选，含边界） |
| `maxSize` | 非负安全整数 | `proof.size` 总字节数上限（可选，含边界） |
| `requiredFiles` | 对象 | **仅 1.1**。键为产物清单中的正斜杠相对路径，值为该文件内容的 64 位**小写**十六进制 SHA-256；出现时必须为**非空对象**（可选） |
| `forbiddenFiles` | 字符串数组 | **仅 1.1**。清单中不得出现的正斜杠相对路径；出现时必须为**非空数组**且路径不重复（可选） |

规则细节：

- 未知字段、非法类型或取值均报 `POLICY_INVALID`；`proofNotBefore` 晚于 `proofNotAfter`
  同样为 `POLICY_INVALID`。
- 时间仅接受以 `Z` 结尾的 UTC ISO-8601（如 `2026-10-03T12:00:00Z`，秒可带小数）；
  `proof.generatedAt` 无法解析为该格式时记 `generated-at-invalid`，不再评估时间上下界。
- 指纹比较大小写不敏感；文件数与大小上限均为“达到上限即通过”。
- `requireSbom` 为 `false`（或缺省）时不禁止额外提供的 SBOM，仍按既有规则校验。
- 策略只在签名、完整性、可选 SBOM 校验**全部通过后**加载执行；伪造、篡改等仍按原错误码
  返回，不会落到策略结果。策略文件缺失报 `INPUT_NOT_FOUND`、不可读报 `PERMISSION_DENIED`。

#### 策略版本

- `"1.0"`：接受上述全部旧字段，**不得**携带 `requiredFiles` / `forbiddenFiles`，否则
  `POLICY_INVALID`。
- `"1.1"`：接受全部旧字段，并可有 `requiredFiles` 与 `forbiddenFiles`（均可缺省）。
  两字段互不影响其余规则；`policy-sign` 对两个版本的签名都逐字节确定，且不改写策略。
- 其他版本号一律 `POLICY_INVALID`。

#### 1.1 文件级路径与摘要约束

- 路径键（`requiredFiles`）与路径数组（`forbiddenFiles`）必须是产物清单中的正斜杠相对路径，
  按清单的 Unicode 原样**精确匹配（大小写敏感）**：不得为空字符串、绝对路径（以 `/` 开头）、
  含反斜杠、空路径段（相邻 `/` 或尾随 `/`），也不得含点目录段（`.` / `..`）。
- `requiredFiles` 的值必须恰好为 64 位**小写**十六进制 SHA-256（大写摘要非法）。
- `forbiddenFiles` 路径不得重复；同一路径不得同时出现在 `requiredFiles` 与
  `forbiddenFiles`（约束重叠为 `POLICY_INVALID`）。
- 结构、类型、取值、摘要或路径非法，以及空对象/空数组，均为 `POLICY_INVALID`。

文件级规则在主签名、SBOM、共签、完整性及可选策略签名全部通过之后才评估（此时证明清单与
当前产物逐项一致，直接以清单为真）：

- `requiredFiles` 中的路径在清单中缺失 → `required-file-missing`，`observed` 为该路径；
- 路径存在但内容摘要不符 → `required-file-digest-mismatch`，`observed` 为清单中的**实际摘要**；
- `forbiddenFiles` 中的路径在清单中出现 → `forbidden-file-present`，`observed` 为该路径。

策略违规时 stderr 输出 `POLICY_VIOLATION`，`details.violations` 按
**时间 → 密钥 → SBOM → 文件数 → 大小 → 文件级规则** 排序；文件级规则内部依次为
`required-file-missing` → `required-file-digest-mismatch` → `forbidden-file-present`，
**同类按路径的 UTF-16 码元升序**。每项含 `rule` 与 `observed`：

```json
{
  "status": "ERROR",
  "errorCode": "POLICY_VIOLATION",
  "message": "策略校验未通过（2 项违规）",
  "details": {
    "violations": [
      { "rule": "required-file-missing", "observed": "sub/missing.txt" },
      { "rule": "forbidden-file-present", "observed": "evil.bin" }
    ]
  }
}
```

可能的 `rule`：`generated-at-invalid` / `proof-not-before` / `proof-not-after` /
`allowed-key-fingerprints` / `require-sbom`（`observed` 为 `"absent"`）/
`max-file-count` / `max-size` / `required-file-missing`（`observed` 为路径）/
`required-file-digest-mismatch`（`observed` 为实际摘要）/
`forbidden-file-present`（`observed` 为路径）。

### 6. 发布门禁（`gate`，独立入口）

```
node provguard.mjs gate \
  --artifact <产物路径> \
  --proof <proof.json> \
  --sbom <sbom.json> \
  --policy <policy.json>
```

`gate` 是独立的发布判定入口：不改动既有命令的默认行为、文件格式、输出与退出码，
只读取本地公开文件（**不读取任何私钥或凭证**），成功时不写出任何业务数据文件。
执行流水线：读取并解析四类输入 → 校验策略 → 验证证明签名与产物摘要、建立 SBOM 与
产物的对应关系 → 将 SBOM 与策略逐条件比对 → 在 stdout 输出确定性 JSON 报告。

**门禁证明（`--proof`）** 为自包含签名证明（公钥内嵌，无需额外密钥文件）：

```json
{
  "artifactDigest": "<64 位十六进制，与 verify 相同的产物摘要>",
  "source": "<构建来源引用，如仓库与提交>",
  "signer": "<签名主体/证书身份>",
  "publicKey": "<Ed25519 公钥 PEM>",
  "signature": "<对去除 signature 字段后的稳定 JSON 字节的 Base64 签名>"
}
```

**门禁 SBOM（`--sbom`）**：

```json
{
  "artifactDigest": "<64 位十六进制，须与产物实际摘要一致以建立对应关系>",
  "packages": [ { "name": "...", "version": "...", "license": "..." } ]
}
```

`packages` 每项必须含非空 `name` 与 `license`，`version` 可选。

**发布策略（`--policy`）** 为非空 JSON 对象，只允许以下条件字段（可只包含其中一部分，
但至少一项；空策略、未知条件类型或值不符合条件定义均为 `PolicyError`）：

| 字段 | 类型 | 报告条件标识 | 说明 |
| --- | --- | --- | --- |
| `allowedSources` | 非空字符串数组 | `source` | 允许的构建来源引用（精确匹配证明的 `source`） |
| `allowedSigners` | 非空字符串数组 | `signer` | 允许的签名主体/证书身份（精确匹配证明的 `signer`） |
| `artifactDigest` | 64 位十六进制 | `digest` | 期望的产物摘要（大小写不敏感） |
| `allowedPackages` | 非空字符串数组 | `packages` | SBOM 中每个包名都必须命中 |
| `allowedLicenses` | 非空字符串数组 | `licenses` | SBOM 中每个许可证都必须命中 |

**报告**：stdout 输出确定性 JSON，对象键按固定顺序（`status`、`artifactDigest`、
`proofSource`、`signer`、`packageCount`、`conditions`；条件条目为 `id`、`observed`、
`result`，条件按 `source → signer → digest → packages → licenses` 排列，仅包含策略中
出现的条件）：

```json
{
  "status": "allowed",
  "artifactDigest": "<已核实的产物摘要>",
  "proofSource": "<证明中的构建来源>",
  "signer": "<证明中的签名主体>",
  "packageCount": 2,
  "conditions": [
    { "id": "source", "observed": "...", "result": "pass" }
  ]
}
```

**退出码与错误码**（门禁的失败都有唯一可观察结果，错误以 JSON 写 stderr）：

| 退出码 | 含义 |
| --- | --- |
| `0` | 全部条件通过，stdout 输出 `allowed` 报告 |
| `4` | 证明有效但违反许可证、来源、身份或包约束，stdout 输出 `denied` 报告（非系统错误，stderr 为空） |
| `2` | `InputError`：路径不存在、文件不可读、JSON 语法错误、缺少必需字段或缺少必填参数；`PolicyError`：策略为空、条件类型未知或值不符合条件定义 |
| `3` | `VerificationError`：证明签名无效、证明中的产物摘要与实际产物不一致、证明或 SBOM 无法建立与产物的对应关系 |

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
| `INPUT_NOT_FOUND` | 产物、证明、签名、SBOM 或其签名、公钥、策略文件、策略签名文件（`policy.json.sig`）/策略公钥、共签清单（`proof.cosignatures.json` / `sbom.cosignatures.json`）、证明分发包路径不存在 |
| `PERMISSION_DENIED` | 输入不可读或输出不可写（权限不足），包括策略文件、策略签名文件与共签清单不可读，以及 `policy-sign` 的签名输出不可写 |
| `KEY_NOT_FOUND` | 公钥/私钥无法解析、不是 Ed25519，验证时提供的公钥与证明记录的签名密钥不一致（错误公钥），共签公钥未在证明声明的共签者集合中，或策略签名公钥无法解析/不是 Ed25519 |
| `PROOF_INVALID` | 证明、SBOM 或共签清单的 JSON 不可解析、结构或摘要非法；签名文件不是合法 Base64 或长度非法；共签清单含主签名指纹、指纹重复、与证明声明的签名者集合不一致；分发包 JSON 不可解析、`bundleVersion` 非 `"1.0"`、成员缺失或多余、成员 Base64 非法、字节长度或 SHA-256 与内容不符、共签成员与证明声明不一致 |
| `SIGNATURE_INVALID` | 公钥正确但签名与证明/SBOM 内容不匹配（内容被改动或签名损坏）；共签签名与内容不匹配，或有效共签数量不足 `--min-cosigners`；策略合法但策略签名不是合法 Base64、长度非 64 字节、与策略规范字节不符或策略公钥不匹配 |
| `INTEGRITY_MISMATCH` | 验签通过后，产物相对证明存在字节改动、文件新增/删除/重命名，或 `sbom.json`（或共签校验时复算的 SBOM）与证明记录的 `sbomDigest` 不一致；`details.mismatches` 给出差异路径与类型（`content-modified` / `size-mismatch` / `added` / `missing` / `artifact-digest-mismatch` / `artifact-name-mismatch`） |
| `POLICY_INVALID` | 策略文件 JSON 不可解析或顶层非对象、含未知字段、字段类型/取值非法、`policyVersion` 缺失或不为 `"1.0"`/`"1.1"`、指纹白名单为空数组、`proofNotBefore` 晚于 `proofNotAfter`、1.0 携带 `requiredFiles`/`forbiddenFiles`、1.1 文件级字段为空对象/空数组或类型非法、路径为空/绝对/含反斜杠/空路径段/点目录段、摘要不是 64 位小写十六进制、`forbiddenFiles` 重复或与 `requiredFiles` 重叠（验证与 `policy-sign` 相同） |
| `POLICY_VIOLATION` | 签名与完整性（及可选 SBOM、共签、策略签名）均通过但不满足策略；`details.violations` 按时间、密钥、SBOM、文件数、大小、文件级规则（必需缺失 → 必需摘要不符 → 禁止出现，同类按路径 UTF-16 码元升序）列出全部违规，每项含 `rule` 与 `observed` |
| `SYMLINK_INVALID` | 目录扫描发现危险符号链接：形成回路（`details.reason` 为 `cycle`）或目标越出产物根目录（`details.reason` 为 `outside-root`）；`details.path` 为链接的相对路径。generate 在写出任何证明前失败，verify 在签名有效后的扫描阶段失败 |
| `USAGE_ERROR` | 缺少必填参数、未知子命令，`--sbom` 与 `--sbom-signature` 只给一者，`--co-key` 重复或与主密钥相同，共签校验三参数（`--cosignatures` / `--cosigner-key` / `--min-cosigners`）未同时提供、`--min-cosigners` 非正整数或超过共签公钥数量，`--bundle` 与独立文件参数（`--proof` / `--signature` / `--sbom` / `--sbom-signature` / `--cosignatures`）混用，包模式下 `--cosigner-key` 与 `--min-cosigners` 未同时提供，`policy-sign` 缺少 `--policy`/`--key`/`--signature`，或 `--policy-signature` 与 `--policy-key` 缺值、只给一者、未与 `--policy` 同时提供 |

错误不会被伪装成成功：只有在签名有效且全部清单条目逐项一致时才输出 `VERIFIED`。

## 示例

```
node provguard.mjs keygen --key-dir keys
node provguard.mjs generate --artifact dist/ --key keys/provguard.private.pem --out attestation/ --bundle
node provguard.mjs policy-sign --policy policy.json --key keys/provguard.private.pem \
  --signature attestation/policy.json.sig
node provguard.mjs verify   --artifact dist/ \
  --proof attestation/proof.json \
  --signature attestation/proof.json.sig \
  --key keys/provguard.public.pem \
  --sbom attestation/sbom.json \
  --sbom-signature attestation/sbom.json.sig \
  --policy policy.json \
  --policy-signature attestation/policy.json.sig \
  --policy-key keys/provguard.public.pem
# 或直接使用分发包：
node provguard.mjs verify   --artifact dist/ \
  --bundle attestation/proof.bundle.json \
  --key keys/provguard.public.pem \
  --policy policy.json \
  --policy-signature attestation/policy.json.sig \
  --policy-key keys/provguard.public.pem
```

## 测试

```
node --test
```

测试以子进程驱动 CLI，覆盖正常往返、确定性、空目录与零字节文件、输出目录自排除，
以及字节篡改、新增/删除、错误公钥、非法签名、非法证明、缺失路径与私钥不可解析等错误路径；
策略测试覆盖通过（PASS）、闭区间边界、指纹大小写不敏感、`requireSbom`、上限边界、
违规排序、`generated-at-invalid`、策略文件各类非法情形、缺失/不可读以及篡改优先；
策略 1.1 文件级规则测试覆盖必需文件通过/缺失/摘要不符（observed 为实际摘要）、禁止文件
出现、多规则整体排序（旧规则在前、同类按路径 UTF-16 码元升序）、路径 Unicode 大小写
敏感、空对象/空数组、空/绝对/反斜杠/空路径段/点目录段路径、大写或非法摘要、
`forbiddenFiles` 重复、两字段重叠、1.0 携带新字段、未知版本，以及与策略签名、分发包、
共签组合的往返；
符号链接测试覆盖越出根目录（outside-root）、指回祖先与互相成环（cycle）、ELOOP、
generate 失败前不写证明、verify 扫描阶段报错，以及安全内部链接的记录与稳定性；
共签测试覆盖双清单往返与结构、缺省不创建清单、1.1 证明的旧路径验证、重复/同源
`--co-key`、三参数缺一与非法 `min`、清单缺失、未声明公钥、签名篡改、有效数不足、
产物篡改优先级、清单含主签名指纹、部分共签达标以及共签与策略组合；
分发包测试覆盖 `--bundle` 生成（独立文件保留、成员字节与原文件一致、成员排序与
重复生成稳定性）、`verify --bundle` 往返（含共签与策略组合）、参数互斥与缺参、
包不可解析、版本非法、成员缺失/多余、Base64/长度/SHA-256 不符、包内证明篡改、
错误公钥、产物篡改与共签成员缺失；
策略签名测试覆盖 `policy-sign` 成功输出与字段、重复签名逐字节一致、不改写输入、
verify 独立文件与分发包两种模式往返、错误签名密钥/篡改策略/错误公钥、签名
Base64 与长度非法、各路径缺失与不可读、非 Ed25519 密钥、参数不成对或缺 `--policy`、
策略违规仍返回 `POLICY_VIOLATION`，以及证明/产物篡改优先于策略签名校验；
发布门禁测试覆盖 allowed/denied 往返与退出码（0/4）、报告固定键顺序与逐条件
标识/观测值/判定、部分条件策略、五类条件各自的违规判定、输入缺失/不可读/JSON
语法错误/缺字段（`InputError`，退出码 2）、空策略/未知条件/非法条件值
（`PolicyError`，退出码 2）、签名篡改/产物摘要与 SBOM 对应失败
（`VerificationError`，退出码 3），以及门禁不写出任何业务数据文件。
