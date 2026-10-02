# Prov Guard

软件供应链证明与完整性校验工具：为构建产物生成并验证签名与证明，检测篡改并输出软件物料清单。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现可独立执行的命令行工具：构建产物签名、证明生成、证明验证、篡改检测与
软件物料清单（SBOM）输出。仅依赖 Node.js（>= 18）内置模块，无第三方依赖。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。

## 运行环境

- Node.js >= 18（使用内置 `node:crypto` 的 Ed25519 与文件系统 API）。
- 无需 `npm install`；Windows / macOS / Linux 行为一致。

## 命令

入口为 `src/cli.mjs`（也可通过 `npx provguard` 或 `node src/cli.mjs` 调用）。

### 1. 生成签名密钥

```
node src/cli.mjs keygen --out keys/
```

输出 `private_key.pem`（PKCS#8，权限收窄为 0600）与 `public_key.pem`（SPKI）。

### 2. 生成证明与物料清单

```
node src/cli.mjs generate \
  --artifact <构建产物目录> \
  --key <private_key.pem> \
  --out <输出目录>
```

- 递归读取产物目录中的全部常规文件，计算每个文件的 SHA-256，记录相对路径、
  字节大小与类型（text/binary）。
- 计算整个产物的稳定内容摘要（对排序后的 `路径|大小|文件摘要` 流再取 SHA-256）。
- 输出三个文件：
  - `proof.json`：证明，含证明版本 `version`、生成时间 `generated_at`、
    产物名、产物摘要、签名公钥指纹、文件清单、文件总数与总大小；
    使用稳定字段顺序与两空格缩进，文件字节即签名输入。
  - `proof.json.sig`：对 `proof.json` 规范字节的 Ed25519 裸签名（64 字节），
    可单独保存与分发。
  - `sbom.json`：JSON 格式软件物料清单，按相对路径排序列出每个文件的
    摘要、大小与类型。
- 同一产物在未改变时重复生成，`sbom.json` 与 `proof.json` 中的摘要/文件列表
  逐字节一致；`generated_at` 只记录生成时间，不参与任何摘要或文件清单计算。
- 输出目录位于产物目录内部时自动排除（证明中以相对路径记录 `excluded_dirs`），
  输出目录不能与产物根目录相同。空目录与零字节文件按真实情况记录。

成功时 stdout 输出 `status=GENERATED` 及证明/签名/清单路径、版本、产物摘要、
文件条目数与生成时间。

### 3. 验证证明并检测篡改

```
node src/cli.mjs verify \
  --artifact <构建产物目录> \
  --proof <proof.json> \
  --signature <proof.json.sig> \
  --key <public_key.pem>
```

按固定顺序执行：检查全部输入存在 → 解析证明与签名格式 → 校验公钥与证明记录的
签名密钥一致 → 验证签名 → 重新扫描产物并逐项比较摘要、路径、大小与清单。

成功时 stdout 输出：

```json
{
  "status": "VERIFIED",
  "version": "1.0",
  "artifact_digest": "<64 位十六进制摘要>",
  "file_count": 12
}
```

任意文件字节变化（含等长替换）、文件新增或删除都判定为篡改，输出
`INTEGRITY_MISMATCH`，并在 `detail.differences` 中列出发生差异的相对路径及
类型（`added` / `removed` / `modified`）。

## 错误码与退出码

所有失败均以非零退出码结束，stdout 输出机器可读 JSON：
`{"error": "<错误码>", "message": "<简短说明>", "detail": ...}`，
绝不把错误伪装成成功。

| 错误码 | 退出码 | 含义 |
| --- | --- | --- |
| `INPUT_NOT_FOUND` | 2 | 产物、证明或签名路径不存在 / 不可访问 |
| `PERMISSION_DENIED` | 3 | 输入或输出路径权限不足 |
| `PROOF_INVALID` | 4 | 证明 JSON 非法、字段缺失/非法，或签名格式非法（非 64 字节） |
| `INTEGRITY_MISMATCH` | 5 | 重算摘要/清单与证明不一致：字节变化或文件增删（篡改） |
| `SIGNATURE_INVALID` | 6 | 签名与证明内容不匹配（含证明被篡改、签名被翻转） |
| `KEY_NOT_FOUND` | 7 | 公钥文件缺失、无法解析，或与证明记录的签名密钥不是同一把 |

## 路径与输出约定

- 清单与差异中的相对路径统一使用正斜杠 `/`（Windows 上同样如此）。
- 所有 JSON 均为 UTF-8、键名字典序稳定排列、两空格缩进、以换行结尾。
- 只统计常规文件；空目录允许（记为 0 个文件），零字节文件记录大小为 0、
  摘要为 SHA-256 空输入摘要。

## 测试

```
npm test        # 即 node --test test/*.test.mjs
```

覆盖成功路径、字节篡改、等长替换、新增/删除文件、错误公钥、非法签名、
非法证明、缺失输入、空目录/零字节文件、输出目录位于产物内，以及 SBOM 确定性。
