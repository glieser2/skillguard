# SkillGuard v2 (`skillguard/2`)

[English](README.md) | [简体中文](README.zh-CN.md)

**基于 GenLayer 的固定 Commit 智能体技能与 MCP 供应链安全认证注册表（`skillguard/2`：合约强制完整发布目录树承诺 + 遗漏文件证据挑战通道）**

> **在线体验 (GitHub Pages)**: [https://glieser2.github.io/skillguard/](https://glieser2.github.io/skillguard/)  
> **GitHub 仓库**: [https://github.com/glieser2/skillguard](https://github.com/glieser2/skillguard)  
> **GenLayer Testnet Bradbury Phase 2 (`chainId = 4221`)**: [`0x6AA5b430483d7DfBae3CBEc4e578160DE9504612`](https://scan.bradbury.genlayer.com/address/0x6AA5b430483d7DfBae3CBEc4e578160DE9504612)

---

## SkillGuard v2 (`skillguard/2`) 核心安全升级

针对 Steward 对 v1 版本的审核反馈（*“发布者可以在遗漏可执行文件和依赖项的情况下仍然获得预安装认证通过结果；后续提交需要由合约强制执行完整的发布清单或目录树承诺，并提供能够补充遗漏证据的挑战路径”*），**SkillGuard v2 (`skillguard/2`)** 在智能合约、前端与 CLI/MCP 全链路实现了三项强制安全机制：

1. **合约强制完整发布目录树承诺（`tree_commitment`）与防伪装校验（`register_release`）**：
   - 每次调用 `register_release` 必须提交完整的 `tree_commitment`（包含 `tree_sha256`、`total_files`、`declared_dependencies` 与完整文件列表 `tree_entries`）。
   - 合约内置防伪装扩展名校验（`validate_tree_commitment`）：
     - 凡扩展名为 `.py`、`.js`、`.mjs`、`.cjs`、`.ts`、`.tsx`、`.jsx`、`.sh`、`.bash`、`.ps1`、`.sol`、`.rs`、`.go`、`.rb`、`.php`、`.wasm`、`.bin` 的文件，**必须**标记为 `role = "executable"`（严禁伪装为 `"doc"` 或 `"asset"` 逃避审计）。
     - 凡文件名为 `package.json`、`pyproject.toml`、`requirements.txt`、`cargo.toml`、`skill.json`、`mcp.json`、`manifest.json` 的清单文件，**必须**标记为 `role = "manifest"`。
     - `tree_entries` 中 **100% 的 `"manifest"` 与 `"executable"` 文件**必须全部纳入待审 `sources` 列表，且路径、角色与 `sha256` 严格一致，否则合约直接拒绝注册。
2. **确定性清单安装钩子（Install Hooks）与依赖完整性筛查（`lock_evidence`）**：
   - 在 `lock_evidence(release_id)` 阶段，验证者通过 `gl.eq_principle.strict_eq` 抓取 GitHub 固定 Commit 原始字节并校验 SHA-256，同时确定性解析所有 `role == "manifest"` 的清单文件：
     - 一旦检出 `preinstall`、`install`、`postinstall`、`prepare`、`prepublishOnly` 等安装期自动执行钩子，立即触发 `MANIFEST_INSTALL_HOOK`。
     - 一旦检出 `dependencies` / `optionalDependencies` / `peerDependencies` 中存在未在 `tree_commitment.declared_dependencies` 中声明的依赖，或使用了非固定版本（`*`、`latest`、`git+`、`http://`、`https://`、`file:`、`link:`），立即触发 `UNDECLARED_OR_UNPINNED_DEPENDENCY`（映射为 `OMITTED_EXECUTABLE_OR_DEPENDENCY`），强制判定为 `CRITICAL` / `BLOCKED`。
3. **遗漏文件证据挑战与链上重审通道（`challenge_release` -> `lock_challenge_evidence` -> `audit_release`）**：
   - 若发布者在提交 `tree_commitment` 时故意隐瞒了同一 Git Commit 下的某个可执行文件或依赖清单，任何挑战者均可调用 `challenge_release(release_id, reason, evidence, omitted_sources)` 提交同一 `repo@commit_sha` 下的遗漏文件描述符（`path`、`raw_url`、`sha256`、`role`）。
   - 调用 `lock_challenge_evidence(release_id, challenge_id)` 后，GenLayer 验证者节点会在链上通过 `strict_eq` 共识抓取该遗漏文件并验证 SHA-256，将其追加至版本记录的 `extra_sources` 与 `proven_omitted_paths`，并将挑战标记为 `evidence_locked = True`。
   - 随后调用 `audit_release(release_id)` 触发重审时，合约将确定性把该版本状态更新为 `BLOCKED`（`CRITICAL` 风险，违规码 `OMITTED_EXECUTABLE_OR_DEPENDENCY`），并将挑战状态更新为 `UPHELD`（挑战成立）。
4. **CLI 与 MCP 本地目录树完整性校验（`--dir <local_dir>`）**：
   - `npx skillguard check <owner/repo> <commit_sha> --dir <local_dir>` 与 `skillguard_check_release` MCP 工具支持将本地待安装目录与链上 `tree_commitment` 逐文件比对 SHA-256，一旦发现本地多出未登记的可执行/清单文件或哈希不一致，立即拦截退出。

---

## 链上真实部署与端到端验证证明

### 1. GenLayer Testnet Bradbury Phase 2 (`chainId = 4221`) — 生产环境 v2 部署

完整证明记录于 [`artifacts/bradbury-deployment-proof.json`](artifacts/bradbury-deployment-proof.json) 与 [`src/deployment.json`](src/deployment.json)：

| 字段 | 详情 |
| :--- | :--- |
| **网络** | GenLayer Testnet Bradbury Phase 2 (`https://rpc.bradbury.genlayer.com`, `chainId = 4221`) |
| **策略版本** | `skillguard/2`（已通过链上只读调用 `get_policy_version()` 验证） |
| **合约地址** | [`0x6AA5b430483d7DfBae3CBEc4e578160DE9504612`](https://scan.bradbury.genlayer.com/address/0x6AA5b430483d7DfBae3CBEc4e578160DE9504612) |
| **部署者地址** | `0x5d89aa09Dea3aa1792B6a5E7de755A97d9c504bD` |
| **GenLayer 协议交易 ID** | `0x401dee443cff3f815efe941b5709f3bdaf2d154062be1d4f920284d247c498d7` |
| **L2 Envelope 交易哈希** | `0xf243f48f508760a116c18e2ea7452c1bbbb53e5d0cc5159620c7b3b9b5d3e1c6` |
| **区块高度** | `268801` (`0x1354c2549d452873147144df864153ac24f282d5803a5b767982ee623c0d0986`) |
| **共识状态** | `FINALIZED` / `MAJORITY_AGREE` (`result = 0 / FINISHED_WITH_RETURN`) |
| **完整合约源码** | [`contracts/skill_guard.py`](contracts/skill_guard.py)（`41,717` 字节，SHA-256 `39d65ba94fb04d087a050fe51f7cd2fc14ba644bc08ed85bbf8e152dc3c61570`） |
| **紧凑版合约源码** | [`contracts/skill_guard_compact.py`](contracts/skill_guard_compact.py)（`34,332` 字节，SHA-256 `6e76cc92b10ddb1f8cecf86b41096d733106ef636f06640dbba25fbef3114d10`，`ast_equivalent = true`） |

### 2. GenLayer Consensus Studio-dev (`chainId = 61997`) — 完整 E2E 生命周期证明

完整证明记录于 [`artifacts/studio-e2e.json`](artifacts/studio-e2e.json)：

- **合约地址**：`0x1C357d261e5A048FFEdA6Ac79Ea532ebb429DEAe`（部署交易 `0xe563d072307604b9f51546bb47b0dadfaf3708e78a25df03e86f76ad5b65d051`，`get_policy_version() == "skillguard/2"`）
- **Release #1（完整目录树承诺 -> `APPROVED` / `LOW` 低风险认证通过）**：
  - 目标版本：`OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba`（包含 `contracts/package.json`、`contracts/utils/Context.sol`、`contracts/access/Ownable.sol`，`tree_sha256 = a707f860579e11607d94133d9f75d005eb9757f7cb4480cec4c02f170b94fda2`）
  - `register_release` -> `lock_evidence` -> `audit_release` 全部达成 `MAJORITY_AGREE`，最终状态为 **`APPROVED` (`LOW`)**。
- **Release #2（遗漏文件挑战路径 E2E -> `BLOCKED` / `CRITICAL` / `UPHELD`）**：
  - 目标版本：`OpenZeppelin/openzeppelin-contracts@b7f748eae2341b9e8e8f85cf966e94476813d168`（发布者仅登记 `contracts/package.json` 与 `contracts/utils/Context.sol`，故意从 `tree_commitment` 中遗漏了同 Commit 下的 `contracts/access/Ownable.sol`）
  - 第一轮审计通过后，挑战者调用 `challenge_release` 提交遗漏文件 `contracts/access/Ownable.sol` -> 调用 `lock_challenge_evidence` 在链上抓取并验证该遗漏文件 -> 调用 `audit_release` 重审，最终状态确定性转为 **`BLOCKED`（`CRITICAL` 风险，违规码 `OMITTED_EXECUTABLE_OR_DEPENDENCY`，`proven_omitted_paths = ["contracts/access/Ownable.sol"]`，挑战 `#1` 状态为 `UPHELD`）**。

---

## 快速开始与验证命令

```bash
corepack pnpm install

# 1. 运行 Python 智能合约单元测试（10/10 全部通过，覆盖目录树承诺与遗漏文件挑战）
python -m unittest discover -s tests/python -v

# 2. 运行前端领域测试与 CLI/MCP 集成测试（包含 --dir 本地目录树校验）
corepack pnpm test

# 3. 构建生产环境前端包
corepack pnpm build

# 4. 测试 CLI 安装前门禁（含 --dir 本地目录树比对）
node cli/skillguard.mjs check OpenZeppelin/openzeppelin-contracts 3e6c86392c97fbc30d3d20a378a6f58beba08eba --demo
node cli/skillguard.mjs check OpenZeppelin/openzeppelin-contracts 3e6c86392c97fbc30d3d20a378a6f58beba08eba --demo --dir .
node cli/skillguard.mjs check agent-tools-lab/solana-rebalancer-mcp 7b4e9102c5f841d8a92b0e11c4f97a8e3d21b604 --demo
```

---

## 开源许可

MIT
