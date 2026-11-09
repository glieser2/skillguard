# SkillGuard v2 (`skillguard/2`) Security & Verification Audit Report

## 1. Executive Summary

This report documents the security upgrade, static/dynamic verification, and live on-chain deployment proofs for **SkillGuard v2 (`skillguard/2`)**.

### Steward Feedback Addressed
Initial submission (`a414b531-176c-48b7-84d0-49070412b709`) received the following Steward review feedback:
> *"We cannot accept this as an install-safety attestation because publishers can omit executable files and dependencies while still receiving an approved pre-install result. A future submission would need a contract-enforced complete release manifest or tree commitment and a challenge path that can add omitted evidence."*

### How SkillGuard v2 (`skillguard/2`) Resolves Both Findings

| Finding | Contract & Client Mechanism in `skillguard/2` | Verification Proof |
| :--- | :--- | :--- |
| **1. Complete Release Manifest / Tree Commitment** | `register_release` requires `tree_commitment` (`tree_sha256`, `total_files`, `declared_dependencies`, `tree_entries`). `validate_tree_commitment` enforces that all executable extensions (`.py`, `.js`, `.ts`, `.sol`, `.sh`, etc.) have `role = "executable"`, all manifest files (`package.json`, `pyproject.toml`, `requirements.txt`, `skill.json`, `mcp.json`, etc.) have `role = "manifest"`, and **100% of `"manifest"` and `"executable"` entries** in `tree_entries` are included in audited `sources` with matching `sha256`. | Python unit tests (`test_rejects_executable_disguised_as_doc_or_omitted_from_sources`), Vitest (`domain.test.ts`), and Studio-dev Release #1 (`0x4dedf854...`). |
| **2. Manifest Install Hooks & Undeclared/Unpinned Dependencies** | `lock_evidence` runs `scan_static_signals` on fetched bytes, deterministically parsing `role == "manifest"` JSON files. Any lifecycle hook (`preinstall`, `install`, `postinstall`, `prepare`, `prepublishOnly`) raises `MANIFEST_INSTALL_HOOK`; any undeclared or unpinned dependency (`*`, `latest`, `git+`, `http://`, `https://`, `file:`) raises `UNDECLARED_OR_UNPINNED_DEPENDENCY` (`OMITTED_EXECUTABLE_OR_DEPENDENCY`), forcing `CRITICAL` / `BLOCKED`. | Python unit tests (`test_manifest_install_hook_and_unpinned_dependency_blocked`) + CLI/MCP tests. |
| **3. Omitted-Evidence Challenge Path** | `challenge_release(release_id, reason, evidence, omitted_sources)` accepts concrete omitted file descriptors from the same `repo@commit_sha`. `lock_challenge_evidence(release_id, challenge_id)` fetches and SHA-256-verifies those omitted files on-chain under `gl.eq_principle.strict_eq`, appending them to `extra_sources` and `proven_omitted_paths`. `audit_release(release_id)` then deterministically transitions the release to `BLOCKED` (`CRITICAL` / `OMITTED_EXECUTABLE_OR_DEPENDENCY`) and marks the challenge `UPHELD`. | Studio-dev Release #2 E2E (`challenge_release` `0xf8980807...` -> `lock_challenge_evidence` `0x37f4a8f7...` -> `audit_release` `0xde92ca72...` -> `BLOCKED` / `UPHELD`). |
| **4. Local Pre-Install Directory Tree Verification** | `cli/skillguard.mjs` (`--dir <local_dir>`) and `cli/mcp-server.mjs` (`local_dir`) run `verifyLocalDirectoryTree(localDir, treeCommitment)` to verify that the local directory has zero untracked executable/manifest files and that every local file matches the on-chain `tree_commitment` SHA-256. | `tests/cli.test.mjs` (`3/3` passing). |

---

## 2. Contract Equivalence & Build Integrity

- **Canonical Contract (`contracts/skill_guard.py`)**:
  - Size: `41,717` bytes
  - SHA-256: `39d65ba94fb04d087a050fe51f7cd2fc14ba644bc08ed85bbf8e152dc3c61570`
- **Compact Contract (`contracts/skill_guard_compact.py`)**:
  - Size: `34,332` bytes (generated via `scripts/build-compact-contract.py` to stay under the Bradbury Phase 2 RPC payload limit while preserving 100% of logic)
  - SHA-256: `6e76cc92b10ddb1f8cecf86b41096d733106ef636f06640dbba25fbef3114d10`
  - AST Equivalence: `ast_equivalent = true` (verified by stripping docstrings and comparing full Python AST dumps).

---

## 3. Automated Test Suite Results

1. **Python Contract Logic Unit Tests (`python -m unittest discover -s tests/python -v`)**:
   - `10 / 10` tests passed (`OK`), covering:
     - Clean release registration, evidence lock, and approval (`APPROVED`).
     - Prompt-injection static marker detection (`PROMPT_INJECTION_MARKER` -> `BLOCKED`).
     - Undeclared capability detection (`UNDECLARED_CAPABILITY` -> `BLOCKED`).
     - Rejecting executable files disguised as `"doc"` or omitted from `sources`.
     - Blocking manifest `postinstall` hooks and undeclared/unpinned dependencies.
     - Omitted-evidence challenge path (`challenge_release` + `lock_challenge_evidence` + `audit_release` -> `OMITTED_EXECUTABLE_OR_DEPENDENCY` / `BLOCKED` / `UPHELD`).
2. **Frontend Domain & Isomorphic Sandbox Tests (`corepack pnpm test:unit`)**:
   - `4 / 4` Vitest tests passed (`src/lib/domain.test.ts`).
3. **CLI & MCP Server Integration Tests (`corepack pnpm test:cli`)**:
   - `3 / 3` Node integration tests passed (`tests/cli.test.mjs`), including local directory tree verification (`--dir`).
4. **Production Frontend Bundle (`corepack pnpm build`)**:
   - TypeScript (`tsc --noEmit`) + Vite production build succeeded with zero warnings or errors.

---

## 4. On-Chain Verification Summary

### 4.1 GenLayer Testnet Bradbury Phase 2 (`chainId = 4221`)
- **Contract Address**: [`0x6AA5b430483d7DfBae3CBEc4e578160DE9504612`](https://scan.bradbury.genlayer.com/address/0x6AA5b430483d7DfBae3CBEc4e578160DE9504612)
- **Protocol Tx ID**: `0x401dee443cff3f815efe941b5709f3bdaf2d154062be1d4f920284d247c498d7`
- **L2 Envelope Tx Hash**: `0xf243f48f508760a116c18e2ea7452c1bbbb53e5d0cc5159620c7b3b9b5d3e1c6`
- **Block Number**: `268801` (`FINALIZED`, `MAJORITY_AGREE`, `result = 0 / FINISHED_WITH_RETURN`)
- **On-Chain Readback**: `get_policy_version() == "skillguard/2"`, `get_release_count() == 0`

### 4.2 GenLayer Consensus Studio-dev (`chainId = 61997`)
- **Contract Address**: `0x1C357d261e5A048FFEdA6Ac79Ea532ebb429DEAe`
- **Release #1 (`OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba`)**:
  - Complete 3-file `tree_commitment` (`contracts/package.json`, `contracts/utils/Context.sol`, `contracts/access/Ownable.sol`) -> **`APPROVED` (`LOW` risk)**.
- **Release #2 (`OpenZeppelin/openzeppelin-contracts@b7f748eae2341b9e8e8f85cf966e94476813d168`)**:
  - Publisher omitted `contracts/access/Ownable.sol` from `tree_commitment` -> Challenger submitted `Ownable.sol` via `challenge_release` (`0xf8980807...`) -> Validators locked omitted file via `lock_challenge_evidence` (`0x37f4a8f7...`) -> Round 2 `audit_release` (`0xde92ca72...`) transitioned Release #2 to **`BLOCKED` (`CRITICAL`, `OMITTED_EXECUTABLE_OR_DEPENDENCY`, `proven_omitted_paths = ["contracts/access/Ownable.sol"]`, `challenge #1 = UPHELD`)**.
