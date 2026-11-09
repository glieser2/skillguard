# GenLayer Portal Resubmission Draft (`SkillGuard v2` / `skillguard/2`)

Resubmission target: `https://portal.genlayer.foundation/submit-contribution?resubmit=a414b531-176c-48b7-84d0-49070412b709`

---

## 02. One-Line Description (<= 180 chars)

```text
Commit-pinned MCP & agent skill attestation registry on GenLayer with contract-enforced release tree commitments, omitted-file challenges, and multi-LLM consensus.
```
*(163 characters)*

---

## 03. Detailed Description (<= 1000 chars)

```text
SkillGuard v2 (skillguard/2) is an on-chain pre-install attestation registry for MCP servers & agent skills on GenLayer, upgraded to address Steward feedback:
1. Contract-Enforced Complete Release Tree Commitment: register_release requires a full tree_commitment (tree_sha256, total_files, declared_dependencies, tree_entries). Anti-evasion rules enforce that all code files (.py/.js/.ts/.sol/.sh/etc.) are classified as executable, manifests (package.json/pyproject.toml/skill.json/mcp.json) as manifest, and 100% of manifest & executable files are included in audited sources.
2. Deterministic Manifest & Dependency Screening: lock_evidence fetches commit-pinned GitHub raw bytes via strict_eq, verifies SHA-256, and blocks install hooks (preinstall/postinstall) or undeclared/unpinned dependencies.
3. Omitted-Evidence Challenge Path: challenge_release accepts omitted_sources from the same repo@commit; lock_challenge_evidence locks them on-chain via strict_eq, and audit_release blocks the release (OMITTED_EXECUTABLE_OR_DEPENDENCY) and marks the challenge UPHELD.
```
*(996 characters)*

---

## 05. Step-by-Step Verification Guide

```text
1. Inspect Live Bradbury Phase 2 Contract (chainId 4221):
Open https://scan.bradbury.genlayer.com/address/0x6AA5b430483d7DfBae3CBEc4e578160DE9504612 (Protocol Tx: 0x401dee443cff3f815efe941b5709f3bdaf2d154062be1d4f920284d247c498d7, Block 268801). Calling get_policy_version() returns "skillguard/2".

2. Explore the Interactive Web Workbench:
Open https://glieser2.github.io/skillguard/ (or clone https://github.com/glieser2/skillguard and run `corepack pnpm install && corepack pnpm dev`).
- Open the "Tree Commitment & Sources" tab on SG-#001 to verify tree_sha256, declared_dependencies, and 100% manifest/executable coverage.
- Click "Submit Challenge" on SG-#001, load the preset omitted executable (`contracts/access/Ownable.sol`), submit the challenge, click "1. Lock Omitted Files", and click "2. Re-Audit Release" to see the release transition to BLOCKED (OMITTED_EXECUTABLE_OR_DEPENDENCY) and the challenge become UPHELD.

3. Run Automated Tests & Local Tree Gate:
Run `python -m unittest discover -s tests/python -v` (10/10 pass) and `corepack pnpm test`.
Run `node cli/skillguard.mjs check OpenZeppelin/openzeppelin-contracts 3e6c86392c97fbc30d3d20a378a6f58beba08eba --demo --dir .` to test local directory tree verification.
```

---

## 06. Expected Outcome & On-Chain Proof

```text
1. Bradbury Phase 2 Deployment (chainId 4221):
- Contract: 0x6AA5b430483d7DfBae3CBEc4e578160DE9504612 (FINALIZED / MAJORITY_AGREE in Block 268801, Protocol Tx 0x401dee443cff3f815efe941b5709f3bdaf2d154062be1d4f920284d247c498d7, L2 Tx 0xf243f48f508760a116c18e2ea7452c1bbbb53e5d0cc5159620c7b3b9b5d3e1c6).
- Proof: artifacts/bradbury-deployment-proof.json (`get_policy_version() == "skillguard/2"`).

2. Full E2E Lifecycle Proof on GenLayer Studio-dev (chainId 61997):
- Contract: 0x1C357d261e5A048FFEdA6Ac79Ea532ebb429DEAe (artifacts/studio-e2e.json).
- Release #1 (Clean Complete Tree Commitment): register_release (0x4dedf854...) -> lock_evidence (0xf9af5bbd...) -> audit_release (0x4a7ef371...) finalized as APPROVED (LOW risk).
- Release #2 (Omitted-Evidence Challenge Path): Publisher omitted contracts/access/Ownable.sol -> Round 1 audit_release (0x327714fb...) -> challenge_release with omitted_sources (0xf8980807...) -> lock_challenge_evidence (0x37f4a8f7...) -> Round 2 audit_release (0xde92ca72...) finalized as BLOCKED (CRITICAL, OMITTED_EXECUTABLE_OR_DEPENDENCY, proven_omitted_paths: ["contracts/access/Ownable.sol"], challenge #1: UPHELD).
```

---

## Contract Link & Proof Links

- **GenLayer Testnet Contract Link**: `https://scan.bradbury.genlayer.com/address/0x6AA5b430483d7DfBae3CBEc4e578160DE9504612`
- **GitHub Repository Proof**: `https://github.com/glieser2/skillguard`
- **Live Demo (GitHub Pages)**: `https://glieser2.github.io/skillguard/`
