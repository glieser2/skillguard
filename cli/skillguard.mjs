#!/usr/bin/env node
// SkillGuard v2 Pre-Install CLI Verifier (`npx skillguard check <owner/repo>@<commit_sha> [--dir <local_dir>]`)

import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { createClient } from 'genlayer-js';
import { studionet, studioDevnet, testnetBradbury } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

const EXEC_EXTS = [
  '.py',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.sh',
  '.bash',
  '.ps1',
  '.sol',
  '.rs',
  '.go',
  '.rb',
  '.php',
  '.wasm',
  '.bin',
];
const MANIFEST_NAMES = new Set([
  'package.json',
  'pyproject.toml',
  'requirements.txt',
  'cargo.toml',
  'skill.json',
  'mcp.json',
  'manifest.json',
]);

export function classifyPath(relPath) {
  const lower = String(relPath).toLowerCase();
  const base = lower.split('/').pop() || '';
  if (MANIFEST_NAMES.has(base)) return 'manifest';
  if (EXEC_EXTS.some((ext) => lower.endsWith(ext))) return 'executable';
  return 'documentation';
}

export function computeTreeSha256(treeEntries) {
  const canonical = JSON.stringify(
    treeEntries.map((e) => ({
      byte_length: Number(e.byte_length ?? e.byteLength),
      classification: String(e.classification),
      path: String(e.path),
      sha256: String(e.sha256).toLowerCase(),
    }))
  );
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

const FALLBACK_OPENZEPPELIN_TREE_ENTRIES = [
  {
    path: 'contracts/package.json',
    sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
    byte_length: 786,
    classification: 'manifest',
    audited: true,
  },
  {
    path: 'contracts/utils/Context.sol',
    sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
    byte_length: 860,
    classification: 'executable',
    audited: true,
  },
  {
    path: 'contracts/access/Ownable.sol',
    sha256: '38578bd71c0a909840e67202db527cc6b4e6b437e0f39f0c909da32c1e30cb81',
    byte_length: 3102,
    classification: 'executable',
    audited: true,
  },
];

const FALLBACK_REGISTRY = [
  {
    id: 1,
    skill_id: 'openzeppelin-context-helper',
    repo: 'OpenZeppelin/openzeppelin-contracts',
    commit_sha: '3e6c86392c97fbc30d3d20a378a6f58beba08eba',
    policy_version: 'skillguard/2',
    verdict: 'APPROVED',
    risk_level: 'LOW',
    declared_vs_actual_mismatch: false,
    finding_categories: [],
    tree_commitment: {
      tree_sha256: computeTreeSha256(FALLBACK_OPENZEPPELIN_TREE_ENTRIES),
      total_files: 3,
      declared_dependencies: [],
      tree_entries: FALLBACK_OPENZEPPELIN_TREE_ENTRIES,
    },
    summary:
      'Verified read-only access control reference module with complete release tree commitment and zero undeclared host capabilities.',
  },
  {
    id: 2,
    skill_id: 'solana-wallet-rebalancer-mcp',
    repo: 'agent-tools-lab/solana-rebalancer-mcp',
    commit_sha: '7b4e9102aa891234bcde0987654321fedcba0987',
    policy_version: 'skillguard/2',
    verdict: 'BLOCKED',
    risk_level: 'CRITICAL',
    declared_vs_actual_mismatch: true,
    finding_categories: [
      'PROMPT_INJECTION_INSTRUCTION',
      'UNDECLARED_CAPABILITY',
      'CREDENTIAL_EXFILTRATION',
      'OMITTED_EXECUTABLE_OR_DEPENDENCY',
    ],
    summary:
      'Contains prompt-injection hijack strings, postinstall lifecycle hook, and undeclared SOLANA_PRIVATE_KEY exfiltration.',
  },
  {
    id: 3,
    skill_id: 'git-worktree-sandbox-mcp',
    repo: 'devtools-guild/git-worktree-mcp',
    commit_sha: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    policy_version: 'skillguard/2',
    verdict: 'WARN',
    risk_level: 'MEDIUM',
    declared_vs_actual_mismatch: false,
    finding_categories: [],
    summary: 'Observed filesystem_write and subprocess_exec match declared permissions.',
  },
];

async function walkLocalFiles(rootDir, currentDir = rootDir, acc = []) {
  const entries = await readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await walkLocalFiles(rootDir, fullPath, acc);
    } else if (entry.isFile()) {
      const relPath = path.relative(rootDir, fullPath).split(path.sep).join('/');
      const buf = await readFile(fullPath);
      const sha256 = createHash('sha256').update(buf).digest('hex');
      acc.push({
        path: relPath,
        sha256,
        byte_length: buf.byteLength,
        classification: classifyPath(relPath),
      });
    }
  }
  return acc;
}

// 本地目录树完整性校验：核验本地待安装目录中的所有可执行文件与清单文件是否均已纳入链上 tree_commitment
export async function verifyLocalDirectoryTree(localDir, treeCommitment) {
  if (!treeCommitment || !Array.isArray(treeCommitment.tree_entries)) {
    return {
      verified: false,
      omittedOrMismatchedPaths: ['<missing_tree_commitment>'],
      reason: 'Attestation does not contain a v2 tree_commitment.',
    };
  }
  const expectedTreeSha = computeTreeSha256(treeCommitment.tree_entries);
  if (
    treeCommitment.tree_sha256 &&
    expectedTreeSha !== String(treeCommitment.tree_sha256).toLowerCase()
  ) {
    return {
      verified: false,
      omittedOrMismatchedPaths: ['<tree_sha256_mismatch>'],
      reason: 'On-chain tree_sha256 does not match canonical digest of tree_entries.',
    };
  }

  const entryMap = new Map();
  for (const e of treeCommitment.tree_entries) {
    entryMap.set(String(e.path), {
      sha256: String(e.sha256).toLowerCase(),
      byte_length: Number(e.byte_length ?? e.byteLength),
      classification: String(e.classification),
      audited: Boolean(e.audited),
    });
  }

  const st = await stat(localDir);
  if (!st.isDirectory()) {
    throw new Error(`--dir path is not a directory: ${localDir}`);
  }
  const localFiles = await walkLocalFiles(localDir);
  const omittedOrMismatchedPaths = [];

  for (const lf of localFiles) {
    const committed = entryMap.get(lf.path);
    if (!committed) {
      if (lf.classification === 'executable' || lf.classification === 'manifest') {
        omittedOrMismatchedPaths.push(lf.path);
      }
      continue;
    }
    if (
      committed.sha256 !== lf.sha256 ||
      committed.byte_length !== lf.byte_length ||
      committed.classification !== lf.classification
    ) {
      omittedOrMismatchedPaths.push(lf.path);
    }
  }

  return {
    verified: omittedOrMismatchedPaths.length === 0,
    localFileCount: localFiles.length,
    omittedOrMismatchedPaths,
    treeSha256: expectedTreeSha,
  };
}

async function resolveDeploymentConfig() {
  try {
    const raw = await readFile(new URL('../src/deployment.json', import.meta.url), 'utf8');
    return JSON.parse(raw);
  } catch {
    return { rpcUrl: '', contractAddress: '' };
  }
}

export async function querySkillGuardAttestation(targetSpec, options = {}) {
  const parts = String(targetSpec || '').trim().split('@');
  if (parts.length !== 2 || !parts[0] || !/^[0-9a-fA-F]{7,40}$/.test(parts[1])) {
    throw new Error('Target must be formatted as <owner/repo>@<commit_sha>');
  }
  const repo = parts[0].trim();
  const commitPrefix = parts[1].trim().toLowerCase();

  const dep = await resolveDeploymentConfig();
  const rpcUrl = (options.rpcUrl || process.env.SKILLGUARD_RPC_URL || dep.rpcUrl || '').replace(/\/$/, '');
  const contractAddress =
    options.contractAddress || process.env.SKILLGUARD_CONTRACT_ADDRESS || dep.contractAddress || '';

  let baseResult = null;

  if (rpcUrl && /^0x[a-fA-F0-9]{40}$/.test(contractAddress) && commitPrefix.length === 40) {
    try {
      const chain =
        rpcUrl === 'https://rpc-bradbury.genlayer.com'
          ? testnetBradbury
          : rpcUrl === 'https://studio.genlayer.com/api'
          ? studionet
          : studioDevnet;
      const client = createClient({ chain, endpoint: rpcUrl });
      const releaseIdRaw = await client.readContract({
        address: contractAddress,
        functionName: 'get_release_id_by_commit',
        args: [repo, commitPrefix],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      });
      const releaseId = Number(releaseIdRaw || 0);
      if (releaseId > 0) {
        const [attRaw, relRaw] = await Promise.all([
          client.readContract({
            address: contractAddress,
            functionName: 'get_attestation',
            args: [releaseId],
            transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
          }),
          client.readContract({
            address: contractAddress,
            functionName: 'get_release',
            args: [releaseId],
            transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
          }),
        ]);
        if (attRaw) {
          const parsedAtt = JSON.parse(String(attRaw));
          const parsedRel = relRaw ? JSON.parse(String(relRaw)) : {};
          baseResult = {
            source: 'genlayer-live',
            contractAddress,
            tree_commitment: parsedRel?.spec?.tree_commitment,
            ...parsedAtt,
          };
        }
      }
    } catch {
      // Fallback to local snapshot if chain read fails
    }
  }

  if (!baseResult) {
    const found = FALLBACK_REGISTRY.find(
      (item) =>
        item.repo.toLowerCase() === repo.toLowerCase() &&
        item.commit_sha.startsWith(commitPrefix)
    );
    if (!found) {
      baseResult = {
        source: 'unregistered',
        repo,
        commit_sha: commitPrefix,
        verdict: 'UNVERIFIED',
        risk_level: 'UNKNOWN',
        declared_vs_actual_mismatch: false,
        finding_categories: [],
        summary: 'No attestation found for this repo and commit SHA.',
      };
    } else {
      baseResult = { source: 'local-registry', ...structuredClone(found) };
    }
  }

  if (options.localDir) {
    const treeCheck = await verifyLocalDirectoryTree(options.localDir, baseResult.tree_commitment);
    baseResult.local_tree_verification = treeCheck;
    if (!treeCheck.verified) {
      const cats = new Set(baseResult.finding_categories || []);
      cats.add('OMITTED_EXECUTABLE_OR_DEPENDENCY');
      baseResult.verdict = 'BLOCKED';
      baseResult.risk_level = 'CRITICAL';
      baseResult.finding_categories = [...cats];
      baseResult.summary = `Local directory verification FAILED: omitted or modified executable/manifest files detected (${treeCheck.omittedOrMismatchedPaths.join(', ')}).`;
    }
  }

  return baseResult;
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === '--help' || cmd === '-h') {
    console.log(
      'Usage: skillguard check <owner/repo>@<commit_sha> [--dir <local_dir>] [--json] [--allow-warn]'
    );
    process.exit(0);
  }
  if (cmd !== 'check' || !args[1]) {
    console.error('Error: Expected `skillguard check <owner/repo>@<commit_sha>`');
    process.exit(1);
  }
  const asJson = args.includes('--json');
  const allowWarn = args.includes('--allow-warn');
  const dirIdx = args.indexOf('--dir');
  const localDir = dirIdx >= 0 && args[dirIdx + 1] ? args[dirIdx + 1] : undefined;

  const result = await querySkillGuardAttestation(args[1], { localDir });

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`[SkillGuard] Target:  ${result.repo}@${result.commit_sha}`);
    console.log(`[SkillGuard] Source:  ${result.source}`);
    console.log(`[SkillGuard] Verdict: ${result.verdict} (Risk: ${result.risk_level})`);
    if (result.local_tree_verification) {
      console.log(
        `[SkillGuard] TreeCheck: ${
          result.local_tree_verification.verified ? 'VERIFIED' : 'FAILED (OMITTED FILES)'
        }`
      );
    }
    if (result.finding_categories?.length) {
      console.log(`[SkillGuard] Threats: ${result.finding_categories.join(', ')}`);
    }
    console.log(`[SkillGuard] Summary: ${result.summary}`);
  }

  if (result.verdict === 'APPROVED' || (allowWarn && result.verdict === 'WARN')) {
    process.exit(0);
  }
  process.exit(2);
}

if (
  import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` ||
  process.argv[1]?.endsWith('skillguard.mjs')
) {
  main().catch((err) => {
    console.error('[SkillGuard Error]', err.message || err);
    process.exit(1);
  });
}
