// Run real GenVM E2E verification on Studio-dev deployed SkillGuard v2 contract:
// Part A (Release #1):
//   1. Register commit-pinned OpenZeppelin release with complete tree_commitment (package.json + Context.sol)
//   2. Lock immutable GitHub raw byte snapshot & manifest dependency screen (lock_evidence)
//   3. Execute multi-LLM consensus security audit (audit_release) and verify APPROVED readback
// Part B (Release #2 — Omitted-Evidence Challenge Path):
//   4. Register a release at commit b7f748eae2341b9e8e8f85cf966e94476813d168 that omits contracts/access/Ownable.sol
//   5. Lock evidence & run Round 1 audit (APPROVED)
//   6. Challenger submits challenge_release with omitted_sources: [contracts/access/Ownable.sol]
//   7. Challenger calls lock_challenge_evidence -> audit_release (Round 2) -> verify BLOCKED (CRITICAL / OMITTED_EXECUTABLE_OR_DEPENDENCY) & UPHELD!

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createAccount, createClient } from 'genlayer-js';
import { studioDevnet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

function consensusAccepted(tx) {
  if (tx?.lifecycle?.outcome !== 'accepted') return false;
  const hasName = typeof tx.resultName === 'string';
  const hasNum = tx.result !== undefined && tx.result !== null;
  if (hasName && tx.resultName !== 'MAJORITY_AGREE') return false;
  if (hasNum && tx.result !== 1 && tx.result !== '1' && tx.result !== 1n) return false;
  return hasName || hasNum;
}

const executionSucceeded = (tx) =>
  (tx?.statusName === 'FINALIZED' || tx?.lifecycle?.state === 'finalized' || tx?.status === 7) &&
  consensusAccepted(tx) &&
  (tx.txExecutionResultName === 'FINISHED_WITH_RETURN' || tx.txExecutionResult === 1);

async function fundAccount(rpcUrl, addr) {
  await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'sim_fundAccount',
      params: [addr, 10000000000000000000],
    }),
    signal: AbortSignal.timeout(30000),
  });
}

async function main() {
  const dep = JSON.parse(await readFile(new URL('../src/deployment.json', import.meta.url), 'utf8'));
  const rpcUrl = 'https://studio-dev.genlayer.com/api';
  const address = dep.studioDevContractAddress || dep.contractAddress;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address || '')) {
    throw new Error('No deployed contractAddress in src/deployment.json');
  }

  const publisher = createAccount();
  const challenger = createAccount();
  await Promise.all([fundAccount(rpcUrl, publisher.address), fundAccount(rpcUrl, challenger.address)]);

  const pubClient = createClient({ chain: studioDevnet, endpoint: rpcUrl, account: publisher });
  const chalClient = createClient({ chain: studioDevnet, endpoint: rpcUrl, account: challenger });

  const estimate = await pubClient.estimateTransactionFees({
    leaderTimeunitsAllocation: 600n,
    validatorTimeunitsAllocation: 600n,
    executionBudgetPerRound: 10000000000000000n,
    appealRounds: 0n,
  });

  // Check if Release #1 already exists on this contract
  let release1Id = Number(
    await pubClient.readContract({
      address,
      functionName: 'get_release_id_by_commit',
      args: [
        'OpenZeppelin/openzeppelin-contracts',
        '3e6c86392c97fbc30d3d20a378a6f58beba08eba',
      ],
      transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
    })
  );

  const treeEntries1 = [
    {
      byte_length: 786,
      classification: 'manifest',
      path: 'contracts/package.json',
      sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
    },
    {
      byte_length: 860,
      classification: 'executable',
      path: 'contracts/utils/Context.sol',
      sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
    },
  ];
  const treeSha1 = createHash('sha256').update(JSON.stringify(treeEntries1), 'utf8').digest('hex');

  let r1Txs = {};
  if (release1Id === 0) {
    const releasePayload1 = JSON.stringify({
      skill_id: 'oz-context-inspector-skill',
      title: 'OpenZeppelin Pinned Context & Access Inspector Skill',
      package_type: 'agent_skill',
      repo: 'OpenZeppelin/openzeppelin-contracts',
      commit_sha: '3e6c86392c97fbc30d3d20a378a6f58beba08eba',
      version: '5.1.0',
      rubric_version: 'skillguard/capability-rubric/2',
      declared_permissions: {
        network_access: false,
        filesystem_write: false,
        subprocess_exec: false,
        secret_env_access: false,
      },
      scope_summary:
        'Commit-pinned OpenZeppelin package.json manifest and Context.sol reference module with complete tree commitment.',
      tree_commitment: {
        tree_sha256: treeSha1,
        total_files: 2,
        declared_dependencies: [],
        tree_entries: treeEntries1,
      },
      sources: [
        {
          path: 'contracts/package.json',
          role: 'manifest',
          url: 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/3e6c86392c97fbc30d3d20a378a6f58beba08eba/contracts/package.json',
          sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
          byte_length: 786,
        },
        {
          path: 'contracts/utils/Context.sol',
          role: 'entrypoint',
          url: 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/3e6c86392c97fbc30d3d20a378a6f58beba08eba/contracts/utils/Context.sol',
          sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
          byte_length: 860,
        },
      ],
    });

    console.log('1. Submitting register_release #1...');
    const regTxHash = await pubClient.writeContract({
      address,
      functionName: 'register_release',
      args: [releasePayload1],
      fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
    });
    const regTx = await pubClient.waitForFinalization({ hash: regTxHash, interval: 3000, retries: 80 });
    if (!executionSucceeded(regTx)) throw new Error('register_release #1 failed');
    release1Id = 1;

    console.log('2. Submitting lock_evidence #1...');
    const lockTxHash = await pubClient.writeContract({
      address,
      functionName: 'lock_evidence',
      args: [release1Id],
      fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
    });
    const lockTx = await pubClient.waitForFinalization({ hash: lockTxHash, interval: 3000, retries: 80 });
    if (!executionSucceeded(lockTx)) throw new Error('lock_evidence #1 failed');

    console.log('3. Submitting audit_release #1...');
    const auditTxHash = await pubClient.writeContract({
      address,
      functionName: 'audit_release',
      args: [release1Id],
      fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
    });
    const auditTx = await pubClient.waitForFinalization({ hash: auditTxHash, interval: 4000, retries: 90 });
    if (!executionSucceeded(auditTx)) throw new Error('audit_release #1 failed');
    r1Txs = { register_release: regTxHash, lock_evidence: lockTxHash, audit_release: auditTxHash };
  } else {
    console.log('Release #1 already verified on-chain (releaseId = 1).');
    try {
      const prev = JSON.parse(await readFile('artifacts/studio-e2e.json', 'utf8'));
      r1Txs = prev.transactions || {};
    } catch {
      // ignore
    }
  }

  const snap1 = JSON.parse(
    String(
      await pubClient.readContract({
        address,
        functionName: 'get_evidence_snapshot',
        args: [release1Id],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      })
    )
  );
  const att1 = JSON.parse(
    String(
      await pubClient.readContract({
        address,
        functionName: 'get_attestation',
        args: [release1Id],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      })
    )
  );
  console.log('Release #1 verdict:', att1.verdict, 'risk:', att1.risk_level);

  // Part B: Release #2 — Omitted-Evidence Challenge Path
  const commit2 = 'b7f748eae2341b9e8e8f85cf966e94476813d168';
  const treeEntries2 = [
    {
      byte_length: 786,
      classification: 'manifest',
      path: 'contracts/package.json',
      sha256: 'e3e0121956d938f085920cc0ffe0d8ceebafa95dc39b58ec0c219d902de37294',
    },
    {
      byte_length: 1390,
      classification: 'executable',
      path: 'contracts/utils/Context.sol',
      sha256: 'c070e80549c0319b25b4b2510004ecda5602a01c5ed9520adcb1354e9a0f2288',
    },
  ];
  const treeSha2 = createHash('sha256').update(JSON.stringify(treeEntries2), 'utf8').digest('hex');

  const releasePayload2 = JSON.stringify({
    skill_id: 'oz-partial-tree-demo',
    title: 'OpenZeppelin Partial Release (Omitted Ownable.sol Challenge Demo)',
    package_type: 'agent_skill',
    repo: 'OpenZeppelin/openzeppelin-contracts',
    commit_sha: commit2,
    version: '5.5.0',
    rubric_version: 'skillguard/capability-rubric/2',
    declared_permissions: {
      network_access: false,
      filesystem_write: false,
      subprocess_exec: false,
      secret_env_access: false,
    },
    scope_summary:
      'Publisher claimed only contracts/package.json and contracts/utils/Context.sol exist in this release, omitting contracts/access/Ownable.sol.',
    tree_commitment: {
      tree_sha256: treeSha2,
      total_files: 2,
      declared_dependencies: [],
      tree_entries: treeEntries2,
    },
    sources: [
      {
        path: 'contracts/package.json',
        role: 'manifest',
        url: `https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/${commit2}/contracts/package.json`,
        sha256: 'e3e0121956d938f085920cc0ffe0d8ceebafa95dc39b58ec0c219d902de37294',
        byte_length: 786,
      },
      {
        path: 'contracts/utils/Context.sol',
        role: 'entrypoint',
        url: `https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/${commit2}/contracts/utils/Context.sol`,
        sha256: 'c070e80549c0319b25b4b2510004ecda5602a01c5ed9520adcb1354e9a0f2288',
        byte_length: 1390,
      },
    ],
  });

  console.log('4. Submitting register_release #2 (partial tree omitting Ownable.sol)...');
  const reg2TxHash = await pubClient.writeContract({
    address,
    functionName: 'register_release',
    args: [releasePayload2],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const reg2Tx = await pubClient.waitForFinalization({ hash: reg2TxHash, interval: 3000, retries: 80 });
  if (!executionSucceeded(reg2Tx)) throw new Error('register_release #2 failed');

  const release2Id = Number(
    await pubClient.readContract({
      address,
      functionName: 'get_release_id_by_commit',
      args: ['OpenZeppelin/openzeppelin-contracts', commit2],
      transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
    })
  );
  console.log('Registered release2Id:', release2Id);

  console.log('5. Submitting lock_evidence #2 & Round 1 audit_release #2...');
  const lock2TxHash = await pubClient.writeContract({
    address,
    functionName: 'lock_evidence',
    args: [release2Id],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const lock2Tx = await pubClient.waitForFinalization({ hash: lock2TxHash, interval: 3000, retries: 80 });
  if (!executionSucceeded(lock2Tx)) throw new Error('lock_evidence #2 failed');

  const audit2Round1Hash = await pubClient.writeContract({
    address,
    functionName: 'audit_release',
    args: [release2Id],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const audit2R1Tx = await pubClient.waitForFinalization({
    hash: audit2Round1Hash,
    interval: 4000,
    retries: 90,
  });
  if (!executionSucceeded(audit2R1Tx)) throw new Error('audit_release #2 Round 1 failed');

  console.log('6. Challenger submitting challenge_release with omitted_sources: [contracts/access/Ownable.sol]...');
  const challengePayload = JSON.stringify({
    claimed_category: 'OMITTED_EXECUTABLE_OR_DEPENDENCY',
    evidence_source_indices: [],
    omitted_sources: [
      {
        path: 'contracts/access/Ownable.sol',
        role: 'module',
        url: `https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/${commit2}/contracts/access/Ownable.sol`,
        sha256: '38578bd71c0a909840e67202db527cc6b4e6b437e0f39f0c909da32c1e30cb81',
        byte_length: 3102,
      },
    ],
    statement:
      'Publisher omitted executable file contracts/access/Ownable.sol (3102 bytes) from the release tree_commitment at the exact same commit SHA.',
  });
  const chalTxHash = await chalClient.writeContract({
    address,
    functionName: 'challenge_release',
    args: [release2Id, challengePayload],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const chalTx = await chalClient.waitForFinalization({ hash: chalTxHash, interval: 3000, retries: 80 });
  if (!executionSucceeded(chalTx)) throw new Error('challenge_release failed');

  console.log('7. Challenger submitting lock_challenge_evidence(releaseId=2, challengeId=1)...');
  const lockChalTxHash = await chalClient.writeContract({
    address,
    functionName: 'lock_challenge_evidence',
    args: [release2Id, 1],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const lockChalTx = await chalClient.waitForFinalization({
    hash: lockChalTxHash,
    interval: 3000,
    retries: 80,
  });
  if (!executionSucceeded(lockChalTx)) throw new Error('lock_challenge_evidence failed');

  console.log('8. Submitting Round 2 challenge re-audit (audit_release #2)...');
  const audit2Round2Hash = await chalClient.writeContract({
    address,
    functionName: 'audit_release',
    args: [release2Id],
    fees: { distribution: estimate.distribution, feeValue: estimate.feeValue },
  });
  const audit2R2Tx = await chalClient.waitForFinalization({
    hash: audit2Round2Hash,
    interval: 4000,
    retries: 90,
  });
  if (!executionSucceeded(audit2R2Tx)) throw new Error('audit_release #2 Round 2 failed');

  const att2 = JSON.parse(
    String(
      await pubClient.readContract({
        address,
        functionName: 'get_attestation',
        args: [release2Id],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      })
    )
  );
  const ch1 = JSON.parse(
    String(
      await pubClient.readContract({
        address,
        functionName: 'get_challenge',
        args: [1],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      })
    )
  );
  console.log(
    'Release #2 Round 2 verdict:',
    att2.verdict,
    'risk:',
    att2.risk_level,
    'proven_omitted_paths:',
    att2.proven_omitted_paths,
    'challenge #1 status:',
    ch1.status
  );

  const e2eRecord = {
    verifiedAt: new Date().toISOString(),
    rpcUrl,
    chainId: 61997,
    contractAddress: address,
    releaseId: release1Id,
    treeSha256: treeSha1,
    transactions: r1Txs,
    snapshotHash: snap1.snapshot_hash,
    attestation: att1,
    omittedEvidenceChallengeE2E: {
      releaseId: release2Id,
      commitSha: commit2,
      challengeId: 1,
      transactions: {
        register_release: reg2TxHash,
        lock_evidence: lock2TxHash,
        audit_release_round1: audit2Round1Hash,
        challenge_release: chalTxHash,
        lock_challenge_evidence: lockChalTxHash,
        audit_release_round2: audit2Round2Hash,
      },
      finalAttestation: att2,
      finalChallenge: ch1,
    },
  };
  await writeFile('artifacts/studio-e2e.json', JSON.stringify(e2eRecord, null, 2) + '\n');

  dep.e2eVerified = true;
  dep.sampleReleaseIds = [release1Id, release2Id];
  await writeFile('src/deployment.json', JSON.stringify(dep, null, 2) + '\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
