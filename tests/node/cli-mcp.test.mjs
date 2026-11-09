import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  computeTreeSha256,
  querySkillGuardAttestation,
  verifyLocalDirectoryTree,
} from '../../cli/skillguard.mjs';
import { handleJsonRpcMessage } from '../../cli/mcp-server.mjs';

test('CLI verifier approves verified OpenZeppelin commit and blocks backdoored MCP', async () => {
  const clean = await querySkillGuardAttestation(
    'OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba'
  );
  assert.equal(clean.verdict, 'APPROVED');
  assert.equal(clean.risk_level, 'LOW');

  const blocked = await querySkillGuardAttestation(
    'agent-tools-lab/solana-rebalancer-mcp@7b4e9102aa891234bcde0987654321fedcba0987'
  );
  assert.equal(blocked.verdict, 'BLOCKED');
  assert.equal(blocked.risk_level, 'CRITICAL');
});

test('verifyLocalDirectoryTree approves complete tree and blocks unattested local executable', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'skillguard-tree-'));
  try {
    const pkgBytes = Buffer.from('{"name":"demo","version":"1.0.0"}', 'utf8');
    const idxBytes = Buffer.from('export const ok = true;\n', 'utf8');
    await mkdir(path.join(tmpDir, 'src'), { recursive: true });
    await writeFile(path.join(tmpDir, 'package.json'), pkgBytes);
    await writeFile(path.join(tmpDir, 'src', 'index.ts'), idxBytes);

    const treeEntries = [
      {
        path: 'package.json',
        sha256: createHash('sha256').update(pkgBytes).digest('hex'),
        byte_length: pkgBytes.byteLength,
        classification: 'manifest',
        audited: true,
      },
      {
        path: 'src/index.ts',
        sha256: createHash('sha256').update(idxBytes).digest('hex'),
        byte_length: idxBytes.byteLength,
        classification: 'executable',
        audited: true,
      },
    ];
    const tc = {
      tree_sha256: computeTreeSha256(treeEntries),
      total_files: 2,
      declared_dependencies: [],
      tree_entries: treeEntries,
    };

    const okCheck = await verifyLocalDirectoryTree(tmpDir, tc);
    assert.equal(okCheck.verified, true);
    assert.equal(okCheck.omittedOrMismatchedPaths.length, 0);

    // Add an omitted executable file (`src/hidden_worker.js`) not in tree_entries
    await writeFile(path.join(tmpDir, 'src', 'hidden_worker.js'), 'fetch("https://evil.tld")');
    const failCheck = await verifyLocalDirectoryTree(tmpDir, tc);
    assert.equal(failCheck.verified, false);
    assert.ok(failCheck.omittedOrMismatchedPaths.includes('src/hidden_worker.js'));
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('MCP JSON-RPC server lists tools and executes skillguard_check_attestation', async () => {
  const listRes = await handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/list',
  });
  assert.equal(listRes.result.tools[0].name, 'skillguard_check_attestation');

  const callRes = await handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: {
      name: 'skillguard_check_attestation',
      arguments: {
        target:
          'OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba',
      },
    },
  });
  assert.equal(callRes.result.isError, false);
  const payload = JSON.parse(callRes.result.content[0].text);
  assert.equal(payload.verdict, 'APPROVED');
});
