// 领域模型、能力评分表常量、完整目录树承诺（Tree Commitment）计算与客户端确定性校验逻辑

export const POLICY_VERSION = 'skillguard/2';
export const SNAPSHOT_VERSION = 'skillguard/evidence-snapshot/2';
export const RUBRIC_VERSION = 'skillguard/capability-rubric/2';
export const SOURCE_HOST = 'raw.githubusercontent.com';
export const MAX_SOURCE_BYTES = 16384;
export const MAX_SOURCES = 6;

export type CapabilityId =
  | 'network_access'
  | 'filesystem_write'
  | 'subprocess_exec'
  | 'secret_env_access';

export type FindingCategory =
  | 'PROMPT_INJECTION_INSTRUCTION'
  | 'UNDECLARED_CAPABILITY'
  | 'CREDENTIAL_EXFILTRATION'
  | 'REMOTE_CODE_EXECUTION'
  | 'OBFUSCATED_PAYLOAD'
  | 'OMITTED_EXECUTABLE_OR_DEPENDENCY'
  | 'MANIFEST_INSTALL_HOOK';

export type ObservedState = 'OBSERVED' | 'NOT_OBSERVED';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'APPROVED' | 'WARN' | 'BLOCKED' | 'INSUFFICIENT_EVIDENCE';
export type ReleaseStatus =
  | 'REGISTERED'
  | 'EVIDENCE_LOCKED'
  | 'CHALLENGE_EVIDENCE_PENDING'
  | 'CHALLENGED'
  | Verdict;
export type PackageType = 'mcp_server' | 'agent_skill';
export type SourceRole = 'manifest' | 'entrypoint' | 'permissions' | 'module';
export type TreeClassification = 'manifest' | 'executable' | 'documentation' | 'asset';

export interface CapabilityDefinition {
  id: CapabilityId;
  labelEn: string;
  labelZh: string;
  questionEn: string;
  questionZh: string;
}

export const CAPABILITIES: CapabilityDefinition[] = [
  {
    id: 'network_access',
    labelEn: 'Outbound Network / HTTP Access',
    labelZh: '外部网络与 HTTP 请求访问',
    questionEn:
      'Does the code perform outbound HTTP/WebSocket requests, open sockets, or send data externally?',
    questionZh: '被审计源码是否发起外部 HTTP/HTTPS/WebSocket 请求、打开网络套接字或向外部端点传输数据？',
  },
  {
    id: 'filesystem_write',
    labelEn: 'Filesystem Write / Mutation',
    labelZh: '本地文件系统写入或修改',
    questionEn:
      'Does the code write, modify, delete, or create files or directories on the host filesystem?',
    questionZh: '被审计源码是否在宿主机文件系统上写入、修改、删除或创建文件与目录？',
  },
  {
    id: 'subprocess_exec',
    labelEn: 'Subprocess / Shell / Dynamic Code Execution',
    labelZh: '子进程、Shell 命令或动态代码执行',
    questionEn:
      'Does the code spawn subprocesses, execute shell commands, or evaluate dynamic code (eval, exec, child_process)?',
    questionZh: '被审计源码是否派生子进程、执行 Shell 命令或运行动态代码（如 eval、exec、child_process、subprocess）？',
  },
  {
    id: 'secret_env_access',
    labelEn: 'Credentials / Private Key / Sensitive Env Access',
    labelZh: '环境变量凭据、私钥或助记词访问',
    questionEn:
      'Does the code read secret env vars, tokens, wallet files, seed phrases, private keys, or credential stores?',
    questionZh: '被审计源码是否读取含密钥/Token 的环境变量、钱包文件、助记词、私钥或浏览器凭据存储？',
  },
];

export const FINDING_CATEGORY_META: Record<
  FindingCategory,
  { labelEn: string; labelZh: string; severity: 'HIGH' | 'CRITICAL' }
> = {
  PROMPT_INJECTION_INSTRUCTION: {
    labelEn: 'Prompt Injection / Auditor Hijack Instruction',
    labelZh: '提示词注入 / 审计模型劫持指令',
    severity: 'CRITICAL',
  },
  UNDECLARED_CAPABILITY: {
    labelEn: 'Undeclared System Capability Usage',
    labelZh: '使用未声明的系统敏感权限',
    severity: 'HIGH',
  },
  CREDENTIAL_EXFILTRATION: {
    labelEn: 'Credential / Private Key Exfiltration',
    labelZh: '凭据、私钥或助记词窃取外传',
    severity: 'CRITICAL',
  },
  REMOTE_CODE_EXECUTION: {
    labelEn: 'Arbitrary Command / Remote Code Execution',
    labelZh: '任意命令或远程代码执行',
    severity: 'CRITICAL',
  },
  OBFUSCATED_PAYLOAD: {
    labelEn: 'Obfuscated Payload / Covert Telemetry',
    labelZh: '混淆载荷或隐蔽遥测后门',
    severity: 'CRITICAL',
  },
  OMITTED_EXECUTABLE_OR_DEPENDENCY: {
    labelEn: 'Omitted Executable File or Undeclared Dependency',
    labelZh: '遗漏可执行文件或隐瞒未声明/未锁定依赖',
    severity: 'CRITICAL',
  },
  MANIFEST_INSTALL_HOOK: {
    labelEn: 'Dangerous Package Install Hook (preinstall/postinstall)',
    labelZh: '危险包安装生命周期钩子 (preinstall/postinstall)',
    severity: 'CRITICAL',
  },
};

export interface PinnedSource {
  path: string;
  role: SourceRole;
  url: string;
  sha256: string;
  byteLength: number;
  contentPreview?: string;
}

export interface DeclaredDependency {
  name: string;
  version: string;
}

export interface TreeEntry {
  path: string;
  sha256: string;
  byteLength: number;
  classification: TreeClassification;
}

export interface TreeCommitment {
  treeSha256: string;
  totalFiles: number;
  declaredDependencies: DeclaredDependency[];
  treeEntries: TreeEntry[];
}

export type DeclaredPermissions = Record<CapabilityId, boolean>;

export interface ReleaseSpec {
  skillId: string;
  title: string;
  packageType: PackageType;
  repo: string;
  commitSha: string;
  version: string;
  rubricVersion: string;
  declaredPermissions: DeclaredPermissions;
  scopeSummary: string;
  treeCommitment: TreeCommitment;
  sources: PinnedSource[];
}

export interface SourceCheckRecord {
  index: number;
  path: string;
  status: 'VERIFIED' | 'UNAVAILABLE' | 'TOO_LARGE' | 'HASH_MISMATCH' | 'INVALID_ENCODING';
  sha256: string;
  byteLength: number;
}

export interface StaticSignal {
  code: string;
  sourceIndex: number;
}

export interface EvidenceSnapshotRecord {
  snapshotVersion: string;
  snapshotHash: string;
  extraSources?: PinnedSource[];
  provenOmittedPaths?: string[];
  sourceChecks: SourceCheckRecord[];
  staticSignals: StaticSignal[];
  materials: (string | null)[];
  allVerified: boolean;
}

export interface CapabilityCheckRecord {
  capabilityId: CapabilityId;
  state: ObservedState;
  evidenceIndices: number[];
}

export interface AttestationRecord {
  releaseId: number;
  skillId: string;
  repo: string;
  commitSha: string;
  specHash: string;
  snapshotHash: string;
  treeSha256?: string;
  provenOmittedPaths?: string[];
  policyVersion: string;
  rubricVersion: string;
  auditRound: number;
  capabilityChecks: CapabilityCheckRecord[];
  undeclaredCapabilities: CapabilityId[];
  findingCategories: FindingCategory[];
  staticSignals: StaticSignal[];
  declaredVsActualMismatch: boolean;
  riskLevel: RiskLevel;
  verdict: Verdict;
  summary: string;
  evaluatedChallengeIds: number[];
  resolvedChallengeIds: number[];
  sourceChecks: SourceCheckRecord[];
  auditedAt: string;
  scopeDisclaimer: string;
  mode?: 'demo' | 'live';
}

export interface ChallengeRecord {
  id: number;
  releaseId: number;
  challenger: string;
  claimedCategory: FindingCategory;
  evidenceSourceIndices: number[];
  omittedSources?: PinnedSource[];
  verifiedOmittedPaths?: string[];
  evidenceLocked?: boolean;
  statement: string;
  challengeHash: string;
  status: 'OPEN' | 'UPHELD' | 'REJECTED';
  resolvedRound?: number;
  resolvedVerdict?: Verdict;
  createdAt: string;
}

export interface ReleaseOrder {
  id: number;
  submitter: string;
  spec: ReleaseSpec;
  specHash: string;
  policyVersion: string;
  status: ReleaseStatus;
  auditRound: number;
  challengeIds: number[];
  createdAt: string;
  snapshot?: EvidenceSnapshotRecord;
  attestation?: AttestationRecord;
  challenges: ChallengeRecord[];
  origin?: {
    network: string;
    chainId: number;
    contractAddress: string;
  };
}

export interface ConnectionConfig {
  mode: 'demo' | 'live';
  rpcUrl: string;
  contractAddress: string;
}

// 纯 TypeScript 同步 SHA-256 实现，保证浏览器与 Node 端 canonical tree_sha256 与 Python 合约完全一致
const K_SHA256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256Utf8Sync(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const totalLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K_SHA256[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7].map((n) => n.toString(16).padStart(8, '0')).join('');
}

// 根据文件路径推导合约强制要求的分类
export function inferTreeClassification(path: string, role?: SourceRole): TreeClassification {
  const lower = path.trim().toLowerCase();
  const base = lower.split('/').pop() || '';
  if (
    role === 'manifest' ||
    ['package.json', 'pyproject.toml', 'requirements.txt', 'cargo.toml', 'skill.json', 'mcp.json', 'manifest.json'].includes(base)
  ) {
    return 'manifest';
  }
  if (
    ['.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.sh', '.bash', '.ps1', '.sol', '.rs', '.go', '.rb', '.php', '.wasm', '.bin'].some((ext) =>
      lower.endsWith(ext)
    )
  ) {
    return 'executable';
  }
  return 'documentation';
}

// 计算与 Python 合约 digest(norm_entries) 完全一致的 tree_sha256
export function computeTreeSha256Sync(entries: TreeEntry[]): string {
  const canonicalItems = entries.map(
    (e) =>
      `{"byte_length":${Number(e.byteLength)},"classification":${JSON.stringify(
        e.classification
      )},"path":${JSON.stringify(e.path.trim())},"sha256":${JSON.stringify(
        e.sha256.trim().toLowerCase()
      )}}`
  );
  const canonicalJson = `[${canonicalItems.join(',')}]`;
  return sha256Utf8Sync(canonicalJson);
}

// 从固定源码列表与声明依赖构建完整目录树承诺对象
export function buildTreeCommitmentFromSources(
  sources: PinnedSource[],
  declaredDependencies: DeclaredDependency[] = [],
  extraNonExecutableEntries: TreeEntry[] = []
): TreeCommitment {
  const treeEntries: TreeEntry[] = [
    ...sources.map((s) => ({
      path: s.path.trim(),
      sha256: s.sha256.trim().toLowerCase(),
      byteLength: Number(s.byteLength),
      classification: inferTreeClassification(s.path, s.role),
    })),
    ...extraNonExecutableEntries,
  ];
  const sortedDeps = [...declaredDependencies].sort((a, b) => a.name.localeCompare(b.name));
  return {
    treeSha256: computeTreeSha256Sync(treeEntries),
    totalFiles: treeEntries.length,
    declaredDependencies: sortedDeps,
    treeEntries,
  };
}

// 构造固定 commit 的 raw.githubusercontent.com URL
export function buildPinnedRawUrl(repo: string, commitSha: string, path: string): string {
  const cleanRepo = repo.trim().replace(/^\/+|\/+$/g, '');
  const cleanSha = commitSha.trim().toLowerCase();
  const cleanPath = path.trim().replace(/^\/+/, '');
  return `https://raw.githubusercontent.com/${cleanRepo}/${cleanSha}/${cleanPath}`;
}

// 校验固定 commit 源码 URL
export function validatePinnedUrl(url: string, repo?: string, commitSha?: string): string {
  const trimmed = url.trim();
  const match = /^https:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/([0-9a-f]{40})\/([A-Za-z0-9_./-]+)$/.exec(trimmed);
  if (!match) {
    throw new Error('Source URL must follow https://raw.githubusercontent.com/<owner>/<repo>/<40-hex-commit>/<path>');
  }
  if (repo && match[1].toLowerCase() !== repo.trim().toLowerCase()) {
    throw new Error('Source URL repository does not match declared repo');
  }
  if (commitSha && match[2] !== commitSha.trim().toLowerCase()) {
    throw new Error('Source URL commit SHA does not match declared commit_sha');
  }
  return trimmed;
}

// 确定性静态提示词注入与清单扫描（与合约 Python 规则对齐）
const STATIC_PATTERNS: Array<{ code: string; regex: RegExp }> = [
  { code: 'PROMPT_INJECTION_IGNORE', regex: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i },
  { code: 'PROMPT_INJECTION_OVERRIDE', regex: /disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules)/i },
  { code: 'PROMPT_INJECTION_FAKE_SAFE', regex: /you\s+must\s+output\s+["']?(?:low|approved|safe)["']?/i },
  { code: 'PROMPT_INJECTION_SYSTEM_TAG', regex: /<\s*\/?\s*system\s*>/i },
];

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
const UNPINNED_PREFIXES = ['http://', 'https://', 'git+', 'github:', 'file:', 'link:', 'workspace:'];

export function scanStaticSignals(
  materials: (string | null)[],
  sources?: PinnedSource[],
  treeCommitment?: TreeCommitment,
  provenOmittedPaths: string[] = []
): StaticSignal[] {
  const signals: StaticSignal[] = [];
  const depMap = new Map<string, string>(
    (treeCommitment?.declaredDependencies || []).map((d) => [d.name, d.version])
  );

  materials.forEach((content, index) => {
    if (typeof content !== 'string') return;
    for (const item of STATIC_PATTERNS) {
      if (item.regex.test(content)) {
        signals.push({ code: item.code, sourceIndex: index });
      }
    }
    const src = sources?.[index];
    if (src && src.role === 'manifest' && src.path.toLowerCase().endsWith('.json')) {
      try {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          signals.push({ code: 'MANIFEST_JSON_INVALID', sourceIndex: index });
          return;
        }
        const scripts = parsed.scripts as Record<string, unknown> | undefined;
        if (scripts && typeof scripts === 'object') {
          if (INSTALL_HOOKS.some((h) => typeof scripts[h] === 'string' && String(scripts[h]).trim())) {
            signals.push({ code: 'MANIFEST_INSTALL_HOOK', sourceIndex: index });
          }
        }
        if (treeCommitment) {
          const actual = new Map<string, string>();
          for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
            const blk = parsed[field] as Record<string, unknown> | undefined;
            if (blk && typeof blk === 'object') {
              for (const [k, v] of Object.entries(blk)) {
                actual.set(k, String(v).trim());
              }
            }
          }
          let mismatch = actual.size !== depMap.size;
          for (const [k, v] of actual.entries()) {
            const lv = v.toLowerCase();
            if (
              depMap.get(k) !== v ||
              ['*', 'latest', ''].includes(lv) ||
              UNPINNED_PREFIXES.some((p) => lv.startsWith(p))
            ) {
              mismatch = true;
            }
          }
          if (mismatch) {
            signals.push({ code: 'UNDECLARED_OR_UNPINNED_DEPENDENCY', sourceIndex: index });
          }
        }
      } catch {
        signals.push({ code: 'MANIFEST_JSON_INVALID', sourceIndex: index });
      }
    }
  });

  if (
    (treeCommitment?.declaredDependencies || []).some((d) => {
      const lv = d.version.toLowerCase();
      return ['*', 'latest', ''].includes(lv) || UNPINNED_PREFIXES.some((p) => lv.startsWith(p));
    })
  ) {
    signals.push({ code: 'UNDECLARED_OR_UNPINNED_DEPENDENCY', sourceIndex: 0 });
  }
  if (provenOmittedPaths.length > 0) {
    signals.push({ code: 'PROVEN_OMITTED_RELEASE_FILE', sourceIndex: Math.max(0, materials.length - 1) });
  }
  return signals;
}

// 根据能力观测、静态注入信号、清单依赖与挑战补交遗漏文件确定性推导风险等级与裁决
export function deriveRiskAndVerdict(
  declaredPermissions: DeclaredPermissions,
  capabilityChecks: CapabilityCheckRecord[],
  findingCategories: FindingCategory[],
  staticSignals: StaticSignal[],
  provenOmittedPaths: string[] = []
): {
  undeclaredCapabilities: CapabilityId[];
  findingCategories: FindingCategory[];
  declaredVsActualMismatch: boolean;
  riskLevel: RiskLevel;
  verdict: Verdict;
} {
  const undeclared: CapabilityId[] = [];
  for (const check of capabilityChecks) {
    if (check.state === 'OBSERVED' && !declaredPermissions[check.capabilityId]) {
      undeclared.push(check.capabilityId);
    }
  }
  const catSet = new Set<FindingCategory>(findingCategories);
  const codes = new Set(staticSignals.map((s) => s.code));
  if (
    codes.has('PROMPT_INJECTION_IGNORE') ||
    codes.has('PROMPT_INJECTION_OVERRIDE') ||
    codes.has('PROMPT_INJECTION_FAKE_SAFE') ||
    codes.has('PROMPT_INJECTION_SYSTEM_TAG')
  ) {
    catSet.add('PROMPT_INJECTION_INSTRUCTION');
  }
  if (codes.has('MANIFEST_INSTALL_HOOK')) {
    catSet.add('MANIFEST_INSTALL_HOOK');
  }
  if (
    provenOmittedPaths.length > 0 ||
    codes.has('PROVEN_OMITTED_RELEASE_FILE') ||
    codes.has('UNDECLARED_OR_UNPINNED_DEPENDENCY') ||
    codes.has('MANIFEST_JSON_INVALID')
  ) {
    catSet.add('OMITTED_EXECUTABLE_OR_DEPENDENCY');
  }
  if (undeclared.length > 0) catSet.add('UNDECLARED_CAPABILITY');

  const orderedCategories: FindingCategory[] = (
    [
      'PROMPT_INJECTION_INSTRUCTION',
      'UNDECLARED_CAPABILITY',
      'CREDENTIAL_EXFILTRATION',
      'REMOTE_CODE_EXECUTION',
      'OBFUSCATED_PAYLOAD',
      'OMITTED_EXECUTABLE_OR_DEPENDENCY',
      'MANIFEST_INSTALL_HOOK',
    ] as FindingCategory[]
  ).filter((c) => catSet.has(c));

  const criticalSet = new Set<FindingCategory>([
    'CREDENTIAL_EXFILTRATION',
    'REMOTE_CODE_EXECUTION',
    'OBFUSCATED_PAYLOAD',
    'PROMPT_INJECTION_INSTRUCTION',
    'OMITTED_EXECUTABLE_OR_DEPENDENCY',
    'MANIFEST_INSTALL_HOOK',
  ]);
  const hasCriticalCat = orderedCategories.some((c) => criticalSet.has(c));

  let riskLevel: RiskLevel;
  let verdict: Verdict;

  if (
    hasCriticalCat ||
    undeclared.includes('subprocess_exec') ||
    undeclared.includes('secret_env_access')
  ) {
    riskLevel = 'CRITICAL';
    verdict = 'BLOCKED';
  } else if (undeclared.length > 0) {
    riskLevel = 'HIGH';
    verdict = 'BLOCKED';
  } else if (
    capabilityChecks.some(
      (c) =>
        c.state === 'OBSERVED' &&
        ['subprocess_exec', 'secret_env_access', 'filesystem_write'].includes(c.capabilityId)
    )
  ) {
    riskLevel = 'MEDIUM';
    verdict = 'WARN';
  } else {
    riskLevel = 'LOW';
    verdict = 'APPROVED';
  }

  return {
    undeclaredCapabilities: undeclared,
    findingCategories: orderedCategories,
    declaredVsActualMismatch:
      undeclared.length > 0 || catSet.has('OMITTED_EXECUTABLE_OR_DEPENDENCY'),
    riskLevel,
    verdict,
  };
}

// 生成可嵌入 README 的 SVG 徽章与 Markdown 代码
export function generateShieldBadgeMarkdown(release: ReleaseOrder): {
  markdown: string;
  cliCommand: string;
  mcpConfigJson: string;
} {
  const verdict = release.attestation?.verdict || release.status;
  const risk = release.attestation?.riskLevel || 'UNVERIFIED';
  const color =
    verdict === 'APPROVED'
      ? '10b981'
      : verdict === 'WARN'
      ? 'f59e0b'
      : verdict === 'BLOCKED'
      ? 'ef4444'
      : '64748b';
  const shortSha = release.spec.commitSha.slice(0, 8);
  const badgeUrl = `https://img.shields.io/badge/SkillGuard-${encodeURIComponent(
    `${verdict}_${risk}_${shortSha}`
  )}-${color}?style=flat-square`;
  const markdown = `[![SkillGuard Attestation](${badgeUrl})](https://github.com/${release.spec.repo}/tree/${release.spec.commitSha})`;
  const cliCommand = `npx skillguard check ${release.spec.repo}@${release.spec.commitSha} --dir .`;
  const mcpConfigJson = JSON.stringify(
    {
      mcpServers: {
        skillguard: {
          command: 'node',
          args: ['./cli/mcp-server.mjs'],
          env: {
            SKILLGUARD_RPC_URL:
              release.origin?.network === 'bradbury-phase-2'
                ? 'https://rpc-bradbury.genlayer.com'
                : 'https://studio-dev.genlayer.com/api',
            SKILLGUARD_CONTRACT_ADDRESS:
              release.origin?.contractAddress || '0xYourSkillGuardContract',
          },
        },
      },
    },
    null,
    2
  );
  return { markdown, cliCommand, mcpConfigJson };
}
