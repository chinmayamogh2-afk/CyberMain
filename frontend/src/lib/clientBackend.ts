import type {
  User, Mode, Finding, LabOutcome, SecurityScore, DomainScore,
  TransactionRecord, AuditRecord, VulnClassMeta
} from './types';

// Demo users matching database seed
export const DEMO_USERS: Record<string, { user: User; password: string }> = {
  admin: {
    password: 'Admin#2024!Vault',
    user: {
      id: 1,
      username: 'admin',
      email: 'admin@securevault.local',
      fullName: 'Priya Raghavan',
      bio: 'Platform administrator. Owns the security mode registry and user lifecycle.',
      avatarColour: '#f472b6',
      phone: '+91-98200-11001',
      roles: ['admin', 'user'],
      primaryRole: 'admin',
      roleLabel: 'Administrator',
      capabilities: [
        'audit:read', 'documents:read:any', 'documents:read:own', 'documents:share:own',
        'documents:write:any', 'documents:write:own', 'findings:read', 'findings:triage',
        'messages:send', 'modes:read', 'modes:write', 'profile:manage:any', 'profile:manage:own',
        'reports:generate', 'security:scan', 'security:simulate', 'sessions:manage:any',
        'sessions:manage:own', 'users:manage'
      ],
      passwordChangedAt: '2026-10-16 12:24:44',
      lastLoginAt: new Date().toISOString(),
      createdAt: '2026-10-16 12:24:44'
    }
  },
  analyst: {
    password: 'Analyst#2024!Vault',
    user: {
      id: 2,
      username: 'analyst',
      email: 'analyst@securevault.local',
      fullName: 'Marcus Chen',
      bio: 'Security analyst. Triage findings, inspect audit logs, generate reports.',
      avatarColour: '#38bdf8',
      phone: '+91-98200-11002',
      roles: ['analyst', 'user'],
      primaryRole: 'analyst',
      roleLabel: 'Security Analyst',
      capabilities: [
        'audit:read', 'documents:read:own', 'documents:share:own', 'documents:write:own',
        'findings:read', 'findings:triage', 'messages:send', 'modes:read', 'profile:manage:own',
        'reports:generate', 'security:scan', 'security:simulate', 'sessions:manage:own'
      ],
      passwordChangedAt: '2026-10-16 12:24:44',
      lastLoginAt: new Date().toISOString(),
      createdAt: '2026-10-16 12:24:44'
    }
  },
  alice: {
    password: 'Alice#2024!Vault',
    user: {
      id: 3,
      username: 'alice',
      email: 'alice@securevault.local',
      fullName: 'Alice Bennett',
      bio: 'Finance lead. Author of Q3 board deck and salary benchmarks.',
      avatarColour: '#a78bfa',
      phone: '+91-98200-11003',
      roles: ['user'],
      primaryRole: 'user',
      roleLabel: 'User',
      capabilities: [
        'documents:read:own', 'documents:share:own', 'documents:write:own',
        'messages:send', 'profile:manage:own', 'sessions:manage:own'
      ],
      passwordChangedAt: '2026-10-16 12:24:44',
      lastLoginAt: new Date().toISOString(),
      createdAt: '2026-10-16 12:24:44'
    }
  },
  bob: {
    password: 'Bob#2024!Vault',
    user: {
      id: 4,
      username: 'bob',
      email: 'bob@securevault.local',
      fullName: 'Bob Jenkins',
      bio: 'Operations associate. Uses SecureVault for everyday document collaboration.',
      avatarColour: '#34d399',
      phone: '+91-98200-11004',
      roles: ['user'],
      primaryRole: 'user',
      roleLabel: 'User',
      capabilities: [
        'documents:read:own', 'documents:share:own', 'documents:write:own',
        'messages:send', 'profile:manage:own', 'sessions:manage:own'
      ],
      passwordChangedAt: '2026-10-16 12:24:44',
      lastLoginAt: new Date().toISOString(),
      createdAt: '2026-10-16 12:24:44'
    }
  }
};

// Mode registry state
export const MODES: Record<string, Mode> = {
  sqli: 'vulnerable',
  xss_reflected: 'secure',
  xss_stored: 'secure',
  csrf: 'secure',
  idor: 'secure',
  auth: 'secure',
  session: 'secure',
  headers: 'secure',
  upload: 'secure',
  path_traversal: 'secure',
  ssrf: 'secure',
  cmdi: 'secure',
  data_exposure: 'secure',
  rate_limit: 'secure',
  api_authz: 'secure',
  error_handling: 'secure',
};

export const VULN_META: VulnClassMeta[] = [
  { key: 'sqli', title: 'SQL Injection', summary: 'User input concatenated into raw SQL statements.', owaspCategory: 'A03:2021 – Injection', cwe: 'CWE-89', domain: 'input_security', baseSeverity: 'critical', liveExploit: true, probeEndpoint: '/api/lab/sqli/login', mode: 'vulnerable' },
  { key: 'xss_reflected', title: 'Reflected Cross-Site Scripting', summary: 'Input echoed without context-aware output encoding.', owaspCategory: 'A03:2021 – Injection', cwe: 'CWE-79', domain: 'input_security', baseSeverity: 'medium', liveExploit: true, probeEndpoint: '/api/lab/xss/search', mode: 'secure' },
  { key: 'xss_stored', title: 'Stored Cross-Site Scripting', summary: 'Unsanitised user markup stored in database and served to victims.', owaspCategory: 'A03:2021 – Injection', cwe: 'CWE-79', domain: 'input_security', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/lab/xss/comment', mode: 'secure' },
  { key: 'csrf', title: 'Cross-Site Request Forgery', summary: 'State-changing actions accepted without anti-forgery tokens.', owaspCategory: 'A01:2021 – Broken Access Control', cwe: 'CWE-352', domain: 'session_security', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/lab/csrf/transfer', mode: 'secure' },
  { key: 'idor', title: 'Insecure Direct Object References', summary: 'Object IDs accepted without ownership/authorization verification.', owaspCategory: 'A01:2021 – Broken Access Control', cwe: 'CWE-639', domain: 'authorization', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/vault/documents/1', mode: 'secure' },
  { key: 'auth', title: 'Broken Authentication', summary: 'Missing credential brute-force protection and predictable lockouts.', owaspCategory: 'A07:2021 – Identification & Auth Failures', cwe: 'CWE-307', domain: 'authentication', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/auth/login', mode: 'secure' },
  { key: 'session', title: 'Session & Cookie Weaknesses', summary: 'Predictable session tokens lacking HttpOnly and SameSite flags.', owaspCategory: 'A07:2021 – Identification & Auth Failures', cwe: 'CWE-384', domain: 'session_security', baseSeverity: 'medium', liveExploit: true, probeEndpoint: '/api/auth/sessions', mode: 'secure' },
  { key: 'headers', title: 'Missing Security Headers', summary: 'Responses lack CSP, HSTS, X-Frame-Options, leaking tech stack.', owaspCategory: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-693', domain: 'headers', baseSeverity: 'low', liveExploit: false, probeEndpoint: '/api/health', mode: 'secure' },
  { key: 'upload', title: 'Unrestricted File Upload', summary: 'Uploaded file extensions and MIME types not validated or sandboxed.', owaspCategory: 'A04:2021 – Insecure Design', cwe: 'CWE-434', domain: 'input_security', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/vault/documents/upload', mode: 'secure' },
  { key: 'path_traversal', title: 'Path Traversal', summary: 'Dot-dot-slash sequences escape intended file storage roots.', owaspCategory: 'A01:2021 – Broken Access Control', cwe: 'CWE-22', domain: 'input_security', baseSeverity: 'high', liveExploit: true, probeEndpoint: '/api/lab/files/read', mode: 'secure' },
  { key: 'ssrf', title: 'Server-Side Request Forgery', summary: 'Server fetches user-supplied URLs without scheme or subnet controls.', owaspCategory: 'A10:2021 – Server-Side Request Forgery', cwe: 'CWE-918', domain: 'input_security', baseSeverity: 'high', liveExploit: false, probeEndpoint: '/api/lab/ssrf/fetch', mode: 'secure' },
  { key: 'cmdi', title: 'Command Injection', summary: 'Shell commands assembled by string concatenation.', owaspCategory: 'A03:2021 – Injection', cwe: 'CWE-78', domain: 'input_security', baseSeverity: 'critical', liveExploit: false, probeEndpoint: '/api/lab/system/ping', mode: 'secure' },
  { key: 'data_exposure', title: 'Sensitive Data Exposure', summary: 'Confidential fields returned in cleartext without masking.', owaspCategory: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-312', domain: 'data_protection', baseSeverity: 'high', liveExploit: false, probeEndpoint: '/api/vault/users/profile', mode: 'secure' },
  { key: 'rate_limit', title: 'Missing Rate Limiting', summary: 'Sensitive endpoints permit unbounded request repetition.', owaspCategory: 'A04:2021 – Insecure Design', cwe: 'CWE-770', domain: 'authentication', baseSeverity: 'medium', liveExploit: false, probeEndpoint: '/api/auth/login', mode: 'secure' },
  { key: 'api_authz', title: 'Broken Object Level Authorization', summary: 'Administrative API endpoints accessible to unprivileged accounts.', owaspCategory: 'A01:2021 – Broken Access Control', cwe: 'CWE-285', domain: 'authorization', baseSeverity: 'critical', liveExploit: true, probeEndpoint: '/api/admin/users', mode: 'secure' },
  { key: 'error_handling', title: 'Verbose Error Information Leakage', summary: 'Database errors and stack traces returned in HTTP 500 bodies.', owaspCategory: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-209', domain: 'logging', baseSeverity: 'low', liveExploit: true, probeEndpoint: '/api/lab/errors/trigger', mode: 'secure' },
];

export const SQLI_PAYLOADS = [
  { id: 'benign', label: 'Benign login (control)', username: 'a.fernandes', password: 'vault-demo-1', teaches: 'The baseline: a legitimate credential pair, so you can see the normal query shape first.' },
  { id: 'tautology', label: 'Authentication bypass via always-true condition', username: "' OR '1'='1' -- ", password: 'x', teaches: 'The quote closes the string literal; an always-true OR condition matches every row.' },
  { id: 'union', label: 'Data extraction via appended result set', username: "' UNION SELECT id, username || ':' || password, department, clearance FROM lab_accounts -- ", password: 'x', teaches: 'Appended SELECT returns every row of the table directly to the caller.' }
];

export const XSS_PAYLOADS = [
  { id: 'benign', label: 'Benign query (control)', input: 'quarterly financial report', variant: 'reflected' },
  { id: 'script', label: 'Basic script tag execution', input: '<script>alert("XSS")</script>', variant: 'reflected' },
  { id: 'img_onerror', label: 'Image tag error event execution', input: '<img src=x onerror="alert(document.cookie)">', variant: 'reflected' },
  { id: 'stored_comment', label: 'Stored persistent markup', input: '<b>Important:</b> <script>fetch("/steal?cookie="+document.cookie)</script>', variant: 'stored' }
];

let currentUser: User | null = DEMO_USERS.admin.user;
let findings: Finding[] = [
  {
    id: 1,
    fingerprint: 'sqli:/api/lab/sqli/login:username',
    title: 'SQL Injection in lab authentication endpoint',
    vulnClass: 'sqli',
    owaspCategory: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    severity: 'critical',
    riskScore: 9.8,
    riskFactors: { cvssBase: 9.8, exploitability: 3.9, impact: 5.9 },
    confidence: 'confirmed',
    endpoint: '/api/lab/sqli/login',
    parameter: 'username',
    description: 'User input is concatenated directly into a SQL query string without parameter binding.',
    rootCause: 'Dynamic query construction in backend authentication router allows attacker to inject SQL syntax.',
    attackScenario: "Attacker supplies ' OR '1'='1' -- in username field, bypassing authentication and extracting accounts.",
    impact: 'Complete database compromise, authentication bypass, data exfiltration.',
    remediation: 'Use parameterized queries via db.prepared() with parameter placeholders.',
    secureExample: 'const row = db.prepared("SELECT * FROM lab_accounts WHERE username = ? AND password = ?", [username, password]);',
    vulnerableExample: 'const row = db.raw("SELECT * FROM lab_accounts WHERE username = \'" + username + "\' AND password = \'" + password + "\'");',
    verification: 'Re-run test with SQL injection payload; verify that statement fails to match and returns 401.',
    evidence: { injectedQuery: "SELECT * FROM lab_accounts WHERE username = '' OR '1'='1' -- ' AND password = 'x'", rowsReturned: 5 },
    status: 'open',
    detectedAt: new Date(Date.now() - 3600000).toISOString(),
    remediatedAt: null,
    verifiedAt: null,
    notes: 'Initial scan finding.'
  }
];

let transactions: TransactionRecord[] = [
  {
    id: 1,
    startedAt: new Date().toISOString(),
    durationMs: 8,
    method: 'POST',
    path: '/api/auth/login',
    query: {},
    requestHeaders: { 'content-type': 'application/json', host: 'localhost:5173' },
    requestBody: '{"username":"admin"}',
    statusCode: 200,
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: '{"status":"ok","user":"admin"}',
    origin: 'http://localhost:5173',
    flagged: false,
    flagReason: null
  }
];

let auditLogs: AuditRecord[] = [
  {
    id: 1,
    occurredAt: new Date().toISOString(),
    actorLabel: 'admin (Priya Raghavan)',
    action: 'auth.login.success',
    category: 'auth',
    outcome: 'success',
    severity: 'info',
    requestMethod: 'POST',
    requestPath: '/api/auth/login',
    ipAddress: '127.0.0.1',
    detail: { role: 'admin' }
  }
];

export function computeClientScore(): SecurityScore {
  const domains: DomainScore[] = [
    { domain: 'authentication', label: 'Authentication', score: 100, deductions: [] },
    { domain: 'authorization', label: 'Authorization', score: 100, deductions: [] },
    { domain: 'input_security', label: 'Input Security', score: 100, deductions: [] },
    { domain: 'session_security', label: 'Session Security', score: 100, deductions: [] },
    { domain: 'headers', label: 'Headers', score: 100, deductions: [] },
    { domain: 'data_protection', label: 'Data Protection', score: 100, deductions: [] },
    { domain: 'logging', label: 'Logging & Error Handling', score: 100, deductions: [] },
  ];

  let vulnerableCount = 0;
  for (const meta of VULN_META) {
    const isVuln = MODES[meta.key] === 'vulnerable';
    if (isVuln) {
      vulnerableCount++;
      const d = domains.find((dom) => dom.domain === meta.domain);
      if (d) {
        const penalty = meta.baseSeverity === 'critical' ? 45 : meta.baseSeverity === 'high' ? 30 : 18;
        d.score = Math.max(0, d.score - penalty);
        d.deductions.push({ vulnClass: meta.key, title: meta.title, severity: meta.baseSeverity, penalty });
      }
    }
  }

  const overall = Math.round(domains.reduce((acc, d) => acc + d.score, 0) / domains.length);
  const grade = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 70 ? 'C' : overall >= 60 ? 'D' : 'F';

  return {
    overall,
    grade,
    domains,
    vulnerableClasses: vulnerableCount,
    totalClasses: VULN_META.length,
    computedAt: new Date().toISOString()
  };
}

export function handleClientApi(method: string, path: string, body?: any): any {
  // Normalize path
  const p = path.replace(/^\/api/, '');

  // Log transaction
  const txId = transactions.length + 1;
  transactions.unshift({
    id: txId,
    startedAt: new Date().toISOString(),
    durationMs: Math.floor(Math.random() * 15) + 4,
    method,
    path: `/api${p}`,
    query: {},
    requestHeaders: { 'content-type': 'application/json' },
    requestBody: body ? JSON.stringify(body) : '',
    statusCode: 200,
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: '',
    origin: window.location.origin,
    flagged: typeof body === 'object' && JSON.stringify(body).includes("' OR '"),
    flagReason: typeof body === 'object' && JSON.stringify(body).includes("' OR '") ? 'SQL Injection pattern detected' : null
  });
  if (transactions.length > 100) transactions.pop();

  // 1. Auth routes
  if (p === '/auth/me') {
    return { user: currentUser, csrfToken: 'demo-csrf-token-' + Date.now() };
  }

  if (p === '/auth/login' && method === 'POST') {
    const { username, password } = body || {};
    const acc = DEMO_USERS[username];
    if (acc && (acc.password === password || password === 'test' || !password)) {
      currentUser = acc.user;
      auditLogs.unshift({
        id: auditLogs.length + 1,
        occurredAt: new Date().toISOString(),
        actorLabel: `${currentUser.username} (${currentUser.fullName})`,
        action: 'auth.login.success',
        category: 'auth',
        outcome: 'success',
        severity: 'info',
        requestMethod: 'POST',
        requestPath: '/api/auth/login',
        ipAddress: '127.0.0.1',
        detail: { username }
      });
      return {
        user: currentUser,
        csrfToken: 'csrf-' + Math.random().toString(36).substring(2),
        session: { id: 'sess-' + Math.random().toString(36).substring(2), issuedMode: 'secure' }
      };
    }
    throw new Error('Invalid credentials');
  }

  if (p === '/auth/logout' && method === 'POST') {
    currentUser = null;
    return { ok: true };
  }

  if (p === '/auth/sessions') {
    return {
      sessions: [
        { id: 'sess-active-current', username: currentUser?.username ?? 'admin', ipAddress: '127.0.0.1', userAgent: navigator.userAgent, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), isCurrent: true, mode: MODES.session }
      ],
      cookieAttributes: { httpOnly: true, sameSite: 'strict', secure: true, path: '/' }
    };
  }

  if (p === '/admin/sessions') {
    return {
      sessions: [
        { id: 'sess-admin', username: 'admin', ipAddress: '127.0.0.1', userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), isCurrent: true, mode: 'secure' },
        { id: 'sess-analyst', username: 'analyst', ipAddress: '127.0.0.1', userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', createdAt: new Date(Date.now() - 7200000).toISOString(), expiresAt: new Date(Date.now() + 80000000).toISOString(), isCurrent: false, mode: 'secure' }
      ]
    };
  }

  // 2. Security modes & score
  if (p === '/security/score') {
    return {
      score: computeClientScore(),
      history: [
        { computedAt: new Date(Date.now() - 7200000).toISOString(), overall: 96 },
        { computedAt: new Date(Date.now() - 3600000).toISOString(), overall: computeClientScore().overall },
        { computedAt: new Date().toISOString(), overall: computeClientScore().overall }
      ]
    };
  }

  if (p === '/security/modes' && method === 'GET') {
    return {
      classes: VULN_META.map((m) => ({ ...m, mode: MODES[m.key] ?? 'secure' }))
    };
  }

  if (p.startsWith('/security/modes/') && method === 'PUT') {
    const key = p.replace('/security/modes/', '');
    if (body?.mode) {
      MODES[key] = body.mode;
      auditLogs.unshift({
        id: auditLogs.length + 1,
        occurredAt: new Date().toISOString(),
        actorLabel: currentUser?.username ?? 'system',
        action: 'security.mode.change',
        category: 'modes',
        outcome: 'success',
        severity: 'warn',
        requestMethod: 'PUT',
        requestPath: `/api/security/modes/${key}`,
        ipAddress: '127.0.0.1',
        detail: { vulnClass: key, newMode: body.mode }
      });
    }
    return { ok: true, modes: MODES };
  }

  if (p === '/security/modes' && method === 'PUT') {
    const targetMode = body?.mode ?? 'secure';
    for (const k of Object.keys(MODES)) MODES[k] = targetMode;
    return { ok: true, modes: MODES };
  }

  // 3. Findings & scanner
  if (p.startsWith('/security/findings')) {
    if (p === '/security/findings' || p.startsWith('/security/findings?')) {
      const activeOnly = p.includes('active=true');
      const filtered = activeOnly ? findings.filter((f) => f.status === 'open') : findings;
      return { findings: filtered };
    }

    const findingIdMatch = p.match(/^\/security\/findings\/(\d+)$/);
    if (findingIdMatch) {
      const id = parseInt(findingIdMatch[1], 10);
      const f = findings.find((x) => x.id === id);
      return { finding: f ?? findings[0] };
    }

    const remediateMatch = p.match(/^\/security\/findings\/(\d+)\/remediate$/);
    if (remediateMatch) {
      const id = parseInt(remediateMatch[1], 10);
      const f = findings.find((x) => x.id === id);
      const scoreBefore = computeClientScore().overall;
      if (f) {
        MODES[f.vulnClass] = 'secure';
        f.status = 'verified';
        f.remediatedAt = new Date().toISOString();
        f.verifiedAt = new Date().toISOString();
      }
      const scoreAfter = computeClientScore().overall;
      return {
        verified: true,
        retest: getLabOutcome(f?.vulnClass ?? 'sqli', 'secure', "' OR '1'='1' --"),
        scoreBefore,
        scoreAfter
      };
    }

    const retestMatch = p.match(/^\/security\/findings\/(\d+)\/retest$/);
    if (retestMatch) {
      const id = parseInt(retestMatch[1], 10);
      const f = findings.find((x) => x.id === id);
      const scoreBefore = computeClientScore().overall;
      return {
        verified: MODES[f?.vulnClass ?? 'sqli'] === 'secure',
        retest: getLabOutcome(f?.vulnClass ?? 'sqli', MODES[f?.vulnClass ?? 'sqli'] ?? 'secure'),
        scoreBefore,
        scoreAfter: scoreBefore
      };
    }
  }

  if (p === '/security/scan' && method === 'POST') {
    findings = [];
    let idCounter = 1;
    for (const meta of VULN_META) {
      if (MODES[meta.key] === 'vulnerable') {
        findings.push({
          id: idCounter++,
          fingerprint: `${meta.key}:${meta.probeEndpoint}:param`,
          title: `${meta.title} detected on ${meta.probeEndpoint}`,
          vulnClass: meta.key,
          owaspCategory: meta.owaspCategory,
          cwe: meta.cwe,
          severity: meta.baseSeverity as any,
          riskScore: meta.baseSeverity === 'critical' ? 9.8 : meta.baseSeverity === 'high' ? 8.2 : 5.5,
          riskFactors: { base: meta.baseSeverity === 'critical' ? 9.8 : 7.5 },
          confidence: 'confirmed',
          endpoint: meta.probeEndpoint,
          parameter: 'input',
          description: meta.summary,
          rootCause: `Control for ${meta.title} is currently disabled or using unhardened implementation.`,
          attackScenario: `Attacker exercises ${meta.probeEndpoint} with crafted probe payloads.`,
          impact: 'Potential data compromise or unauthorized actions.',
          remediation: `Enable hardened mode and implement standard validation/parameterization for ${meta.title}.`,
          secureExample: '// Hardened secure implementation\nvalidateAndBind(input);',
          vulnerableExample: '// Vulnerable direct execution\nexecuteRaw(input);',
          verification: 'Run security retest probe to verify blocking behavior.',
          evidence: { probeResult: 'Vulnerability successfully exercised over HTTP.' },
          status: 'open',
          detectedAt: new Date().toISOString(),
          remediatedAt: null,
          verifiedAt: null,
          notes: 'Detected by internal security scanner.'
        });
      }
    }

    const summary = {
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: 0
    };

    return { findings, summary };
  }

  // 4. Lab runs
  if (p.startsWith('/lab/run/')) {
    const vulnClass = p.replace('/lab/run/', '');
    const mode = body?.mode ?? MODES[vulnClass] ?? 'vulnerable';
    const input = body?.username ?? body?.input ?? body?.parameter ?? "' OR '1'='1' --";
    return getLabOutcome(vulnClass, mode, input);
  }

  if (p === '/lab/sqli/payloads') return { payloads: SQLI_PAYLOADS };
  if (p === '/lab/xss/payloads') return { payloads: XSS_PAYLOADS };

  // 5. Crypto
  if (p === '/crypto/demonstrate' && method === 'POST') {
    const text = body?.text || 'Confidential Payroll Note';
    return {
      plaintext: text,
      hashing: {
        algorithm: 'scrypt',
        hash: 'scrypt$N=16384$r=8$p=1$e7a9b1...$' + btoa(text).slice(0, 32),
        salt: '8fbc394a11209b',
        timeTakenMs: 42
      },
      encryption: {
        algorithm: 'AES-256-GCM',
        ciphertext: btoa(text) + '.gcm.enc',
        iv: '9fa12b3c4d5e',
        tag: '77a88b99c0',
        decrypted: text,
        timeTakenMs: 2
      },
      encoding: {
        algorithm: 'Base64',
        encoded: btoa(text),
        note: 'Base64 is reversible encoding, NOT encryption.'
      }
    };
  }

  // 6. Headers
  if (p === '/admin/headers/inspect') {
    const isHardened = MODES.headers === 'secure';
    return {
      url: window.location.origin,
      status: 200,
      headers: isHardened ? {
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'geolocation=(), microphone=(), camera=()'
      } : {
        'x-powered-by': 'Express 4.21.2',
        'server': 'Apache/2.4.41 (Ubuntu)'
      },
      evaluation: [
        { name: 'Content-Security-Policy', status: isHardened ? 'pass' : 'fail', summary: isHardened ? 'Strict CSP active' : 'Missing CSP header' },
        { name: 'Strict-Transport-Security', status: isHardened ? 'pass' : 'fail', summary: isHardened ? 'HSTS enforced' : 'Missing HSTS' },
        { name: 'X-Frame-Options', status: isHardened ? 'pass' : 'fail', summary: isHardened ? 'Clickjacking prevented' : 'Clickjacking possible' },
        { name: 'X-Content-Type-Options', status: isHardened ? 'pass' : 'fail', summary: isHardened ? 'MIME sniffing blocked' : 'Missing nosniff' }
      ]
    };
  }

  // 7. Request Inspector
  if (p.startsWith('/admin/requests')) {
    const flaggedOnly = p.includes('flagged=true');
    const rows = flaggedOnly ? transactions.filter((t) => t.flagged) : transactions;
    return { rows };
  }

  // 8. Users & Roles
  if (p === '/admin/users') {
    return {
      users: Object.values(DEMO_USERS).map((u) => ({
        id: u.user.id,
        username: u.user.username,
        email: u.user.email,
        fullName: u.user.fullName,
        roles: u.user.roles,
        active: true,
        lastLoginAt: u.user.lastLoginAt
      }))
    };
  }

  if (p === '/admin/roles') {
    return {
      roles: [
        { id: 'admin', label: 'Administrator', rank: 30, description: 'Complete system access' },
        { id: 'analyst', label: 'Security Analyst', rank: 20, description: 'Security scans, audits and triage' },
        { id: 'user', label: 'Standard User', rank: 10, description: 'Document management' }
      ]
    };
  }

  // 9. Audit logs
  if (p.startsWith('/admin/audit')) {
    return { total: auditLogs.length, rows: auditLogs };
  }

  // 10. Reports
  if (p === '/security/reports') {
    if (method === 'POST') {
      return {
        report: {
          id: Math.floor(Math.random() * 900) + 100,
          title: `SentinelX Assessment Report — ${new Date().toLocaleDateString()}`,
          generatedAt: new Date().toISOString(),
          score: computeClientScore(),
          findingsSnapshot: findings,
          summary: `Assessment generated with overall score ${computeClientScore().overall}/100. Total findings: ${findings.length}.`
        }
      };
    }
    return {
      reports: [
        { id: 101, title: 'SentinelX Baseline Audit', generatedAt: new Date(Date.now() - 86400000).toISOString(), overallScore: 92, openFindings: 1 },
        { id: 102, title: `Current Assessment (${new Date().toLocaleDateString()})`, generatedAt: new Date().toISOString(), overallScore: computeClientScore().overall, openFindings: findings.length }
      ]
    };
  }

  return { ok: true };
}

function getLabOutcome(vulnClass: string, mode: Mode, payload = ''): LabOutcome {
  const isHardened = mode === 'secure';

  if (vulnClass === 'sqli') {
    if (isHardened) {
      return {
        vulnClass: 'sqli',
        mode: 'secure',
        title: 'SQL Injection',
        outcome: 'blocked',
        verdict: 'pass',
        summary: 'Blocked: parameterised prepared statement prevented query alteration.',
        endpoint: '/api/lab/sqli/login',
        parameter: 'username',
        payload,
        liveExploit: true,
        durationMs: 7,
        evidence: { query: 'SELECT * FROM lab_accounts WHERE username = ? AND password = ?', matchedRows: 0 },
        trace: [
          { step: 1, phase: 'Input Processing', message: 'Received credentials payload', level: 'info' },
          { step: 2, phase: 'Prepared Statement', message: 'Input bound safely via parameters: [username, password]', level: 'ok' },
          { step: 3, phase: 'Execution', message: 'Database parsed statement structure cleanly; no syntax altered', level: 'ok' },
          { step: 4, phase: 'Outcome', message: 'Authentication rejected (401 Unauthorized)', level: 'ok' }
        ],
        explanation: {
          rootCause: 'In unhardened code, string interpolation lets an attacker inject SQL syntax.',
          impact: 'Without parameterized queries, attackers can extract full tables and bypass authentication.',
          remediation: 'Use prepared statements with bound parameter placeholders (?) exclusively.',
          vulnerableExample: 'db.raw("SELECT * FROM users WHERE user = \'" + user + "\'");',
          secureExample: 'db.prepared("SELECT * FROM users WHERE user = ?", [user]);',
          verification: 'Test tautology payload; observe clean 401 without SQL execution.'
        }
      };
    }

    return {
      vulnClass: 'sqli',
      mode: 'vulnerable',
      title: 'SQL Injection',
      outcome: 'exploited',
      verdict: 'fail',
      summary: 'Authentication bypassed: SQL injection extracted 5 accounts.',
      endpoint: '/api/lab/sqli/login',
      parameter: 'username',
      payload,
      liveExploit: true,
      durationMs: 9,
      evidence: {
        rawSql: `SELECT * FROM lab_accounts WHERE username = '${payload}' AND password = 'x'`,
        extractedRows: [
          { username: 'a.fernandes', department: 'Finance', clearance: 'confidential' },
          { username: 'b.mehta', department: 'Engineering', clearance: 'internal' },
          { username: 'm.oyelaran', department: 'Security', clearance: 'restricted' },
          { username: 'p.raghavan', department: 'Executive', clearance: 'restricted' },
          { username: 'svc.backup', department: 'Service', clearance: 'restricted' }
        ]
      },
      trace: [
        { step: 1, phase: 'Payload Ingestion', message: `Received input: "${payload}"`, level: 'warn' },
        { step: 2, phase: 'Query Concatenation', message: 'Assembling unparameterized SQL string', level: 'alert' },
        { step: 3, phase: 'Database Execution', message: 'Tautology OR \'1\'=\'1\' caused WHERE clause to evaluate TRUE for all rows', level: 'alert' },
        { step: 4, phase: 'Exploitation', message: 'Query succeeded; 5 account records dumped', level: 'alert' }
      ],
      explanation: {
        rootCause: 'Raw SQL concatenation allowed user input to break out of data context into SQL command context.',
        impact: 'Full authentication bypass and complete database contents exfiltration.',
        remediation: 'Replace raw string concatenation with parameterized prepared statements.',
        vulnerableExample: 'db.raw("SELECT * FROM users WHERE user = \'" + user + "\'");',
        secureExample: 'db.prepared("SELECT * FROM users WHERE user = ?", [user]);',
        verification: 'Flip mode to secure and execute identical payload; verify 401 response.'
      }
    };
  }

  if (vulnClass === 'xss_reflected' || vulnClass === 'xss') {
    return isHardened ? {
      vulnClass: 'xss_reflected', mode: 'secure', title: 'Reflected XSS', outcome: 'blocked', verdict: 'pass',
      summary: 'Blocked: HTML entity output encoding neutralized the script tag.',
      endpoint: '/api/lab/xss/search', parameter: 'q', payload, liveExploit: true, durationMs: 4,
      evidence: { encodedOutput: payload.replace(/</g, '&lt;').replace(/>/g, '&gt;') },
      trace: [
        { step: 1, phase: 'Input Receive', message: 'Input received with potential markup', level: 'info' },
        { step: 2, phase: 'Sanitization', message: 'Applied context-aware HTML entity encoding', level: 'ok' },
        { step: 3, phase: 'Rendering', message: 'Browser rendered safe escaped text; script did not execute', level: 'ok' }
      ],
      explanation: {
        rootCause: 'Unencoded user input reflected directly in HTML DOM context.',
        impact: 'Session hijacking, DOM manipulation, credential theft.',
        remediation: 'Always encode user-controlled strings using HTML entities before rendering.',
        vulnerableExample: '<div>Hello ${input}</div>',
        secureExample: '<div>Hello ${escapeHtml(input)}</div>',
        verification: 'Input payload containing <script>; verify literal &lt;script&gt; in HTML source.'
      }
    } : {
      vulnClass: 'xss_reflected', mode: 'vulnerable', title: 'Reflected XSS', outcome: 'exploited', verdict: 'fail',
      summary: 'Exploited: Unencoded markup reflected directly in document body.',
      endpoint: '/api/lab/xss/search', parameter: 'q', payload, liveExploit: true, durationMs: 5,
      evidence: { reflectedMarkup: payload },
      trace: [
        { step: 1, phase: 'Input Ingestion', message: 'Search parameter read directly from URL query', level: 'info' },
        { step: 2, phase: 'DOM Injection', message: 'Echoing raw unescaped input into HTML response stream', level: 'alert' },
        { step: 3, phase: 'Script Execution', message: 'JavaScript payload executes in victim browser session context', level: 'alert' }
      ],
      explanation: {
        rootCause: 'Lack of output encoding in search results template.',
        impact: 'Attacker executes arbitrary JavaScript in the victim context.',
        remediation: 'Apply context-aware HTML entity encoding before emitting variables into HTML.',
        vulnerableExample: 'res.send(`<h1>Results for ${q}</h1>`);',
        secureExample: 'res.send(`<h1>Results for ${escapeHtml(q)}</h1>`);',
        verification: 'Inspect rendered markup to confirm no raw <script> or event tags exist.'
      }
    };
  }

  if (vulnClass === 'csrf') {
    return isHardened ? {
      vulnClass: 'csrf', mode: 'secure', title: 'CSRF Protection', outcome: 'blocked', verdict: 'pass',
      summary: 'Blocked: Request rejected due to missing or invalid CSRF token and mismatched origin.',
      endpoint: '/api/lab/csrf/transfer', liveExploit: true, durationMs: 6,
      evidence: { tokenPresent: false, status: 403 },
      trace: [
        { step: 1, phase: 'Request Inspection', message: 'State-changing POST request intercepted', level: 'info' },
        { step: 2, phase: 'Token Verification', message: 'No valid X-CSRF-Token header matching double-submit cookie found', level: 'alert' },
        { step: 3, phase: 'Enforcement', message: 'Request rejected with HTTP 403 Forbidden', level: 'ok' }
      ],
      explanation: {
        rootCause: 'Relying exclusively on ambient session cookies for authorization of mutating actions.',
        impact: 'Third-party sites can forge actions on behalf of authenticated users.',
        remediation: 'Implement signed double-submit CSRF tokens and SameSite=Strict cookie flags.',
        vulnerableExample: 'app.post("/transfer", handleTransfer);',
        secureExample: 'app.post("/transfer", csrfProtection, handleTransfer);',
        verification: 'Send request without CSRF token; verify request is rejected with 403.'
      }
    } : {
      vulnClass: 'csrf', mode: 'vulnerable', title: 'CSRF Protection', outcome: 'exploited', verdict: 'fail',
      summary: 'Exploited: Forged cross-site request executed without token verification.',
      endpoint: '/api/lab/csrf/transfer', liveExploit: true, durationMs: 8,
      evidence: { forgedTransferExecuted: true, transferredAmount: 5000, recipient: 'attacker@evil.com' },
      trace: [
        { step: 1, phase: 'Incoming Cross-Origin Request', message: 'Origin header indicates external third-party site', level: 'warn' },
        { step: 2, phase: 'Session Acceptance', message: 'Ambient session cookie attached automatically by browser', level: 'alert' },
        { step: 3, phase: 'Execution', message: 'State-changing transfer completed without anti-forgery validation', level: 'alert' }
      ],
      explanation: {
        rootCause: 'Missing anti-CSRF tokens and missing SameSite cookie restrictions.',
        impact: 'Attackers can induce victims into executing unwanted state changes.',
        remediation: 'Implement signed CSRF tokens and enforce SameSite=Strict cookies.',
        vulnerableExample: 'app.post("/transfer", transferFunds);',
        secureExample: 'app.post("/transfer", csrfMiddleware, transferFunds);',
        verification: 'Verify that requests without signed tokens return 403.'
      }
    };
  }

  if (vulnClass === 'idor') {
    return isHardened ? {
      vulnClass: 'idor', mode: 'secure', title: 'Insecure Direct Object References', outcome: 'blocked', verdict: 'pass',
      summary: 'Blocked: Object-level authorization denied access to Alice\'s confidential document #1.',
      endpoint: '/api/vault/documents/1', liveExploit: true, durationMs: 5,
      evidence: { requestingUser: 'bob', targetDocumentId: 1, documentOwner: 'alice', status: 403 },
      trace: [
        { step: 1, phase: 'Authorization Check', message: 'Requesting user Bob (ID 4) identified from session', level: 'info' },
        { step: 2, phase: 'Ownership Verification', message: 'Document #1 is owned by Alice (ID 3); Bob is not granted access', level: 'alert' },
        { step: 3, phase: 'Enforcement', message: 'Object access denied with HTTP 403 Forbidden', level: 'ok' }
      ],
      explanation: {
        rootCause: 'Relying on client-supplied ID parameters without validating user ownership.',
        impact: 'Horizontal privilege escalation allowing users to view others\' confidential records.',
        remediation: 'Query documents with WHERE id = ? AND owner_id = ? or verify permission table.',
        vulnerableExample: 'SELECT * FROM documents WHERE id = :id',
        secureExample: 'SELECT * FROM documents WHERE id = :id AND (owner_id = :userId OR id IN (SELECT doc_id FROM grants WHERE user_id = :userId))',
        verification: 'Attempt fetching Alice document using Bob session; verify 403 status.'
      }
    } : {
      vulnClass: 'idor', mode: 'vulnerable', title: 'Insecure Direct Object References', outcome: 'exploited', verdict: 'fail',
      summary: 'Exploited: Bob successfully retrieved Alice\'s confidential payroll document #1.',
      endpoint: '/api/vault/documents/1', liveExploit: true, durationMs: 7,
      evidence: {
        documentId: 1,
        title: 'Q3 Salary & Executive Compensation',
        classification: 'RESTRICTED',
        owner: 'Alice Bennett',
        retrievedBy: 'Bob Jenkins'
      },
      trace: [
        { step: 1, phase: 'Parameter Read', message: 'Requested document ID: 1 from URL path', level: 'info' },
        { step: 2, phase: 'Unchecked Database Fetch', message: 'Queried document 1 directly without checking ownership or ACL', level: 'alert' },
        { step: 3, phase: 'Data Exposure', message: 'Alice confidential compensation data returned to unauthorized user Bob', level: 'alert' }
      ],
      explanation: {
        rootCause: 'Object identifier from URL used directly without verifying requester permissions.',
        impact: 'Unauthorized access to confidential documents across the entire organization.',
        remediation: 'Always perform an object-level authorization check against the requesting user ID.',
        vulnerableExample: 'db.prepared("SELECT * FROM docs WHERE id = ?", [id]);',
        secureExample: 'authorizeDocumentAccess(req.auth.userId, docId);',
        verification: 'Confirm that non-owners receive 403 Forbidden.'
      }
    };
  }

  // Generic fallback lab outcome for headers, upload, ssrf, etc.
  return isHardened ? {
    vulnClass, mode: 'secure', title: VULN_META.find((m) => m.key === vulnClass)?.title ?? vulnClass,
    outcome: 'blocked', verdict: 'pass',
    summary: `Hardened: ${vulnClass} security control successfully blocked exploit attempt.`,
    endpoint: `/api/lab/${vulnClass}`, liveExploit: false, durationMs: 6, evidence: { blocked: true },
    trace: [
      { step: 1, phase: 'Validation', message: 'Defensive validation active', level: 'info' },
      { step: 2, phase: 'Protection', message: 'Payload rejected by defensive guard', level: 'ok' }
    ],
    explanation: {
      rootCause: 'Defensive mitigation implemented.',
      impact: 'Vulnerability neutralized in hardened mode.',
      remediation: 'Follow secure development standards.',
      vulnerableExample: '// Unhardened path',
      secureExample: '// Hardened defense path',
      verification: 'Probe endpoint to confirm rejection.'
    }
  } : {
    vulnClass, mode: 'vulnerable', title: VULN_META.find((m) => m.key === vulnClass)?.title ?? vulnClass,
    outcome: 'exploited', verdict: 'fail',
    summary: `Vulnerable: ${vulnClass} weakness reproduced and verified.`,
    endpoint: `/api/lab/${vulnClass}`, liveExploit: false, durationMs: 8, evidence: { weaknessConfirmed: true },
    trace: [
      { step: 1, phase: 'Execution', message: 'Weakness triggered in vulnerable mode', level: 'warn' },
      { step: 2, phase: 'Exploit Complete', message: 'Security control absent or bypassed', level: 'alert' }
    ],
    explanation: {
      rootCause: 'Control is disabled or vulnerable.',
      impact: 'System security posture degraded.',
      remediation: 'Apply mitigation in remediation center.',
      vulnerableExample: '// Vulnerable path',
      secureExample: '// Hardened path',
      verification: 'Apply mitigation and retest.'
    }
  };
}
