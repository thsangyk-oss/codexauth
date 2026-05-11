const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8801;

function expandHomePath(inputPath, homeDir = os.homedir()) {
  const value = String(inputPath || '').trim();
  if (value === '~') return homeDir;
  if (value.startsWith('~/') || value.startsWith('~\\')) {
    return path.join(homeDir, value.slice(2));
  }
  return value;
}

function resolveRuntimePath(configuredPath, defaultSegments, homeDir = os.homedir()) {
  const value = String(configuredPath || '').trim();
  if (value) return path.resolve(expandHomePath(value, homeDir));
  return path.join(homeDir, ...defaultSegments);
}

function getRuntimePaths(env = process.env, homeDir = os.homedir()) {
  return {
    codexAuth: resolveRuntimePath(env.CODEX_AUTH, ['.codex', 'auth.json'], homeDir),
  };
}

const RUNTIME_PATHS = getRuntimePaths();
const CODEX_AUTH = RUNTIME_PATHS.codexAuth;
const CODEX_OAUTH_REDIRECT_URI = process.env.CODEX_OAUTH_REDIRECT_URI || 'http://localhost:1455/auth/callback';
const CODEX_OAUTH_AUTHORIZE_URL = process.env.CODEX_OAUTH_AUTHORIZE_URL || 'https://auth.openai.com/oauth/authorize';
const CODEX_OAUTH_TOKEN_URL = process.env.CODEX_OAUTH_TOKEN_URL || 'https://auth.openai.com/oauth/token';
const CODEX_OAUTH_CLIENT_ID = process.env.CODEX_OAUTH_CLIENT_ID || 'app_EMoamEEZ73f0CkXaXp7hrann';
const CODEX_OAUTH_SCOPE = process.env.CODEX_OAUTH_SCOPE || 'openid profile email offline_access';
const BROWSER_USER_AGENT = process.env.CHATGPT_USER_AGENT || (
  process.platform === 'win32'
    ? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
    : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
);
const CODEX_CLI_USER_AGENT = process.env.CODEX_CLI_USER_AGENT || (
  process.platform === 'win32'
    ? 'codex-cli/1.0.18 (Windows; x64)'
    : 'codex-cli/1.0.18 (macOS; arm64)'
);
const OAUTH_SESSION_TTL_MS = 15 * 60 * 1000;
const DATA_DIR = path.join(__dirname, 'data');
const LOCAL_CODEX_DB = path.join(DATA_DIR, 'codex_accounts.json');
const SUBSCRIPTION_CACHE = path.join(DATA_DIR, 'subscriptions.json');
const QUOTA_CACHE_FILE = path.join(DATA_DIR, 'quota-cache.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const oauthSessions = new Map();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Password / device-token auth ─────────────────────────────────────
function readAuth() {
  try {
    const data = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    if (!data || typeof data !== 'object') return { tokens: [] };
    return {
      passwordHash: data.passwordHash || null,
      salt: data.salt || null,
      tokens: Array.isArray(data.tokens) ? data.tokens : [],
      createdAt: data.createdAt || null,
      updatedAt: data.updatedAt || null,
    };
  } catch (_) {
    return { tokens: [] };
  }
}

function writeAuth(auth) {
  fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2));
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 32).toString('hex');
}

function verifyPassword(password, hash, salt) {
  if (!hash || !salt) return false;
  try {
    const computed = hashPassword(password, salt);
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(hash, 'hex'));
  } catch (_) { return false; }
}

function newAuthToken() {
  return crypto.randomBytes(24).toString('hex');
}

function readAuthToken(req) {
  const headerToken = (req.headers['x-cr-token'] || '').toString().trim();
  if (headerToken) return headerToken;
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  return bearer || '';
}

app.use('/api', (req, res, next) => {
  // Allow auth, health, and local apply regardless of password state
  if (req.path.startsWith('/auth/') || req.path === '/health' || req.path.startsWith('/apply/')) return next();
  const auth = readAuth();
  if (!auth.passwordHash) return next();
  const token = readAuthToken(req);
  if (!token || !auth.tokens.includes(token)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
});

app.get('/api/auth/status', (req, res) => {
  const auth = readAuth();
  const token = readAuthToken(req);
  const authed = !auth.passwordHash || (Boolean(token) && auth.tokens.includes(token));
  res.json({
    hasPassword: Boolean(auth.passwordHash),
    authed: Boolean(authed),
    deviceCount: (auth.tokens || []).length,
  });
});

app.post('/api/auth/login', (req, res) => {
  const auth = readAuth();
  if (!auth.passwordHash) return res.status(400).json({ error: 'no_password_set' });
  const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  if (!password) return res.status(400).json({ error: 'password_required' });
  if (!verifyPassword(password, auth.passwordHash, auth.salt)) {
    return res.status(401).json({ error: 'invalid_password' });
  }
  const token = newAuthToken();
  const tokens = [...(auth.tokens || []), token];
  // Cap to last 50 devices
  if (tokens.length > 50) tokens.splice(0, tokens.length - 50);
  writeAuth({ ...auth, tokens });
  res.json({ token });
});

app.post('/api/auth/set-password', (req, res) => {
  const auth = readAuth();
  const newPassword = req.body && typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  const currentPassword = req.body && typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'password_too_short', detail: 'Mật khẩu cần ≥ 4 ký tự' });
  }
  if (auth.passwordHash) {
    const token = readAuthToken(req);
    const authedByToken = Boolean(token) && auth.tokens.includes(token);
    if (!authedByToken && !verifyPassword(currentPassword, auth.passwordHash, auth.salt)) {
      return res.status(401).json({ error: 'invalid_current_password' });
    }
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(newPassword, salt);
  const token = newAuthToken();
  writeAuth({
    passwordHash: hash,
    salt,
    tokens: [token], // changing password invalidates all other devices
    createdAt: auth.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  res.json({ token, ok: true });
});

app.post('/api/auth/clear-password', (req, res) => {
  const auth = readAuth();
  if (!auth.passwordHash) return res.json({ ok: true });
  const currentPassword = req.body && typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
  if (!verifyPassword(currentPassword, auth.passwordHash, auth.salt)) {
    return res.status(401).json({ error: 'invalid_current_password' });
  }
  writeAuth({ tokens: [] });
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const auth = readAuth();
  const token = readAuthToken(req);
  if (token && auth.tokens) {
    writeAuth({ ...auth, tokens: auth.tokens.filter(t => t !== token) });
  }
  res.json({ ok: true });
});

app.post('/api/auth/logout-all', (req, res) => {
  const auth = readAuth();
  if (!auth.passwordHash) return res.json({ ok: true });
  // Keep only current token
  const token = readAuthToken(req);
  writeAuth({ ...auth, tokens: token ? [token] : [] });
  res.json({ ok: true });
});


function parseObjectField(value, fallback = {}) {
  if (!value || typeof value !== 'string') return fallback;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch (e) {
    return fallback;
  }
}

function normalizeLegacyCodexAccountShape(account) {
  if (!account || typeof account !== 'object') return null;

  const providerSpecificData = account.providerSpecificData && typeof account.providerSpecificData === 'object'
    ? account.providerSpecificData
    : {};
  const rawIsActive = account.isActive ?? account.is_active;
  const priority = account.priority ?? account.priority_order ?? 0;
  const expiresIn = account.expiresIn ?? account.expires_in ?? null;
  const consecutiveUseCount = account.consecutiveUseCount ?? account.consecutive_use_count ?? 0;
  const backoffLevel = account.backoffLevel ?? account.backoff_level ?? 0;

  return {
    ...account,
    id: account.id || null,
    provider: account.provider || account.providerId || null,
    authType: account.authType || account.auth_type || null,
    name: account.name || account.email || null,
    email: account.email || null,
    priority: typeof priority === 'number' ? priority : Number(priority || 0),
    isActive: typeof rawIsActive === 'boolean' ? rawIsActive : Boolean(rawIsActive),
    accessToken: account.accessToken || account.access_token || account.accessTokenValue || null,
    refreshToken: account.refreshToken || account.refresh_token || account.refreshTokenValue || null,
    idToken: account.idToken || account.id_token || account.idTokenValue || null,
    expiresAt: account.expiresAt || account.expires_at || null,
    testStatus: account.testStatus || account.test_status || null,
    expiresIn,
    providerSpecificData,
    lastUsedAt: account.lastUsedAt || account.last_used_at || null,
    consecutiveUseCount: typeof consecutiveUseCount === 'number' ? consecutiveUseCount : Number(consecutiveUseCount || 0),
    errorCode: account.errorCode ?? account.error_code ?? null,
    backoffLevel: typeof backoffLevel === 'number' ? backoffLevel : Number(backoffLevel || 0),
    lastError: account.lastError || account.last_error || null,
    lastErrorAt: account.lastErrorAt || account.last_error_at || null,
    createdAt: account.createdAt || account.created_at || null,
    updatedAt: account.updatedAt || account.updated_at || null,
  };
}

function readLocalCodexDb(filePath = LOCAL_CODEX_DB) {
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const providerConnections = Array.isArray(data?.providerConnections)
      ? data.providerConnections
      : Array.isArray(data?.connections)
        ? data.connections
        : [];
    return { providerConnections };
  } catch (e) {
    return { providerConnections: [] };
  }
}

function writeLocalCodexDb(db, filePath = LOCAL_CODEX_DB) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const payload = {
    providerConnections: Array.isArray(db?.providerConnections) ? db.providerConnections : [],
  };
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));
}

function readLocalCodexAccounts(filePath = LOCAL_CODEX_DB) {
  return readLocalCodexDb(filePath).providerConnections
    .filter(connection => (connection?.provider || connection?.providerId) === 'codex')
    .map(normalizeLegacyCodexAccountShape)
    .filter(Boolean)
    .sort((a, b) => {
      const pa = Number.isFinite(a?.priority) ? a.priority : Number(a?.priority || 0);
      const pb = Number.isFinite(b?.priority) ? b.priority : Number(b?.priority || 0);
      if (pa !== pb) return pa - pb;
      return new Date(b?.createdAt || 0).getTime() - new Date(a?.createdAt || 0).getTime();
    });
}

function mergeCodexAccountLists(primaryAccounts, secondaryAccounts) {
  const merged = [];
  const seen = new Set();

  const visit = account => {
    const normalized = normalizeLegacyCodexAccountShape(account);
    if (!normalized) return;
    const keys = [
      normalized.id && `id:${normalized.id}`,
      extractAccountId(normalized) && `account:${extractAccountId(normalized)}`,
      extractChatgptUserId(normalized) && `user:${extractChatgptUserId(normalized)}`,
      normalized.email && `email:${String(normalized.email).toLowerCase()}`,
    ].filter(Boolean);
    if (keys.some(key => seen.has(key))) return;
    keys.forEach(key => seen.add(key));
    merged.push(normalized);
  };

  (Array.isArray(primaryAccounts) ? primaryAccounts : []).forEach(visit);
  (Array.isArray(secondaryAccounts) ? secondaryAccounts : []).forEach(visit);
  return merged;
}

function getStoredCodexAccounts() {
  return readLocalCodexAccounts();
}

function buildLocalCodexAccountRecord(tokenPayload, existingAccount = null, priority = 1) {
  const accessToken = tokenPayload?.access_token || null;
  const refreshToken = tokenPayload?.refresh_token || null;
  const idToken = tokenPayload?.id_token || null;
  const now = new Date().toISOString();
  const decodedId = safeDecodeJWT(idToken || '');
  const decodedAccess = safeDecodeJWT(accessToken || '');
  const authClaims = decodedAccess?.['https://api.openai.com/auth'] || decodedId?.['https://api.openai.com/auth'] || {};
  const profileClaims = decodedAccess?.['https://api.openai.com/profile'] || {};
  const email = decodedId?.email || profileClaims?.email || existingAccount?.email || null;
  const accountId = authClaims?.chatgpt_account_id || existingAccount?.providerSpecificData?.chatgptAccountId || null;
  const planType = authClaims?.chatgpt_plan_type || existingAccount?.providerSpecificData?.chatgptPlanType || null;
  const expiresAt = normalizeIsoDate(tokenPayload?.expires_at)
    || (typeof tokenPayload?.expires_in === 'number' ? new Date(Date.now() + tokenPayload.expires_in * 1000).toISOString() : null)
    || extractExpires({ accessToken });

  return {
    ...(existingAccount || {}),
    id: existingAccount?.id || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')),
    provider: 'codex',
    authType: 'oauth',
    name: email || existingAccount?.name || 'Codex OAuth Account',
    email,
    priority: existingAccount?.priority ?? priority,
    isActive: existingAccount?.isActive ?? true,
    accessToken,
    refreshToken,
    idToken,
    expiresAt,
    testStatus: existingAccount?.testStatus || null,
    expiresIn: tokenPayload?.expires_in ?? existingAccount?.expiresIn ?? null,
    providerSpecificData: {
      ...(existingAccount?.providerSpecificData && typeof existingAccount.providerSpecificData === 'object'
        ? existingAccount.providerSpecificData
        : {}),
      chatgptAccountId: accountId,
      chatgptPlanType: planType,
    },
    lastUsedAt: existingAccount?.lastUsedAt || null,
    consecutiveUseCount: existingAccount?.consecutiveUseCount || 0,
    errorCode: null,
    backoffLevel: existingAccount?.backoffLevel || 0,
    lastError: null,
    lastErrorAt: null,
    createdAt: existingAccount?.createdAt || now,
    updatedAt: now,
  };
}

function persistLocalCodexAccount(tokenPayload, filePath = LOCAL_CODEX_DB) {
  if (!tokenPayload?.id_token) {
    const error = new Error('Thiếu idToken từ OAuth callback; không lưu account');
    error.statusCode = 422;
    throw error;
  }

  const draft = buildLocalCodexAccountRecord(tokenPayload, null, 1);
  const db = readLocalCodexDb(filePath);
  const connections = Array.isArray(db.providerConnections) ? [...db.providerConnections] : [];
  const draftAccountId = extractAccountId(draft);
  const draftUserId = extractChatgptUserId(draft);
  const draftEmail = String(draft.email || '').toLowerCase();

  const existingIndex = connections.findIndex(connection => {
    const normalized = normalizeLegacyCodexAccountShape(connection);
    if (!normalized) return false;
    const accountId = extractAccountId(normalized);
    const userId = extractChatgptUserId(normalized);
    const email = String(normalized.email || '').toLowerCase();
    return (draftAccountId && accountId === draftAccountId)
      || (draftUserId && userId === draftUserId)
      || (draftEmail && email === draftEmail);
  });

  const codexConnections = connections.filter(connection => (connection?.provider || connection?.providerId) === 'codex');
  const nextPriority = codexConnections.reduce((max, connection) => {
    const normalized = normalizeLegacyCodexAccountShape(connection);
    return Math.max(max, Number(normalized?.priority || 0));
  }, 0) + 1;

  const existingAccount = existingIndex >= 0 ? normalizeLegacyCodexAccountShape(connections[existingIndex]) : null;
  const record = buildLocalCodexAccountRecord(tokenPayload, existingAccount, existingAccount?.priority ?? nextPriority);

  if (existingIndex >= 0) connections[existingIndex] = record;
  else connections.push(record);

  writeLocalCodexDb({ providerConnections: connections }, filePath);
  return normalizeLegacyCodexAccountShape(record);
}

function deleteStoredCodexAccounts(ids, filePath = LOCAL_CODEX_DB) {
  const deleteIds = new Set((Array.isArray(ids) ? ids : [ids]).filter(Boolean));
  if (deleteIds.size === 0) return { deletedIds: [], deletedCount: 0, storage: 'local' };

  const db = readLocalCodexDb(filePath);
  const connections = Array.isArray(db?.providerConnections) ? db.providerConnections : [];
  const deletedIds = [];
  const filtered = connections.filter(connection => {
    const isCodex = (connection?.provider || connection?.providerId) === 'codex';
    const shouldDelete = isCodex && deleteIds.has(connection?.id);
    if (shouldDelete) deletedIds.push(connection.id);
    return !shouldDelete;
  });

  if (deletedIds.length === 0) {
    return { deletedIds: [], deletedCount: 0, storage: 'local' };
  }

  writeLocalCodexDb({ providerConnections: filtered }, filePath);
  return { deletedIds, deletedCount: deletedIds.length, storage: 'local' };
}

function readCodexAuth() {
  try {
    return JSON.parse(fs.readFileSync(CODEX_AUTH, 'utf8'));
  } catch (e) {
    return {};
  }
}

function readSubscriptionCache() {
  try {
    const data = JSON.parse(fs.readFileSync(SUBSCRIPTION_CACHE, 'utf8'));
    return data && typeof data === 'object'
      ? { accounts: data.accounts && typeof data.accounts === 'object' ? data.accounts : {} }
      : { accounts: {} };
  } catch (e) {
    return { accounts: {} };
  }
}

function readQuotaCache() {
  try {
    const data = JSON.parse(fs.readFileSync(QUOTA_CACHE_FILE, 'utf8'));
    return data && typeof data === 'object' ? data : {};
  } catch (e) {
    return {};
  }
}

function writeQuotaCache(cache) {
  fs.mkdirSync(path.dirname(QUOTA_CACHE_FILE), { recursive: true });
  fs.writeFileSync(QUOTA_CACHE_FILE, JSON.stringify(cache, null, 2));
}

function writeSubscriptionCache(cache) {
  fs.mkdirSync(path.dirname(SUBSCRIPTION_CACHE), { recursive: true });
  fs.writeFileSync(SUBSCRIPTION_CACHE, JSON.stringify({
    accounts: cache?.accounts && typeof cache.accounts === 'object' ? cache.accounts : {},
  }, null, 2));
}


function createCodeVerifier() {
  return crypto.randomBytes(48).toString('base64url');
}

function createCodeChallenge(codeVerifier) {
  return crypto.createHash('sha256').update(String(codeVerifier || '')).digest('base64url');
}

function createOAuthState() {
  return crypto.randomBytes(16).toString('hex');
}

function buildNativeCodexAuthorizeUrl({ state, codeChallenge, redirectUri = CODEX_OAUTH_REDIRECT_URI } = {}) {
  const url = new URL(CODEX_OAUTH_AUTHORIZE_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CODEX_OAUTH_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', CODEX_OAUTH_SCOPE);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

function cleanupOAuthSessions() {
  const now = Date.now();
  for (const [flowId, session] of oauthSessions.entries()) {
    const expiresAt = new Date(session.expiresAt || 0).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      oauthSessions.delete(flowId);
    }
  }
}

function createOAuthSession(provider, authData, beforeAccounts = []) {
  cleanupOAuthSessions();
  const flowId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + OAUTH_SESSION_TTL_MS).toISOString();
  const codeVerifier = authData?.codeVerifier || createCodeVerifier();
  const state = authData?.state || createOAuthState();
  const redirectUri = authData?.redirectUri || CODEX_OAUTH_REDIRECT_URI;
  const codeChallenge = authData?.codeChallenge || createCodeChallenge(codeVerifier);
  const session = {
    provider,
    codeVerifier,
    codeChallenge,
    state,
    redirectUri,
    createdAt: new Date().toISOString(),
    expiresAt,
    beforeIds: beforeAccounts.map(acc => acc.id),
  };
  oauthSessions.set(flowId, session);
  return { flowId, ...session };
}

function getOAuthSession(flowId) {
  cleanupOAuthSessions();
  if (!flowId) return null;
  return oauthSessions.get(flowId) || null;
}

function destroyOAuthSession(flowId) {
  if (!flowId) return;
  oauthSessions.delete(flowId);
}

function safeDecodeJWT(token) {
  try {
    const payload = String(token || '').split('.')[1];
    if (!payload) return null;
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

function tokenFingerprint(token) {
  if (!token) return null;
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

function extractJwtAuth(account) {
  const accessAuth = safeDecodeJWT(account.accessToken || '')?.['https://api.openai.com/auth'];
  if (accessAuth) return accessAuth;
  const idAuth = safeDecodeJWT(account.idToken || '')?.['https://api.openai.com/auth'];
  return idAuth || null;
}

function extractEmail(account) {
  try {
    if (account.idToken) {
      const d = safeDecodeJWT(account.idToken);
      if (d && d.email) return d.email;
      if (d && d['https://api.openai.com/profile']) return d['https://api.openai.com/profile'].email;
    }
    if (account.accessToken) {
      const d = safeDecodeJWT(account.accessToken);
      if (d && d['https://api.openai.com/profile']) return d['https://api.openai.com/profile'].email;
    }
  } catch (e) {}
  return null;
}

function extractExpires(account) {
  // Prefer the stored expiresAt from db (more accurate than JWT exp)
  if (account.expiresAt) return account.expiresAt;
  const d = safeDecodeJWT(account.accessToken || '');
  if (!d || typeof d.exp !== 'number' || !Number.isFinite(d.exp)) return null;
  const expiresAt = new Date(d.exp * 1000);
  return Number.isFinite(expiresAt.getTime()) ? expiresAt.toISOString() : null;
}

function normalizeIsoDate(value) {
  if (value == null || value === '') return null;

  let ms = null;
  if (value instanceof Date) {
    ms = value.getTime();
  } else if (typeof value === 'number' && Number.isFinite(value)) {
    ms = value > 1e12 ? value : value * 1000;
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (/^\d+$/.test(trimmed)) {
      const num = Number(trimmed);
      if (!Number.isFinite(num)) return null;
      ms = trimmed.length >= 13 ? num : num * 1000;
    } else {
      ms = new Date(trimmed).getTime();
    }
  }

  if (!Number.isFinite(ms)) return null;
  const iso = new Date(ms);
  return Number.isFinite(iso.getTime()) ? iso.toISOString() : null;
}

function extractPlanType(account) {
  return extractJwtAuth(account)?.chatgpt_plan_type || account.planType || account.plan_type || null;
}

function extractSubscriptionExpires(account) {
  const directKeys = [
    'subscriptionExpiresAt',
    'subscription_expires_at',
    'subscriptionExpiry',
    'subscription_expiry',
    'subscriptionEndAt',
    'subscription_end_at',
    'planExpiresAt',
    'plan_expires_at',
    'entitlementExpiresAt',
    'entitlement_expires_at',
  ];

  for (const key of directKeys) {
    const iso = normalizeIsoDate(account[key]);
    if (iso) return iso;
  }

  const nestedCandidates = [
    account.subscription?.expiresAt,
    account.subscription?.expires_at,
    account.entitlement?.expiresAt,
    account.entitlement?.expires_at,
    account.last_active_subscription?.expiresAt,
    account.last_active_subscription?.expires_at,
  ];

  for (const value of nestedCandidates) {
    const iso = normalizeIsoDate(value);
    if (iso) return iso;
  }

  return null;
}

function extractSubscription(account) {
  return {
    plan: extractPlanType(account),
    expiresAt: extractSubscriptionExpires(account),
  };
}

function normalizeSubscriptionData(subscription) {
  if (!subscription || typeof subscription !== 'object') {
    return {
      plan: null,
      subscriptionPlan: null,
      expiresAt: null,
      renewsAt: null,
      cancelsAt: null,
      billingPeriod: null,
      hasActiveSubscription: null,
      willRenew: null,
      workspaceName: null,
      checkedAt: null,
      source: null,
    };
  }

  return {
    plan: subscription.plan || null,
    subscriptionPlan: subscription.subscriptionPlan || subscription.subscription_plan || null,
    expiresAt: normalizeIsoDate(subscription.expiresAt ?? subscription.expires_at),
    renewsAt: normalizeIsoDate(subscription.renewsAt ?? subscription.renews_at),
    cancelsAt: normalizeIsoDate(subscription.cancelsAt ?? subscription.cancels_at),
    billingPeriod: subscription.billingPeriod || subscription.billing_period || null,
    hasActiveSubscription: subscription.hasActiveSubscription ?? subscription.has_active_subscription ?? null,
    willRenew: subscription.willRenew ?? subscription.will_renew ?? null,
    workspaceName: subscription.workspaceName || subscription.workspace_name || null,
    checkedAt: normalizeIsoDate(subscription.checkedAt ?? subscription.checked_at),
    source: subscription.source || null,
  };
}

function mergeSubscriptionData(base, override) {
  const a = normalizeSubscriptionData(base);
  const b = normalizeSubscriptionData(override);
  return {
    plan: b.plan || a.plan || null,
    subscriptionPlan: b.subscriptionPlan || a.subscriptionPlan || null,
    expiresAt: b.expiresAt || a.expiresAt || null,
    renewsAt: b.renewsAt || a.renewsAt || null,
    cancelsAt: b.cancelsAt || a.cancelsAt || null,
    billingPeriod: b.billingPeriod || a.billingPeriod || null,
    hasActiveSubscription: b.hasActiveSubscription ?? a.hasActiveSubscription ?? null,
    willRenew: b.willRenew ?? a.willRenew ?? null,
    workspaceName: b.workspaceName || a.workspaceName || null,
    checkedAt: b.checkedAt || a.checkedAt || null,
    source: b.source || a.source || null,
  };
}

function resolveCachedSubscription(account, subscriptionCache) {
  const accountId = extractAccountId(account);
  const cached = accountId ? subscriptionCache?.accounts?.[accountId] || null : null;
  return mergeSubscriptionData(extractSubscription(account), cached);
}

function buildAccountsCheckHeaders(accessToken, accountId) {
  const headers = {
    'Authorization': `Bearer ${accessToken}`,
    'Accept': 'application/json',
    'Origin': 'https://chatgpt.com',
    'Referer': 'https://chatgpt.com/',
    'User-Agent': BROWSER_USER_AGENT,
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
  };
  if (accountId) headers['chatgpt-account-id'] = accountId;
  return headers;
}

function selectAccountsCheckEntry(payload, accountId) {
  const accounts = payload?.accounts;
  if (!accounts || typeof accounts !== 'object') return null;

  if (accountId && accounts[accountId]) return accounts[accountId];

  const entries = Object.values(accounts).filter(item => item && typeof item === 'object');
  if (accountId) {
    const nested = entries.find(item => item?.account?.account_id === accountId);
    if (nested) return nested;
  }

  if (accounts.default && (!accountId || accounts.default?.account?.account_id === accountId)) {
    return accounts.default;
  }
  if (accounts.default) return accounts.default;
  return entries.length === 1 ? entries[0] : null;
}

function extractSubscriptionFromAccountsCheck(payload, accountId, fallbackPlan = null) {
  const entry = selectAccountsCheckEntry(payload, accountId);
  if (!entry) {
    return {
      available: false,
      plan: fallbackPlan,
      source: 'accounts/check',
    };
  }

  const account = entry.account || {};
  const entitlement = entry.entitlement || {};
  const lastActive = entry.last_active_subscription || {};

  return {
    available: true,
    accountId: account.account_id || accountId || null,
    plan: account.plan_type || fallbackPlan || null,
    subscriptionPlan: entitlement.subscription_plan || null,
    expiresAt: normalizeIsoDate(entitlement.expires_at),
    renewsAt: normalizeIsoDate(entitlement.renews_at),
    cancelsAt: normalizeIsoDate(entitlement.cancels_at),
    billingPeriod: entitlement.billing_period || null,
    hasActiveSubscription: entitlement.has_active_subscription ?? null,
    willRenew: lastActive.will_renew ?? null,
    workspaceName: account.name || null,
    checkedAt: new Date().toISOString(),
    source: 'accounts/check',
  };
}

async function fetchAccountSubscription(account) {
  const accountId = extractAccountId(account);
  const fallbackPlan = extractPlanType(account);
  if (!account?.accessToken) {
    return { available: false, plan: fallbackPlan, error: 'No access token', source: 'accounts/check' };
  }

  try {
    const res = await fetch('https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27', {
      headers: buildAccountsCheckHeaders(account.accessToken, accountId),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return {
        available: false,
        plan: fallbackPlan,
        httpCode: res.status,
        error: text.replace(/\s+/g, ' ').trim().slice(0, 160) || `HTTP ${res.status}`,
        source: 'accounts/check',
      };
    }

    const payload = await res.json();
    return extractSubscriptionFromAccountsCheck(payload, accountId, fallbackPlan);
  } catch (e) {
    return {
      available: false,
      plan: fallbackPlan,
      error: e.message,
      source: 'accounts/check',
    };
  }
}

function persistSubscription(account, subscription, subscriptionCache = readSubscriptionCache()) {
  const accountId = extractAccountId(account);
  if (!accountId || !subscription?.available) return null;

  const merged = mergeSubscriptionData(subscriptionCache.accounts?.[accountId], subscription);
  subscriptionCache.accounts[accountId] = merged;
  writeSubscriptionCache(subscriptionCache);
  return merged;
}

function extractErrorCode(errorCode, lastError) {
  const direct = Number(errorCode);
  if (Number.isFinite(direct) && direct > 0) return direct;
  const match = String(lastError || '').match(/^\[(\d+)\]/);
  return match ? Number(match[1]) : null;
}

function extractErrorDetail(lastError) {
  if (!lastError) return null;
  const raw = String(lastError);
  const match = raw.match(/\{.*\}$/);
  if (match) {
    try {
      const parsed = JSON.parse(match[0]);
      return parsed.detail || parsed.message || raw;
    } catch (e) {}
  }
  return raw.replace(/^\[\d+\]:\s*/, '');
}

function shouldHideDashboardError(errorCode, lastError) {
  const code = extractErrorCode(errorCode, lastError);
  const detail = extractErrorDetail(lastError) || '';
  return code === 400
    && /gpt-5\.5/i.test(detail)
    && /not supported when using Codex with a ChatGPT account/i.test(detail);
}

function sanitizeDashboardError(errorCode, lastError) {
  if (shouldHideDashboardError(errorCode, lastError)) {
    return { errorCode: null, lastError: null };
  }
  return {
    errorCode: extractErrorCode(errorCode, lastError),
    lastError: lastError || null,
  };
}

function parseOAuthCallback(callbackUrl) {
  const raw = String(callbackUrl || '').trim();
  if (!raw) {
    return { valid: false, error: 'Missing callback URL' };
  }

  try {
    const url = new URL(raw);
    const error = url.searchParams.get('error');
    const errorDescription = url.searchParams.get('error_description') || null;
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (error) {
      return {
        valid: false,
        error: errorDescription || error,
        code: null,
        state,
      };
    }

    if (!code) {
      return { valid: false, error: 'No authorization code found in callback URL' };
    }

    return {
      valid: true,
      code,
      state,
      error: null,
      redirectUri: `${url.origin}${url.pathname}`,
    };
  } catch (e) {
    return { valid: false, error: 'Invalid callback URL' };
  }
}

function extractAccountId(account) {
  try {
    return extractJwtAuth(account)?.chatgpt_account_id || null;
  } catch (e) {
    return null;
  }
}

function extractChatgptUserId(account) {
  try {
    return extractJwtAuth(account)?.chatgpt_user_id || null;
  } catch (e) {
    return null;
  }
}

function getCodexAccounts(db) {
  const connections = Array.isArray(db?.providerConnections)
    ? db.providerConnections
    : Array.isArray(db?.connections)
      ? db.connections
      : [];
  return connections.filter(c => (c.provider || c.providerId) === 'codex');
}



async function exchangeCodexAuthorizationCode({ code, codeVerifier, redirectUri = CODEX_OAUTH_REDIRECT_URI } = {}) {
  const payload = new URLSearchParams();
  payload.set('grant_type', 'authorization_code');
  payload.set('client_id', CODEX_OAUTH_CLIENT_ID);
  payload.set('redirect_uri', redirectUri);
  payload.set('code', String(code || ''));
  payload.set('code_verifier', String(codeVerifier || ''));

  const res = await fetch(CODEX_OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://auth.openai.com',
      'Referer': 'https://auth.openai.com/',
      'User-Agent': BROWSER_USER_AGENT,
    },
    body: payload.toString(),
  });

  const text = await res.text().catch(() => '');
  let json = {};
  if (text) {
    try {
      json = JSON.parse(text);
    } catch (e) {
      json = { raw: text };
    }
  }

  if (!res.ok || json?.error) {
    const detail = json?.error_description || json?.error || json?.message || json?.raw || `HTTP ${res.status}`;
    const error = new Error(detail);
    error.statusCode = res.status;
    error.payload = json;
    throw error;
  }

  return json;
}

function pickLatestAccount(accounts, beforeIds = []) {
  const before = new Set(beforeIds);
  const created = accounts
    .filter(acc => acc && !before.has(acc.id))
    .sort((a, b) => {
      const at = new Date(a?.createdAt || 0).getTime();
      const bt = new Date(b?.createdAt || 0).getTime();
      return bt - at;
    });
  return created[0] || null;
}

function resolveCurrentConnection(accounts, auth) {
  const currentAccessToken = auth?.tokens?.access_token || null;
  const currentIdToken = auth?.tokens?.id_token || null;
  const accessJwt = safeDecodeJWT(currentAccessToken);
  const idJwt = safeDecodeJWT(currentIdToken);
  const accessAuth = accessJwt?.['https://api.openai.com/auth'] || {};
  const idAuth = idJwt?.['https://api.openai.com/auth'] || {};
  const profile = accessJwt?.['https://api.openai.com/profile'] || {};
  const current = {
    accountId: auth?.tokens?.account_id || accessAuth.chatgpt_account_id || idAuth.chatgpt_account_id || null,
    userId: accessAuth.chatgpt_user_id || idAuth.chatgpt_user_id || null,
    email: profile.email || idJwt?.email || null,
    tokenFingerprint: tokenFingerprint(currentAccessToken),
    connectionId: null,
    matchStrategy: null,
  };

  if (!accounts.length) return current;

  if (current.tokenFingerprint) {
    const exact = accounts.find(acc => tokenFingerprint(acc.accessToken) === current.tokenFingerprint);
    if (exact) {
      current.connectionId = exact.id;
      current.matchStrategy = 'token';
      return current;
    }
  }

  if (current.userId) {
    const byUser = accounts.filter(acc => extractChatgptUserId(acc) === current.userId);
    if (byUser.length === 1) {
      current.connectionId = byUser[0].id;
      current.matchStrategy = 'userId';
      return current;
    }
  }

  if (current.email) {
    const currentEmail = current.email.toLowerCase();
    const byEmail = accounts.filter(acc => (extractEmail(acc) || '').toLowerCase() === currentEmail);
    if (byEmail.length === 1) {
      current.connectionId = byEmail[0].id;
      current.matchStrategy = 'email';
      return current;
    }
  }

  if (current.accountId) {
    const byAccount = accounts.filter(acc => extractAccountId(acc) === current.accountId);
    if (byAccount.length === 1) {
      current.connectionId = byAccount[0].id;
      current.matchStrategy = 'accountId';
    }
  }

  return current;
}

function buildAccountExportPayload(account) {
  return {
    auth_mode: 'chatgpt',
    OPENAI_API_KEY: null,
    tokens: {
      id_token: account?.idToken || null,
      access_token: account?.accessToken || null,
      refresh_token: account?.refreshToken || null,
      account_id: extractAccountId(account) || null,
    },
    last_refresh: normalizeIsoDate(account?.updatedAt)
      || normalizeIsoDate(account?.lastRefresh)
      || normalizeIsoDate(account?.createdAt)
      || new Date().toISOString(),
  };
}

// ========== API ==========

// Get all locally stored Codex accounts + currently applied account_id
app.get('/api/accounts', (req, res) => {
  const auth = readCodexAuth();
  const codexAccounts = getStoredCodexAccounts();
  const current = resolveCurrentConnection(codexAccounts, auth);
  const subscriptionCache = readSubscriptionCache();

  const now = Date.now();
  const accounts = codexAccounts.map(acc => {
    const dashboardError = sanitizeDashboardError(acc.errorCode, acc.lastError);

    // Extract model locks: { modelName: lockUntilISO | null }
    const modelLocks = {};
    for (const [k, v] of Object.entries(acc)) {
      if (!k.startsWith('modelLock_')) continue;
      const model = k.slice('modelLock_'.length);
      if (v && new Date(v).getTime() > now) {
        modelLocks[model] = v;          // still locked
      } else if (v) {
        modelLocks[model] = null;       // lock expired
      }
    }
    const activeLocks = Object.entries(modelLocks).filter(([, v]) => v !== null);

    return {
      id: acc.id,
      name: acc.name,
      email: extractEmail(acc) || acc.name,
      accountId: extractAccountId(acc),
      priority: acc.priority,
      isActive: acc.isActive,
      testStatus: acc.testStatus,
      authType: acc.authType,
      expiresAt: extractExpires(acc),
      subscription: resolveCachedSubscription(acc, subscriptionCache),
      lastError: dashboardError.lastError,
      errorCode: dashboardError.errorCode,
      lastErrorAt: acc.lastErrorAt || null,
      backoffLevel: acc.backoffLevel || 0,
      consecutiveUseCount: acc.consecutiveUseCount || 0,
      lastUsedAt: acc.lastUsedAt || null,
      createdAt: acc.createdAt || null,
      updatedAt: acc.updatedAt || null,
      modelLocks,          // all locks (active + expired)
      activeLockCount: activeLocks.length,
    };
  });

  res.json({
    accounts,
    count: accounts.length,
    currentAccountId: current.accountId,
    currentConnectionId: current.connectionId,
    currentMatchStrategy: current.matchStrategy,
  });
});

// Kiểm tra token Codex đúng cách theo native Codex auth flow
// POST https://chatgpt.com/backend-api/codex/responses
// acceptStatuses: [400] — 400 nghĩa là token hợp lệ, chỉ request body bị lỗi
async function checkCodexToken(acc) {
  if (!acc.accessToken) {
    return { valid: false, code: null, error: 'No access token' };
  }
  try {
    const response = await fetch('https://chatgpt.com/backend-api/codex/responses', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${acc.accessToken}`,
        'Content-Type': 'application/json',
        'originator': 'codex-cli',
        'User-Agent': CODEX_CLI_USER_AGENT,
      },
      body: JSON.stringify({ model: 'gpt-5.3-codex', input: [], stream: false, store: false }),
    });

    let body = null;
    try { body = await response.json(); } catch (_) {}

    const code = response.status;

    // Token hợp lệ: 2xx hoặc 400 (body lỗi nhưng token OK)
    if (response.ok || code === 400) {
      const detail = body?.detail || body?.error?.message || null;
      return { valid: true, code, detail };
    }

    // Token hết hạn hoặc bị thu hồi
    if (code === 401) return { valid: false, code, error: 'Token hết hạn hoặc bị thu hồi' };
    if (code === 403) return { valid: false, code, error: 'Truy cập bị từ chối' };
    // 429 = token hợp lệ nhưng hết quota — không phải lỗi token
    if (code === 429) return { valid: true, code, detail: 'Quota exhausted' };

    const errMsg = body?.detail || body?.error?.message || `HTTP ${code}`;
    return { valid: false, code, error: errMsg };
  } catch (e) {
    return { valid: false, code: null, error: e.message };
  }
}

// Lấy quota 5h / 7d từ wham/usage
async function fetchWhamUsage(accessToken, accountId = null) {
  try {
    const headers = {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
      'Origin': 'https://chatgpt.com',
      'Referer': 'https://chatgpt.com/',
      'User-Agent': BROWSER_USER_AGENT,
    };
    if (accountId) headers['chatgpt-account-id'] = accountId;
    const res = await fetch('https://chatgpt.com/backend-api/wham/usage', { headers });
    if (!res.ok) return { available: false, httpCode: res.status };

    const c = await res.json();
    const rl = c.rate_limit || {};
    const pw = rl.primary_window   || {};   // 5h session
    const sw = rl.secondary_window || {};   // 7d weekly

    const toISO = ts => ts ? new Date(ts * 1000).toISOString() : null;

    return {
      available: true,
      plan: c.plan_type || null,
      limitReached: rl.limit_reached || false,
      session: {
        used:      pw.used_percent ?? null,
        remaining: pw.used_percent != null ? 100 - pw.used_percent : null,
        resetAt:   toISO(pw.reset_at),
      },
      weekly: {
        used:      sw.used_percent ?? null,
        remaining: sw.used_percent != null ? 100 - sw.used_percent : null,
        resetAt:   toISO(sw.reset_at),
      },
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

function getSharedSubscriptionPromise(acc, sharedState) {
  const accountId = extractAccountId(acc) || acc.id;
  if (!sharedState?.subscriptionPromises) return fetchAccountSubscription(acc);
  if (!sharedState.subscriptionPromises.has(accountId)) {
    sharedState.subscriptionPromises.set(accountId, fetchAccountSubscription(acc));
  }
  return sharedState.subscriptionPromises.get(accountId);
}

// Kiểm tra đầy đủ: token validity + quota 5h/7d + subscription
async function fullCheck(acc, sharedState = {}) {
  const subscriptionCache = sharedState.subscriptionCache || readSubscriptionCache();
  const baseSubscription = resolveCachedSubscription(acc, subscriptionCache);
  const [tokenResult, usageResult, liveSubscription] = await Promise.all([
    checkCodexToken(acc),
    acc.accessToken ? fetchWhamUsage(acc.accessToken, extractAccountId(acc)) : Promise.resolve({ available: false }),
    acc.accessToken ? getSharedSubscriptionPromise(acc, sharedState) : Promise.resolve({ available: false, plan: baseSubscription.plan }),
  ]);

  let subscription = mergeSubscriptionData(baseSubscription, { plan: usageResult?.plan || baseSubscription.plan });
  if (liveSubscription?.available) {
    subscription = mergeSubscriptionData(subscription, liveSubscription);
    persistSubscription(acc, liveSubscription, subscriptionCache);
  }

  return { token: tokenResult, usage: usageResult, subscription };
}

// Đọc quota cache đã lưu (dùng cho frontend load nhanh)
app.get('/api/quota-cache', (req, res) => {
  res.json(readQuotaCache());
});

function buildTokenResult(token) {
  return {
    status: token.valid ? 'ok' : 'error',
    code: token.code,
    detail: token.valid ? token.detail : token.error,
  };
}

function saveToQuotaCache(entries) {
  const qc = readQuotaCache();
  const checkedAt = new Date().toISOString();
  for (const e of entries) {
    qc[e.id] = { token: e.token, usage: e.usage, subscription: e.subscription, email: e.email, checkedAt };
  }
  writeQuotaCache(qc);
}

// Check quota/status for a specific account
app.post('/api/check-quota/:id', async (req, res) => {
  const accounts = getStoredCodexAccounts();
  const acc = accounts.find(a => a.id === req.params.id);
  if (!acc) return res.status(404).json({ error: 'Account not found' });

  const { token, usage, subscription } = await fullCheck(acc, {
    subscriptionCache: readSubscriptionCache(),
    subscriptionPromises: new Map(),
  });
  const email = extractEmail(acc) || acc.name;
  const tokenResult = buildTokenResult(token);
  try { saveToQuotaCache([{ id: acc.id, email, token: tokenResult, usage, subscription }]); } catch (_) {}
  res.json({ id: acc.id, email, token: tokenResult, usage, subscription });
});

// Check all accounts
app.post('/api/check-all', async (req, res) => {
  const accounts = getStoredCodexAccounts();
  const sharedState = {
    subscriptionCache: readSubscriptionCache(),
    subscriptionPromises: new Map(),
  };
  const results = await Promise.all(accounts.map(async acc => {
    const { token, usage, subscription } = await fullCheck(acc, sharedState);
    return {
      id: acc.id,
      name: acc.name,
      email: extractEmail(acc) || acc.name,
      token: buildTokenResult(token),
      usage,
      subscription,
    };
  }));
  try { saveToQuotaCache(results); } catch (_) {}
  res.json({ results });
});


app.post('/api/oauth/codex/start', async (req, res) => {
  try {
    const session = createOAuthSession('codex', {}, getStoredCodexAccounts());
    const authUrl = buildNativeCodexAuthorizeUrl({
      state: session.state,
      codeChallenge: session.codeChallenge,
      redirectUri: session.redirectUri,
    });

    res.json({
      flowId: session.flowId,
      authUrl,
      redirectUri: session.redirectUri,
      expiresAt: session.expiresAt,
      state: session.state,
    });
  } catch (e) {
    res.status(502).json({
      error: 'Không khởi tạo được luồng OAuth',
      detail: e.message,
    });
  }
});

app.post('/api/oauth/codex/finish', async (req, res) => {
  const { flowId, callbackUrl, code, state } = req.body || {};
  const session = getOAuthSession(flowId);

  if (!flowId || !session) {
    return res.status(410).json({ error: 'OAuth session đã hết hạn hoặc không tồn tại' });
  }

  const parsed = callbackUrl
    ? parseOAuthCallback(callbackUrl)
    : { valid: Boolean(code), code: code || null, state: state || null, error: code ? null : 'Missing authorization code' };

  if (!parsed.valid) {
    return res.status(400).json({
      error: 'Callback OAuth không hợp lệ',
      detail: parsed.error,
    });
  }

  if (parsed.redirectUri && parsed.redirectUri !== session.redirectUri) {
    const parsedPath = new URL(parsed.redirectUri).pathname;
    const expectedPath = new URL(session.redirectUri).pathname;
    if (parsedPath !== expectedPath || !/^http:\/\/localhost(?::\d+)?$/i.test(new URL(parsed.redirectUri).origin)) {
      return res.status(400).json({
        error: 'Callback OAuth không hợp lệ',
        detail: 'Redirect URI không khớp với session hiện tại',
      });
    }
  }

  if ((parsed.state || null) !== (session.state || null)) {
    return res.status(400).json({
      error: 'Callback OAuth không hợp lệ',
      detail: 'State không khớp hoặc callback thuộc flow khác',
    });
  }

  try {
    const tokenPayload = await exchangeCodexAuthorizationCode({
      code: parsed.code,
      redirectUri: session.redirectUri,
      codeVerifier: session.codeVerifier,
    });

    const created = persistLocalCodexAccount(tokenPayload);
    const codexAccounts = getStoredCodexAccounts();
    destroyOAuthSession(flowId);

    res.json({
      success: true,
      count: codexAccounts.length,
      createdAccount: created ? {
        id: created.id,
        name: created.name,
        email: extractEmail(created) || created.name || null,
      } : null,
    });
  } catch (e) {
    res.status(e.statusCode || 502).json({
      error: 'Không thêm được OAuth account',
      detail: e.message,
    });
  }
});

// Apply selected account to codex auth
app.post('/api/apply/:id', (req, res) => {
  const accounts = getStoredCodexAccounts();
  const acc = accounts.find(a => a.id === req.params.id);
  if (!acc) return res.status(404).json({ error: 'Account not found' });

  const legacyAccount = normalizeLegacyCodexAccountShape(acc);
  const authPayload = buildAccountExportPayload(legacyAccount);

  try {
    fs.mkdirSync(path.dirname(CODEX_AUTH), { recursive: true });
    fs.writeFileSync(CODEX_AUTH, JSON.stringify(authPayload, null, 2));
    res.json({
      success: true,
      applied: legacyAccount.id,
      email: extractEmail(legacyAccount) || legacyAccount.name,
      accountId: authPayload.tokens.account_id,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to write auth file', detail: e.message });
  }
});

app.post('/api/accounts/:id/delete', (req, res) => {
  const accountId = String(req.params.id || '').trim();
  if (!accountId) return res.status(400).json({ error: 'Missing account id' });

  const before = getStoredCodexAccounts();
  const account = before.find(acc => acc.id === accountId);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  try {
    const result = deleteStoredCodexAccounts([accountId]);
    if (!result.deletedCount) {
      return res.status(409).json({ error: 'Account was not deleted' });
    }

    res.json({
      success: true,
      deletedCount: result.deletedCount,
      deletedIds: result.deletedIds,
      storage: result.storage,
      deletedAccount: {
        id: account.id,
        email: extractEmail(account) || account.name || null,
      },
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete account', detail: e.message });
  }
});

app.post('/api/accounts/delete-invalid', (req, res) => {
  const quotaCache = readQuotaCache();
  const accounts = getStoredCodexAccounts();
  const invalidIds = accounts
    .filter(acc => quotaCache?.[acc.id]?.token?.status && quotaCache[acc.id].token.status !== 'ok')
    .map(acc => acc.id);

  if (invalidIds.length === 0) {
    return res.json({ success: true, deletedCount: 0, deletedIds: [], storage: null });
  }

  try {
    const result = deleteStoredCodexAccounts(invalidIds);
    res.json({
      success: true,
      deletedCount: result.deletedCount,
      deletedIds: result.deletedIds,
      requestedIds: invalidIds,
      storage: result.storage,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete invalid accounts', detail: e.message });
  }
});

// Get currently active codex auth info
app.get('/api/current', (req, res) => {
  const auth = readCodexAuth();
  const codexAccounts = getStoredCodexAccounts();
  const current = resolveCurrentConnection(codexAccounts, auth);
  const subscriptionCache = readSubscriptionCache();
  const currentConnection = codexAccounts.find(acc => acc.id === current.connectionId) || null;
  const currentAccount = {
    accessToken: auth.tokens && auth.tokens.access_token || null,
    idToken: auth.tokens && auth.tokens.id_token || null,
    subscriptionExpiresAt: auth.subscriptionExpiresAt || auth.subscription_expires_at || null,
    subscriptionRenewsAt: auth.subscriptionRenewsAt || auth.subscription_renews_at || null,
    planType: auth.subscriptionPlan || auth.subscription_plan || null,
  };
  const jwtData = safeDecodeJWT(currentAccount.accessToken || '');
  const profile = jwtData && jwtData['https://api.openai.com/profile'] || {};
  const subscription = currentConnection
    ? resolveCachedSubscription(currentConnection, subscriptionCache)
    : resolveCachedSubscription(currentAccount, subscriptionCache);
  res.json({
    auth_mode: auth.auth_mode,
    email: profile.email || current.email || null,
    account_id: current.accountId,
    currentConnectionId: current.connectionId,
    currentMatchStrategy: current.matchStrategy,
    plan_type: subscription.plan,
    subscription,
    expires_at: auth.tokens && auth.tokens.expires_at || null,
    last_refresh: auth.last_refresh || null,
  });
});

app.get('/api/accounts/export', (req, res) => {
  const accounts = getStoredCodexAccounts();
  const payload = accounts.map(buildAccountExportPayload);
  const filename = `codex-accounts-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(JSON.stringify(payload, null, 2));
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`codexauth server running on http://localhost:${PORT}`);
  });
}

module.exports = {
  app,
  safeDecodeJWT,
  tokenFingerprint,
  extractEmail,
  extractExpires,
  extractPlanType,
  extractSubscription,
  extractSubscriptionFromAccountsCheck,
  parseOAuthCallback,
  mergeSubscriptionData,
  sanitizeDashboardError,
  extractAccountId,
  extractChatgptUserId,
  resolveCurrentConnection,
  buildAccountExportPayload,
  expandHomePath,
  resolveRuntimePath,
  getRuntimePaths,
  normalizeLegacyCodexAccountShape,
  deleteStoredCodexAccounts,
  getStoredCodexAccounts,
  createCodeVerifier,
  createCodeChallenge,
  buildNativeCodexAuthorizeUrl,
  buildLocalCodexAccountRecord,
  persistLocalCodexAccount,
  readLocalCodexAccounts,
};
