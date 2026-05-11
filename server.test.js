const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  buildAccountExportPayload,
  buildLocalCodexAccountRecord,
  buildNativeCodexAuthorizeUrl,
  createCodeChallenge,
  deleteStoredCodexAccounts,
  extractExpires,
  extractSubscriptionFromAccountsCheck,
  extractSubscription,
  getRuntimePaths,
  mergeSubscriptionData,
  normalizeLegacyCodexAccountShape,
  parseOAuthCallback,
  persistLocalCodexAccount,
  readLocalCodexAccounts,
  resolveCurrentConnection,
  resolveRuntimePath,
  sanitizeDashboardError,
} = require('./server');

function makeJwt(payload) {
  const encode = value => Buffer.from(JSON.stringify(value))
    .toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test('extractExpires returns null when JWT has no exp', () => {
  const token = makeJwt({
    'https://api.openai.com/auth': { chatgpt_account_id: 'team-1' },
  });

  assert.equal(extractExpires({ accessToken: token }), null);
});

test('resolveCurrentConnection prefers exact token match when account_id is shared', () => {
  const sharedAccountId = 'team-1';
  const accountA = {
    id: 'acc-a',
    accessToken: makeJwt({
      exp: 1770000000,
      'https://api.openai.com/auth': {
        chatgpt_account_id: sharedAccountId,
        chatgpt_user_id: 'user-a',
      },
      'https://api.openai.com/profile': { email: 'a@example.com' },
    }),
    idToken: makeJwt({
      email: 'a@example.com',
      'https://api.openai.com/auth': { chatgpt_account_id: sharedAccountId },
    }),
  };
  const accountB = {
    id: 'acc-b',
    accessToken: makeJwt({
      exp: 1770000001,
      'https://api.openai.com/auth': {
        chatgpt_account_id: sharedAccountId,
        chatgpt_user_id: 'user-b',
      },
      'https://api.openai.com/profile': { email: 'b@example.com' },
    }),
    idToken: makeJwt({
      email: 'b@example.com',
      'https://api.openai.com/auth': { chatgpt_account_id: sharedAccountId },
    }),
  };

  const current = resolveCurrentConnection([accountA, accountB], {
    tokens: {
      access_token: accountB.accessToken,
      id_token: accountB.idToken,
      account_id: sharedAccountId,
    },
  });

  assert.equal(current.connectionId, 'acc-b');
  assert.equal(current.matchStrategy, 'token');
});

test('resolveCurrentConnection falls back to unique user id when token is stale', () => {
  const account = {
    id: 'acc-only',
    accessToken: makeJwt({
      exp: 1770000002,
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'team-2',
        chatgpt_user_id: 'user-only',
      },
      'https://api.openai.com/profile': { email: 'only@example.com' },
    }),
  };

  const current = resolveCurrentConnection([account], {
    tokens: {
      access_token: makeJwt({
        exp: 1770000999,
        'https://api.openai.com/auth': {
          chatgpt_account_id: 'team-2',
          chatgpt_user_id: 'user-only',
        },
        'https://api.openai.com/profile': { email: 'only@example.com' },
      }),
      account_id: 'team-2',
    },
  });

  assert.equal(current.connectionId, 'acc-only');
  assert.equal(current.matchStrategy, 'userId');
});

test('sanitizeDashboardError hides the stale gpt-5.5 dashboard error', () => {
  const result = sanitizeDashboardError(
    400,
    '[400]: {"detail":"The \'gpt-5.5\' model is not supported when using Codex with a ChatGPT account."}',
  );

  assert.deepEqual(result, {
    errorCode: null,
    lastError: null,
  });
});

test('sanitizeDashboardError preserves other errors', () => {
  const result = sanitizeDashboardError(429, 'Rate limit');

  assert.deepEqual(result, {
    errorCode: 429,
    lastError: 'Rate limit',
  });
});

test('extractSubscription prefers explicit subscription expiry and JWT plan type', () => {
  const account = {
    accessToken: makeJwt({
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'team-3',
        chatgpt_plan_type: 'team',
      },
    }),
    subscriptionExpiresAt: '1778000000',
  };

  assert.deepEqual(extractSubscription(account), {
    plan: 'team',
    expiresAt: '2026-05-05T16:53:20.000Z',
  });
});

test('extractSubscriptionFromAccountsCheck prefers the requested account entry', () => {
  const result = extractSubscriptionFromAccountsCheck({
    accounts: {
      'team-1': {
        account: {
          account_id: 'team-1',
          plan_type: 'team',
          name: 'Workspace A',
        },
        entitlement: {
          has_active_subscription: true,
          subscription_plan: 'chatgptteamplan',
          expires_at: '2026-05-19T11:49:04+00:00',
          renews_at: '2026-05-19T05:49:04+00:00',
          billing_period: 'monthly',
        },
        last_active_subscription: {
          will_renew: true,
        },
      },
      default: {
        account: {
          account_id: 'team-2',
          plan_type: 'free',
          name: 'Workspace B',
        },
      },
    },
  }, 'team-1', 'free');

  assert.deepEqual(result, {
    available: true,
    accountId: 'team-1',
    plan: 'team',
    subscriptionPlan: 'chatgptteamplan',
    expiresAt: '2026-05-19T11:49:04.000Z',
    renewsAt: '2026-05-19T05:49:04.000Z',
    cancelsAt: null,
    billingPeriod: 'monthly',
    hasActiveSubscription: true,
    willRenew: true,
    workspaceName: 'Workspace A',
    checkedAt: result.checkedAt,
    source: 'accounts/check',
  });
  assert.ok(result.checkedAt);
});

test('mergeSubscriptionData keeps live expiry and stored plan together', () => {
  const result = mergeSubscriptionData(
    { plan: 'team', expiresAt: null },
    { expiresAt: '2026-05-19T11:49:04+00:00', willRenew: true, source: 'accounts/check' },
  );

  assert.deepEqual(result, {
    plan: 'team',
    subscriptionPlan: null,
    expiresAt: '2026-05-19T11:49:04.000Z',
    renewsAt: null,
    cancelsAt: null,
    billingPeriod: null,
    hasActiveSubscription: null,
    willRenew: true,
    workspaceName: null,
    checkedAt: null,
    source: 'accounts/check',
  });
});

test('parseOAuthCallback extracts code and state from callback URL', () => {
  const result = parseOAuthCallback('http://localhost:1455/auth/callback?code=abc123&state=flow-1');

  assert.deepEqual(result, {
    valid: true,
    code: 'abc123',
    state: 'flow-1',
    error: null,
    redirectUri: 'http://localhost:1455/auth/callback',
  });
});

test('parseOAuthCallback surfaces oauth errors from callback URL', () => {
  const result = parseOAuthCallback('http://localhost:1455/auth/callback?error=access_denied&error_description=User%20cancelled');

  assert.deepEqual(result, {
    valid: false,
    error: 'User cancelled',
    code: null,
    state: null,
  });
});

test('buildAccountExportPayload returns the exportable auth json shape for an account', () => {
  const account = {
    idToken: 'id-token-value',
    accessToken: makeJwt({
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'team-9',
      },
    }),
    refreshToken: 'refresh-token-value',
    updatedAt: '2026-04-24T02:48:56.556Z',
  };

  assert.deepEqual(buildAccountExportPayload(account), {
    auth_mode: 'chatgpt',
    OPENAI_API_KEY: null,
    tokens: {
      id_token: 'id-token-value',
      access_token: account.accessToken,
      refresh_token: 'refresh-token-value',
      account_id: 'team-9',
    },
    last_refresh: '2026-04-24T02:48:56.556Z',
  });
});

test('buildNativeCodexAuthorizeUrl includes PKCE and redirect parameters', () => {
  const codeChallenge = createCodeChallenge('verifier-value');
  const url = new URL(buildNativeCodexAuthorizeUrl({
    state: 'state-1',
    codeChallenge,
    redirectUri: 'http://localhost:1455/auth/callback',
  }));

  assert.equal(url.origin, 'https://auth.openai.com');
  assert.equal(url.pathname, '/oauth/authorize');
  assert.equal(url.searchParams.get('client_id'), 'app_EMoamEEZ73f0CkXaXp7hrann');
  assert.equal(url.searchParams.get('redirect_uri'), 'http://localhost:1455/auth/callback');
  assert.equal(url.searchParams.get('scope'), 'openid profile email offline_access');
  assert.equal(url.searchParams.get('state'), 'state-1');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('code_challenge'), codeChallenge);
});

test('buildLocalCodexAccountRecord maps OAuth token response into db.json-style account', () => {
  const account = buildLocalCodexAccountRecord({
    access_token: makeJwt({
      exp: 1770000000,
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'team-local',
        chatgpt_user_id: 'user-local',
        chatgpt_plan_type: 'plus',
      },
      'https://api.openai.com/profile': { email: 'local@example.com' },
    }),
    refresh_token: 'refresh-local',
    id_token: makeJwt({
      email: 'local@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'team-local',
        chatgpt_plan_type: 'plus',
      },
    }),
    expires_in: 3600,
  }, null, 7);

  assert.equal(account.provider, 'codex');
  assert.equal(account.authType, 'oauth');
  assert.equal(account.email, 'local@example.com');
  assert.equal(account.priority, 7);
  assert.equal(account.refreshToken, 'refresh-local');
  assert.equal(account.idToken != null, true);
  assert.equal(account.providerSpecificData.chatgptAccountId, 'team-local');
  assert.equal(account.providerSpecificData.chatgptPlanType, 'plus');
});

test('persistLocalCodexAccount rejects token payloads without idToken', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codexauth-local-db-missing-id-'));
  const dbPath = path.join(dir, 'codex_accounts.json');

  assert.throws(() => persistLocalCodexAccount({
    access_token: 'access-only',
    refresh_token: 'refresh-only',
  }, dbPath), /Thiếu idToken/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('persistLocalCodexAccount stores and reloads local db.json-style accounts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codexauth-local-db-'));
  const dbPath = path.join(dir, 'codex_accounts.json');
  const accessToken = makeJwt({
    exp: 1770000000,
    'https://api.openai.com/auth': {
      chatgpt_account_id: 'team-store',
      chatgpt_user_id: 'user-store',
      chatgpt_plan_type: 'plus',
    },
    'https://api.openai.com/profile': { email: 'store@example.com' },
  });
  const idToken = makeJwt({
    email: 'store@example.com',
    'https://api.openai.com/auth': {
      chatgpt_account_id: 'team-store',
      chatgpt_plan_type: 'plus',
    },
  });

  const saved = persistLocalCodexAccount({
    access_token: accessToken,
    refresh_token: 'refresh-store',
    id_token: idToken,
    expires_in: 7200,
  }, dbPath);

  const loaded = readLocalCodexAccounts(dbPath);

  assert.equal(saved.email, 'store@example.com');
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].email, 'store@example.com');
  assert.equal(loaded[0].refreshToken, 'refresh-store');
  assert.equal(loaded[0].idToken, idToken);
  assert.equal(loaded[0].providerSpecificData.chatgptAccountId, 'team-store');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('getRuntimePaths defaults to the home-relative Codex auth file', () => {
  const homeDir = path.join(path.sep, 'Users', 'alice');
  const paths = getRuntimePaths({}, homeDir);

  assert.deepEqual(paths, {
    codexAuth: path.join(homeDir, '.codex', 'auth.json'),
  });
});

test('normalizeLegacyCodexAccountShape restores db.json-style token keys from aliases', () => {
  assert.deepEqual(normalizeLegacyCodexAccountShape({
    id: 'acc-legacy',
    provider: 'codex',
    auth_type: 'oauth',
    email: 'legacy@example.com',
    priority: '4',
    is_active: 1,
    access_token: 'access-token',
    refresh_token: 'refresh-token',
    id_token: 'id-token',
    expires_at: '2026-05-19T05:49:04.000Z',
    test_status: 'active',
    expires_in: 123,
    consecutive_use_count: '2',
    error_code: 401,
    backoff_level: '3',
    last_error: 'bad token',
    last_error_at: '2026-05-11T02:49:30.188Z',
    created_at: '2026-05-07T05:42:19.919Z',
    updated_at: '2026-05-11T02:49:30.188Z',
    providerSpecificData: {
      chatgptAccountId: 'team-legacy',
      chatgptPlanType: 'plus',
    },
  }), {
    id: 'acc-legacy',
    provider: 'codex',
    auth_type: 'oauth',
    email: 'legacy@example.com',
    priority: 4,
    is_active: 1,
    access_token: 'access-token',
    refresh_token: 'refresh-token',
    id_token: 'id-token',
    expires_at: '2026-05-19T05:49:04.000Z',
    test_status: 'active',
    expires_in: 123,
    consecutive_use_count: '2',
    error_code: 401,
    backoff_level: '3',
    last_error: 'bad token',
    last_error_at: '2026-05-11T02:49:30.188Z',
    created_at: '2026-05-07T05:42:19.919Z',
    updated_at: '2026-05-11T02:49:30.188Z',
    providerSpecificData: {
      chatgptAccountId: 'team-legacy',
      chatgptPlanType: 'plus',
    },
    authType: 'oauth',
    name: 'legacy@example.com',
    isActive: true,
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    idToken: 'id-token',
    expiresAt: '2026-05-19T05:49:04.000Z',
    testStatus: 'active',
    expiresIn: 123,
    lastUsedAt: null,
    consecutiveUseCount: 2,
    errorCode: 401,
    backoffLevel: 3,
    lastError: 'bad token',
    lastErrorAt: '2026-05-11T02:49:30.188Z',
    createdAt: '2026-05-07T05:42:19.919Z',
    updatedAt: '2026-05-11T02:49:30.188Z',
  });
});

test('resolveRuntimePath supports env overrides and tilde expansion', () => {
  const homeDir = path.join(path.sep, 'Users', 'alice');
  const customAuth = path.join(homeDir, 'custom', 'auth.json');

  assert.equal(
    resolveRuntimePath(customAuth, ['.codex', 'auth.json'], homeDir),
    path.resolve(customAuth),
  );
  assert.equal(
    resolveRuntimePath('~/AppData/Roaming/Codex/auth.json', ['.codex', 'auth.json'], homeDir),
    path.resolve(path.join(homeDir, 'AppData/Roaming/Codex/auth.json')),
  );
});

test('deleteStoredCodexAccounts removes only matching codex ids from local providerConnections', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codexauth-json-delete-'));
  const jsonPath = path.join(dir, 'codex_accounts.json');
  fs.writeFileSync(jsonPath, JSON.stringify({
    providerConnections: [
      { id: 'codex-1', provider: 'codex' },
      { id: 'codex-2', provider: 'codex' },
      { id: 'other-1', provider: 'openai' },
    ],
  }, null, 2));

  const result = deleteStoredCodexAccounts(['codex-2', 'missing-id'], jsonPath);
  const updated = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

  assert.deepEqual(result, {
    deletedIds: ['codex-2'],
    deletedCount: 1,
    storage: 'local',
  });
  assert.deepEqual(updated.providerConnections, [
    { id: 'codex-1', provider: 'codex' },
    { id: 'other-1', provider: 'openai' },
  ]);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('deleteStoredCodexAccounts does not delete non-codex rows even when ids match', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codexauth-json-guard-'));
  const jsonPath = path.join(dir, 'codex_accounts.json');
  fs.writeFileSync(jsonPath, JSON.stringify({
    providerConnections: [
      { id: 'shared-id', provider: 'openai' },
      { id: 'codex-1', provider: 'codex' },
    ],
  }, null, 2));

  const result = deleteStoredCodexAccounts(['shared-id'], jsonPath);
  const updated = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

  assert.deepEqual(result, {
    deletedIds: [],
    deletedCount: 0,
    storage: 'local',
  });
  assert.deepEqual(updated.providerConnections, [
    { id: 'shared-id', provider: 'openai' },
    { id: 'codex-1', provider: 'codex' },
  ]);

  fs.rmSync(dir, { recursive: true, force: true });
});
