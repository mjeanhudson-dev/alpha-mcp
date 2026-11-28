/**
 * Eloquent Commercial MCP Paywall, Billing Webhooks & Clerk Key Portal Worker.
 * Hostname: https://api.eloquentwin.com
 *
 * Routes:
 *   GET  /health                             -> upstream zero-privilege commercial MCP health
 *   GET  /.well-known/oauth-protected-resource -> RFC 9728 commercial resource metadata
 *   POST /mcp                                -> Edge paywall: SHA-256 API key lookup in ENTITLEMENTS_KV,
 *                                               401/402/429 enforcement, signed X-Eloquent-Edge-Secret forward
 *   POST /webhook/polar                      -> Standard Webhooks HMAC-SHA256 -> upsert/revoke entitlement
 *   POST /webhook/stripe                     -> Stripe-Signature HMAC-SHA256 -> upsert/revoke entitlement
 *   GET  /api/portal/status                  -> Clerk RS256 JWT verified subscription & key summary
 *   POST /api/portal/keys/rotate             -> Clerk RS256 JWT verified key mint/rotation (elq_live_...)
 *   POST /api/admin/entitlement              -> X-Eloquent-Edge-Secret gated comp/test entitlement admin
 */

const ALLOWED_ORIGINS_DEFAULT = 'https://eloquentwin.com,https://www.eloquentwin.com,https://aether-webos-kit.pages.dev';
const DEFAULT_CLERK_JWKS_URL = 'https://alert-elk-3324.clerk.accounts.dev/.well-known/jwks.json';
const DEFAULT_CHECKOUT_URL = 'https://eloquentwin.com/#pricing';
const DEFAULT_PORTAL_URL = 'https://eloquentwin.com/portal.html';
const MAX_WEBHOOK_BYTES = 64 * 1024;
const TOLERANCE_SECONDS = 300;
const HEX64 = /^[0-9a-f]{64}$/;
const TIER_DAILY_LIMITS = { demo: 25, pro: 1000, studio: 5000 };

let jwksCache = { url: '', fetchedAt: 0, keys: [] };

function corsHeaders(origin, env) {
  const allowed = (env.ALLOWED_ORIGINS || ALLOWED_ORIGINS_DEFAULT).split(',').map((s) => s.trim()).filter(Boolean);
  const h = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    vary: 'Origin',
  };
  if (origin && allowed.includes(origin)) {
    h['access-control-allow-origin'] = origin;
    h['access-control-allow-methods'] = 'GET, POST, OPTIONS';
    h['access-control-allow-headers'] = 'authorization, content-type, mcp-protocol-version, mcp-session-id';
    h['access-control-max-age'] = '600';
  }
  return h;
}

function jsonResp(body, status, origin, env, extra = {}) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(origin, env), ...extra },
  });
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(str) {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));
}

function timingSafeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
}

function base64UrlToBytes(b64u) {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64u.length % 4)) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function verifyStripeSig(rawBody, header, secret) {
  const parts = header.split(',').map((p) => p.trim().split('='));
  const ts = Number(parts.find((p) => p[0] === 't')?.[1]);
  const sigs = parts.filter((p) => p[0] === 'v1' && HEX64.test(p[1] || '')).map((p) => p[1]);
  if (!ts || sigs.length === 0 || Math.abs(Date.now() / 1000 - ts) > TOLERANCE_SECONDS) return false;
  const expected = toHex(await hmacSha256(new TextEncoder().encode(secret), `${ts}.${rawBody}`));
  return sigs.some((s) => timingSafeEqual(expected, s));
}

async function verifyPolarSig(rawBody, headers, secret) {
  const id = headers.get('webhook-id') || '';
  const ts = Number(headers.get('webhook-timestamp'));
  const sigHeader = headers.get('webhook-signature') || '';
  if (!id || !ts || Math.abs(Date.now() / 1000 - ts) > TOLERANCE_SECONDS) return false;
  const candidates = [new TextEncoder().encode(secret)];
  try {
    const clean = secret.replace(/^whsec_/, '');
    const bin = atob(clean);
    candidates.push(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch { /* raw text secret */ }
  const received = sigHeader.split(' ').filter((s) => s.startsWith('v1,')).map((s) => s.slice(3));
  if (received.length === 0) return false;
  for (const keyBytes of candidates) {
    const digest = await hmacSha256(keyBytes, `${id}.${ts}.${rawBody}`);
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)));
    if (received.some((s) => timingSafeEqual(s, expected))) return true;
  }
  return false;
}

async function verifyClerkJwt(token, env) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[1])));
  } catch {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (!payload || typeof payload.exp !== 'number' || payload.exp < now) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now + 30) return null;
  if (header.alg !== 'RS256' || !header.kid) return null;

  const jwksUrl = env.CLERK_JWKS_URL || DEFAULT_CLERK_JWKS_URL;
  if (jwksCache.url !== jwksUrl || Date.now() - jwksCache.fetchedAt > 300_000 || jwksCache.keys.length === 0) {
    const resp = await fetch(jwksUrl, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return null;
    const data = await resp.json();
    jwksCache = { url: jwksUrl, fetchedAt: Date.now(), keys: Array.isArray(data.keys) ? data.keys : [] };
  }
  const jwk = jwksCache.keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const sig = base64UrlToBytes(parts[2]);
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, signed);
  return valid ? payload : null;
}

function generateApiKey(prefix = 'elq_live_') {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return prefix + toHex(bytes);
}

async function upsertEntitlement(env, { email, provider, subscriptionId, tier, status, periodEnd }) {
  const normEmail = String(email || '').trim().toLowerCase();
  if (!normEmail) return null;
  const emailHash = await sha256Hex(normEmail);
  const entKey = `ent:${emailHash}`;
  const existing = (await env.ENTITLEMENTS_KV.get(entKey, 'json')) || {};
  const cleanTier = TIER_DAILY_LIMITS[tier] ? tier : 'pro';
  const rec = {
    email_hash: emailHash,
    provider: provider || existing.provider || 'manual',
    subscription_id: subscriptionId || existing.subscription_id || '',
    tier: cleanTier,
    status: status || 'active',
    daily_limit: TIER_DAILY_LIMITS[cleanTier] || 1000,
    period_end: periodEnd || existing.period_end || null,
    active_key_hash: existing.active_key_hash || null,
    key_prefix: existing.key_prefix || null,
    updated_at: new Date().toISOString(),
  };
  await env.ENTITLEMENTS_KV.put(entKey, JSON.stringify(rec));
  if (rec.subscription_id) {
    await env.ENTITLEMENTS_KV.put(`sub:${rec.provider}:${rec.subscription_id}`, emailHash);
  }
  // Propagate status/tier changes immediately to any minted API key hash
  if (rec.active_key_hash) {
    await env.ENTITLEMENTS_KV.put(`keyhash:${rec.active_key_hash}`, JSON.stringify({
      email_hash: emailHash,
      tier: rec.tier,
      status: rec.status,
      daily_limit: rec.daily_limit,
      period_end: rec.period_end,
      key_prefix: rec.key_prefix,
      updated_at: rec.updated_at,
    }));
  }
  return rec;
}

async function mintOrRotateKey(env, emailHash, prefix = 'elq_live_') {
  const entKey = `ent:${emailHash}`;
  const ent = await env.ENTITLEMENTS_KV.get(entKey, 'json');
  if (!ent || ent.status !== 'active') return { ok: false, error: 'subscription_inactive' };
  if (ent.active_key_hash) {
    await env.ENTITLEMENTS_KV.delete(`keyhash:${ent.active_key_hash}`);
  }
  const plaintext = generateApiKey(prefix);
  const keyHash = await sha256Hex(plaintext);
  const keyPrefix = plaintext.slice(0, 16) + '...';
  ent.active_key_hash = keyHash;
  ent.key_prefix = keyPrefix;
  ent.updated_at = new Date().toISOString();
  await env.ENTITLEMENTS_KV.put(entKey, JSON.stringify(ent));
  await env.ENTITLEMENTS_KV.put(`keyhash:${keyHash}`, JSON.stringify({
    email_hash: emailHash,
    tier: ent.tier,
    status: ent.status,
    daily_limit: ent.daily_limit || TIER_DAILY_LIMITS[ent.tier] || 1000,
    period_end: ent.period_end || null,
    key_prefix: keyPrefix,
    updated_at: ent.updated_at,
  }));
  return { ok: true, api_key: plaintext, key_prefix: keyPrefix, tier: ent.tier, daily_limit: ent.daily_limit };
}

async function forwardToCommercialOrigin(request, env, tier, tenantHash) {
  const originBase = String(env.COMMERCIAL_ORIGIN || '').trim();
  const edgeSecret = String(env.ELOQUENT_EDGE_SHARED_SECRET || '').trim();
  if (!originBase || !edgeSecret) {
    return jsonResp({ error: 'gateway_unconfigured' }, 503, request.headers.get('origin') || '', env);
  }
  const incoming = new URL(request.url);
  const target = new URL(incoming.pathname + incoming.search, originBase);
  const headers = new Headers();
  for (const name of ['accept', 'content-type', 'mcp-protocol-version', 'mcp-session-id', 'user-agent']) {
    const val = request.headers.get(name);
    if (val) headers.set(name, val);
  }
  headers.set('x-forwarded-proto', 'https');
  headers.set('x-forwarded-host', incoming.host || 'api.eloquentwin.com');
  headers.set('x-eloquent-edge-secret', edgeSecret);
  if (tier) headers.set('x-eloquent-tier', tier);
  if (tenantHash) headers.set('x-eloquent-tenant-hash', tenantHash.slice(0, 16));
  const method = request.method.toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD';
  return fetch(target.toString(), {
    method,
    headers,
    body: hasBody ? request.body : undefined,
    redirect: 'manual',
    signal: AbortSignal.timeout(30000),
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin') || '';

    if (request.method === 'OPTIONS') {
      return jsonResp(null, 204, origin, env);
    }

    // 1. Public discovery endpoints
    if ((request.method === 'GET' || request.method === 'HEAD') && (url.pathname === '/' || url.pathname === '/health' || url.pathname === '/.well-known/oauth-protected-resource')) {
      return forwardToCommercialOrigin(request, env, 'public', '');
    }

    if (!env.ENTITLEMENTS_KV) {
      return jsonResp({ error: 'entitlements_kv_unconfigured' }, 503, origin, env);
    }

    // 2. Payment Webhooks (Polar & Stripe)
    if (request.method === 'POST' && (url.pathname === '/webhook/polar' || url.pathname === '/webhook/stripe')) {
      const provider = url.pathname === '/webhook/polar' ? 'polar' : 'stripe';
      const secret = provider === 'polar' ? env.POLAR_WEBHOOK_SECRET : env.STRIPE_WEBHOOK_SECRET;
      if (!secret) return jsonResp({ error: 'webhook_unconfigured' }, 503, origin, env);
      const rawBody = await request.text();
      if (new TextEncoder().encode(rawBody).length > MAX_WEBHOOK_BYTES) {
        return jsonResp({ error: 'payload_too_large' }, 413, origin, env);
      }
      const sigOk = provider === 'stripe'
        ? await verifyStripeSig(rawBody, request.headers.get('stripe-signature') || '', secret)
        : await verifyPolarSig(rawBody, request.headers, secret);
      if (!sigOk) return jsonResp({ error: 'bad_signature' }, 401, origin, env);

      let ev;
      try { ev = JSON.parse(rawBody); } catch { return jsonResp({ error: 'bad_json' }, 400, origin, env); }
      const evId = provider === 'stripe' ? ev.id : (request.headers.get('webhook-id') || ev.id);
      if (evId) {
        const seenKey = `ev:${provider}:${evId}`;
        if (await env.ENTITLEMENTS_KV.get(seenKey)) {
          return jsonResp({ ok: true, idempotent_replay: true }, 200, origin, env);
        }
        await env.ENTITLEMENTS_KV.put(seenKey, '1', { expirationTtl: 60 * 60 * 24 * 30 });
      }

      if (provider === 'stripe') {
        const obj = ev.data?.object || {};
        const email = obj.customer_details?.email || obj.customer_email || '';
        const subId = obj.subscription || obj.id || '';
        if (ev.type === 'checkout.session.completed' || ev.type === 'invoice.paid') {
          if (email) await upsertEntitlement(env, { email, provider: 'stripe', subscriptionId: subId, tier: 'pro', status: 'active' });
        } else if (ev.type === 'customer.subscription.deleted' || ev.type === 'charge.refunded') {
          const mappedHash = subId ? await env.ENTITLEMENTS_KV.get(`sub:stripe:${subId}`) : null;
          if (mappedHash) {
            const cur = await env.ENTITLEMENTS_KV.get(`ent:${mappedHash}`, 'json');
            if (cur) {
              cur.status = 'revoked';
              cur.updated_at = new Date().toISOString();
              await env.ENTITLEMENTS_KV.put(`ent:${mappedHash}`, JSON.stringify(cur));
              if (cur.active_key_hash) {
                const kh = await env.ENTITLEMENTS_KV.get(`keyhash:${cur.active_key_hash}`, 'json');
                if (kh) {
                  kh.status = 'revoked';
                  await env.ENTITLEMENTS_KV.put(`keyhash:${cur.active_key_hash}`, JSON.stringify(kh));
                }
              }
            }
          }
        }
      } else {
        const data = ev.data || {};
        const email = data.customer?.email || data.user?.email || '';
        const subId = data.subscription_id || data.id || '';
        if (ev.type === 'order.created' || ev.type === 'subscription.active' || ev.type === 'subscription.created') {
          if (email) await upsertEntitlement(env, { email, provider: 'polar', subscriptionId: subId, tier: 'pro', status: 'active' });
        } else if (ev.type === 'subscription.revoked' || ev.type === 'subscription.canceled' || ev.type === 'order.refunded') {
          const mappedHash = subId ? await env.ENTITLEMENTS_KV.get(`sub:polar:${subId}`) : (email ? await sha256Hex(email.toLowerCase()) : null);
          if (mappedHash) {
            const cur = await env.ENTITLEMENTS_KV.get(`ent:${mappedHash}`, 'json');
            if (cur) {
              cur.status = 'revoked';
              cur.updated_at = new Date().toISOString();
              await env.ENTITLEMENTS_KV.put(`ent:${mappedHash}`, JSON.stringify(cur));
              if (cur.active_key_hash) {
                const kh = await env.ENTITLEMENTS_KV.get(`keyhash:${cur.active_key_hash}`, 'json');
                if (kh) {
                  kh.status = 'revoked';
                  await env.ENTITLEMENTS_KV.put(`keyhash:${cur.active_key_hash}`, JSON.stringify(kh));
                }
              }
            }
          }
        }
      }
      return jsonResp({ ok: true }, 200, origin, env);
    }

    // 3. Owner Admin Entitlement Endpoint (for testing, comped seats & verification)
    if (request.method === 'POST' && url.pathname === '/api/admin/entitlement') {
      const edgeSecret = String(env.ELOQUENT_EDGE_SHARED_SECRET || '').trim();
      const got = (request.headers.get('x-eloquent-edge-secret') || '').trim();
      if (!edgeSecret || !timingSafeEqual(got, edgeSecret)) {
        return jsonResp({ error: 'forbidden' }, 403, origin, env);
      }
      let body;
      try { body = await request.json(); } catch { return jsonResp({ error: 'bad_json' }, 400, origin, env); }
      const action = String(body.action || 'upsert');
      if (action === 'upsert') {
        const rec = await upsertEntitlement(env, {
          email: body.email,
          provider: body.provider || 'admin',
          subscriptionId: body.subscription_id || '',
          tier: body.tier || 'pro',
          status: body.status || 'active',
          periodEnd: body.period_end || null,
        });
        if (!rec) return jsonResp({ error: 'email_required' }, 400, origin, env);
        let minted = null;
        if (body.mint_key && rec.status === 'active') {
          minted = await mintOrRotateKey(env, rec.email_hash, body.key_prefix || 'elq_live_');
        }
        return jsonResp({ ok: true, entitlement: rec, minted }, 200, origin, env);
      }
      if (action === 'revoke' && body.email) {
        const rec = await upsertEntitlement(env, { email: body.email, status: 'revoked', tier: body.tier || 'pro' });
        return jsonResp({ ok: true, entitlement: rec }, 200, origin, env);
      }
      return jsonResp({ error: 'unknown_action' }, 400, origin, env);
    }

    // 4. Customer Portal Endpoints (Clerk RS256 JWT authenticated)
    if (url.pathname === '/api/portal/status' || url.pathname === '/api/portal/keys/rotate') {
      const auth = request.headers.get('authorization') || '';
      const jwt = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      const claims = await verifyClerkJwt(jwt, env);
      if (!claims) return jsonResp({ error: 'clerk_auth_required' }, 401, origin, env);
      const email = String(claims.email || claims.primary_email_address || '').trim().toLowerCase();
      if (!email) return jsonResp({ error: 'email_claim_missing' }, 400, origin, env);
      const emailHash = await sha256Hex(email);
      const ent = await env.ENTITLEMENTS_KV.get(`ent:${emailHash}`, 'json');

      if (url.pathname === '/api/portal/status' && request.method === 'GET') {
        const dayKey = `rl:day:${new Date().toISOString().slice(0, 10)}:${ent?.active_key_hash?.slice(0, 16) || 'none'}`;
        const usedToday = ent?.active_key_hash ? (Number(await env.ENTITLEMENTS_KV.get(dayKey)) || 0) : 0;
        return jsonResp({
          status: ent?.status || 'none',
          tier: ent?.tier || 'free',
          key_prefix: ent?.key_prefix || null,
          usage_today: usedToday,
          daily_limit: ent?.daily_limit || 0,
          mcp_url: 'https://api.eloquentwin.com/mcp',
          checkout_url: env.CHECKOUT_URL || DEFAULT_CHECKOUT_URL,
          billing_portal_url: env.BILLING_PORTAL_URL || null,
        }, 200, origin, env);
      }

      if (url.pathname === '/api/portal/keys/rotate' && request.method === 'POST') {
        const minted = await mintOrRotateKey(env, emailHash, 'elq_live_');
        if (!minted.ok) {
          return jsonResp({ error: 'subscription_required', checkout_url: env.CHECKOUT_URL || DEFAULT_CHECKOUT_URL }, 402, origin, env);
        }
        return jsonResp(minted, 200, origin, env);
      }
      return jsonResp({ error: 'method_not_allowed' }, 405, origin, env);
    }

    // 5. Paywalled Commercial MCP Endpoint (/mcp)
    if (url.pathname === '/mcp' || url.pathname === '/mcp/') {
      const auth = request.headers.get('authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      const wwwAuth = 'Bearer resource_metadata="https://api.eloquentwin.com/.well-known/oauth-protected-resource"';

      if (!token || !/^elq_(?:live|test)_[0-9a-f]{24,}$/i.test(token)) {
        return jsonResp(
          {
            error: 'api_key_required',
            message: 'Active Eloquent Commercial MCP key required (Authorization: Bearer elq_live_...).',
            checkout_url: env.CHECKOUT_URL || DEFAULT_CHECKOUT_URL,
            portal_url: DEFAULT_PORTAL_URL,
          },
          401,
          origin,
          env,
          { 'www-authenticate': wwwAuth }
        );
      }

      const keyHash = await sha256Hex(token);
      const ent = await env.ENTITLEMENTS_KV.get(`keyhash:${keyHash}`, 'json');
      if (!ent) {
        return jsonResp(
          { error: 'invalid_api_key', message: 'API key not recognized or rotated.', portal_url: DEFAULT_PORTAL_URL },
          401,
          origin,
          env,
          { 'www-authenticate': wwwAuth }
        );
      }
      const expired = ent.period_end && Date.parse(ent.period_end) < Date.now();
      if (ent.status !== 'active' || expired) {
        return jsonResp(
          {
            error: 'subscription_inactive',
            status: expired ? 'expired' : ent.status,
            message: 'Your Eloquent MCP subscription is inactive. Renew to restore access.',
            upgrade_url: env.CHECKOUT_URL || DEFAULT_CHECKOUT_URL,
          },
          402,
          origin,
          env
        );
      }

      // Per-key daily quota enforcement at Cloudflare Edge
      const limit = Number(ent.daily_limit) || TIER_DAILY_LIMITS[ent.tier] || 1000;
      const dayKey = `rl:day:${new Date().toISOString().slice(0, 10)}:${keyHash.slice(0, 16)}`;
      const used = Number(await env.ENTITLEMENTS_KV.get(dayKey)) || 0;
      if (used >= limit) {
        return jsonResp(
          { error: 'daily_quota_exceeded', used, limit, upgrade_url: env.CHECKOUT_URL || DEFAULT_CHECKOUT_URL },
          429,
          origin,
          env,
          { 'retry-after': '3600' }
        );
      }
      await env.ENTITLEMENTS_KV.put(dayKey, String(used + 1), { expirationTtl: 60 * 60 * 26 });

      return forwardToCommercialOrigin(request, env, ent.tier || 'pro', ent.email_hash || keyHash);
    }

    return jsonResp({ error: 'not_found' }, 404, origin, env);
  },
};
