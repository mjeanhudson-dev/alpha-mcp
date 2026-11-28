/**
 * Aether Sovereign Apex Cloud MCP Edge Router (Cloudflare Worker, zero dependencies).
 * Author: Eloquent (@mjeanhudson-dev)
 *
 * Routes https://mcp.eloquentwin.com/* -> Aether Sovereign Apex MCP v6.0.0-coalesced (12 tools + 5 slash prompts)
 * and https://mcp.eloquentwin.com/alpha/* -> Alpha MCP v2.0.0 (10 tools), with <800ms workstation tunnel priority
 * and lossless legacy tool-alias translation.
 */

const DEFAULT_SOVEREIGN_APEX_ORIGIN = 'https://aether-sovereign-apex-mxnmqsr7gq-ue.a.run.app';
const DEFAULT_ALPHA_MCP_ORIGIN = 'https://alpha-mcp-mxnmqsr7gq-ue.a.run.app';
const WORKSTATION_TIMEOUT_MS = 800;

const LEGACY_TOOL_ALIASES = {
  sovereign_dual_modality_status: 'aether_v5_triprotocol_status',
  interpolate_state_sheet: 'aether_interpolate_state_sheet',
  tandem_edge_route: 'aether_tandem_edge_route',
};

function buildUpstreamHeaders(request, publicHost) {
  const headers = new Headers();
  const passthrough = [
    'accept',
    'authorization',
    'content-type',
    'cookie',
    'mcp-protocol-version',
    'mcp-session-id',
    'origin',
    'user-agent',
    'x-alpha-oauth-secret',
  ];
  for (const name of passthrough) {
    const val = request.headers.get(name);
    if (val) headers.set(name, val);
  }
  headers.set('x-forwarded-proto', 'https');
  headers.set('x-forwarded-host', publicHost);
  const clientIp = request.headers.get('cf-connecting-ip');
  if (clientIp) headers.set('x-forwarded-for', clientIp);
  return headers;
}

async function maybeNormalizeJsonRpcBody(request) {
  if (request.method.toUpperCase() !== 'POST') return null;
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('application/json')) return request.arrayBuffer();
  const buf = await request.arrayBuffer();
  try {
    const txt = new TextDecoder().decode(buf);
    const obj = JSON.parse(txt);
    if (obj && obj.method === 'tools/call' && obj.params && typeof obj.params.name === 'string') {
      const mapped = LEGACY_TOOL_ALIASES[obj.params.name];
      if (mapped) {
        obj.params.name = mapped;
        return new TextEncoder().encode(JSON.stringify(obj)).buffer;
      }
    }
  } catch {}
  return buf;
}

async function forwardToOrigin(request, originBase, targetPathAndSearch, publicHost, bodyBuf, timeoutMs) {
  const targetUrl = new URL(targetPathAndSearch, originBase);
  const method = request.method.toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD';
  return fetch(targetUrl.toString(), {
    method,
    headers: buildUpstreamHeaders(request, publicHost),
    body: hasBody ? (bodyBuf ? bodyBuf.slice(0) : request.body) : undefined,
    redirect: 'manual',
    signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const publicHost = url.host || 'mcp.eloquentwin.com';
    const apexOrigin = (env && env.CLOUD_RUN_MCP_ORIGIN) || DEFAULT_SOVEREIGN_APEX_ORIGIN;
    const alphaOrigin = (env && env.ALPHA_MCP_ORIGIN) || DEFAULT_ALPHA_MCP_ORIGIN;
    const wsOrigin = env && env.WORKSTATION_MCP_ORIGIN ? String(env.WORKSTATION_MCP_ORIGIN).trim() : '';

    if (url.pathname === '/alpha' || url.pathname.startsWith('/alpha/')) {
      const subPath = (url.pathname.slice(6) || '/') + url.search;
      const bodyBuf = request.method !== 'GET' && request.method !== 'HEAD' ? await request.arrayBuffer() : null;
      return forwardToOrigin(request, alphaOrigin, subPath, publicHost, bodyBuf, 30000);
    }

    const normPath = (url.pathname === '/apex' || url.pathname.startsWith('/apex/'))
      ? ((url.pathname.slice(5) || '/') + url.search)
      : (url.pathname + url.search);

    const isMcpPost = normPath.startsWith('/mcp');
    const buffered = request.method !== 'GET' && request.method !== 'HEAD'
      ? (isMcpPost ? await maybeNormalizeJsonRpcBody(request) : await request.arrayBuffer())
      : null;

    if (wsOrigin && (url.pathname === '/mcp' || url.pathname === '/mcp/')) {
      try {
        const wsResp = await forwardToOrigin(request, wsOrigin, normPath, publicHost, buffered, WORKSTATION_TIMEOUT_MS);
        if (wsResp.status < 502) return wsResp;
      } catch {}
    }

    return forwardToOrigin(request, apexOrigin, normPath, publicHost, buffered, 30000);
  },
};
