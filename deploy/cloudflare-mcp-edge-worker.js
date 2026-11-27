/**
 * Aether Sovereign Cloud MCP Edge Router (Cloudflare Worker, zero dependencies).
 * Author: Eloquent (@mjeanhudson-dev)
 *
 * Binds https://mcp.eloquentwin.com/* -> Google Cloud Run (us-east1, $0/mo scale-to-zero)
 * with optional <800ms live-workstation tunnel upgrade when WORKSTATION_MCP_ORIGIN is set.
 * Preserves OAuth 2.1 PKCE S256, RFC 9728 discovery, A2A v1.0.1 cards, and X-Forwarded-Host.
 */

const DEFAULT_CLOUD_RUN_ORIGIN = 'https://alpha-mcp-mxnmqsr7gq-ue.a.run.app';
const WORKSTATION_TIMEOUT_MS = 800;

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

async function forwardToOrigin(request, originBase, publicHost, timeoutMs) {
  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(incomingUrl.pathname + incomingUrl.search, originBase);
  const method = request.method.toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD';
  const init = {
    method,
    headers: buildUpstreamHeaders(request, publicHost),
    body: hasBody ? request.body : undefined,
    redirect: 'manual',
    signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
  };
  return fetch(targetUrl.toString(), init);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const publicHost = url.host || 'mcp.eloquentwin.com';
    const cloudOrigin = (env && env.CLOUD_RUN_MCP_ORIGIN) || DEFAULT_CLOUD_RUN_ORIGIN;
    const wsOrigin = env && env.WORKSTATION_MCP_ORIGIN ? String(env.WORKSTATION_MCP_ORIGIN).trim() : '';

    // Optional Hybrid Mode: try live workstation tunnel first on /mcp calls; auto-failover to Cloud Run in <800ms
    if (wsOrigin && (url.pathname === '/mcp' || url.pathname === '/mcp/')) {
      const buffered = request.method !== 'GET' && request.method !== 'HEAD' ? await request.arrayBuffer() : null;
      const makeReq = () => new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: buffered ? buffered.slice(0) : undefined,
      });
      try {
        const wsResp = await forwardToOrigin(makeReq(), wsOrigin, publicHost, WORKSTATION_TIMEOUT_MS);
        if (wsResp.status < 502) return wsResp;
      } catch {
        // Workstation asleep or tunnel offline -> seamless Cloud Run failover
      }
      return forwardToOrigin(makeReq(), cloudOrigin, publicHost, 30000);
    }

    return forwardToOrigin(request, cloudOrigin, publicHost, 30000);
  },
};
