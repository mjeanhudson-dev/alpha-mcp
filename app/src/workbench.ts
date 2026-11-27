import {
  App,
  applyDocumentTheme,
  applyHostStyleVariables,
} from "@modelcontextprotocol/ext-apps";
import { z } from "zod";

type Json = Record<string, any>;
type Tab = "search" | "manifest" | "slice" | "sovereign";

const TOOL_TAB: Record<string, Tab> = {
  stage0_vault_fts_query: "search",
  stage0_vault_manifest_lookup: "manifest",
  stage0_ast_slice_and_parity: "slice",
  sovereign_dual_modality_status: "sovereign",
  exodia_compaction_gate: "sovereign",
  tandem_edge_route: "sovereign",
  apex_contactor_route_packet: "sovereign",
};

const app = new App({ name: "Alpha MCP Workbench", version: "2.0.0" }, {});
const state: { tab: Tab; data: Partial<Record<string, Json>>; loading: string } = {
  tab: "sovereign",
  data: {},
  loading: "",
};
let caps: Json = {};
let gotResult = false;
let statusMsg = "";

const root = document.getElementById("root")!;

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function extract(result: any): Json | null {
  if (result?.structuredContent && typeof result.structuredContent === "object") return result.structuredContent;
  const text = result?.content?.[0]?.text;
  if (typeof text === "string") {
    try {
      const v = JSON.parse(text);
      return v && typeof v === "object" ? v : null;
    } catch {
      return null;
    }
  }
  return null;
}

async function call(name: string, args: Json): Promise<Json | null> {
  state.loading = name;
  render();
  try {
    const res = await app.callServerTool({ name, arguments: args });
    const data = extract(res) ?? { status: "ERROR", error: "empty result" };
    state.data[name] = data;
    return data;
  } catch (e: any) {
    const data = { status: "ERROR", error: String(e?.message ?? e) };
    state.data[name] = data;
    return data;
  } finally {
    state.loading = "";
    render();
  }
}

function jsonBlock(v: unknown) {
  return `<pre>${esc(JSON.stringify(v, null, 2))}</pre>`;
}

function snippetHtml(s: string) {
  return esc(s).replace(/&gt;&gt;&gt;/g, "<mark>").replace(/&lt;&lt;&lt;/g, "</mark>");
}

function viewSearch() {
  const d = state.data["stage0_vault_fts_query"];
  const hits: Json[] = d?.hits ?? [];
  return `
  <div class="row"><input type="text" id="q" placeholder="BM25 FTS5 query" value="${esc((document.getElementById("q") as HTMLInputElement | null)?.value ?? "")}">
  <select id="topk"><option>5</option><option>10</option><option>20</option></select>
  <button class="act" id="doSearch">Search</button></div>
  ${d?.status === "ERROR" ? `<div class="err">${esc(d.error)}</div>` : ""}
  ${d?.status === "OK" ? `<div class="muted">${d.hit_count} hit(s)</div>` : ""}
  ${hits
    .map(
      (h, i) => `<div class="card"><b>${esc(h.path)}</b> <span class="badge">${esc(h.line_range)}</span>
    <div class="muted">${esc(h.folder_root)} · ${esc(h.ast_summary)}</div>
    <pre>${snippetHtml(h.snippet)}</pre>
    <div class="row" style="margin-top:6px">
      <button class="act" data-slice="${i}">Slice</button>
      <button class="act" data-open="${i}">Open File</button>
      ${caps.updateModelContext ? `<button class="act" data-attach="${i}">Attach</button>` : ""}
    </div></div>`,
    )
    .join("")}`;
}

function viewManifest() {
  const d = state.data["stage0_vault_manifest_lookup"];
  const c: Json = d?.counts ?? {};
  const rows: Json[] = d?.rows ?? [];
  const keys = rows[0] ? Object.keys(rows[0]) : [];
  return `
  <div class="row">${["summary", "secret_audit", "zip", "vhdx", "links"]
    .map((s) => `<button class="act" data-scope="${s}">${s}</button>`)
    .join("")}</div>
  ${d?.status === "ERROR" ? `<div class="err">${esc(d.error)}</div>` : ""}
  <div class="kpis">${["files", "slices", "links", "vhdx_entries", "zip_entries", "secret_audit_hits"]
    .map((k) => `<div class="card kpi"><span class="muted">${k}</span><b>${esc(c[k] ?? "–")}</b></div>`)
    .join("")}</div>
  ${
    rows.length
      ? `<table><tr>${keys.map((k) => `<th>${esc(k)}</th>`).join("")}</tr>${rows
          .map((r) => `<tr>${keys.map((k) => `<td>${esc(r[k])}</td>`).join("")}</tr>`)
          .join("")}</table>`
      : ""
  }`;
}

function viewSlice() {
  const d = state.data["stage0_ast_slice_and_parity"];
  const inp = (id: string, def: string) =>
    esc((document.getElementById(id) as HTMLInputElement | null)?.value ?? def);
  let body = "";
  if (d?.code === "SECRET_PATH_AIRLOCK_DENY" || d?.status === "ERROR") {
    body = `<div class="card err"><b>${esc(d.code ?? "ERROR")}</b> ${esc(d.error ?? d.message ?? "")}</div>`;
  } else if (d) {
    const text = String(d.content ?? d.slice ?? d.text ?? "");
    const start = Number(d.start_line ?? 1);
    const numbered = text
      .split("\n")
      .map((l, i) => `${String(start + i).padStart(5)}  ${l}`)
      .join("\n");
    const parity = d.parity ?? d.status ?? "";
    body = `<div class="muted">${d.sha256 ? `<span class="badge">${esc(parity)}</span> sha256 ${esc(String(d.sha256).slice(0, 16))}` : esc(parity)}</div>
    ${text ? `<pre>${esc(numbered)}</pre>` : jsonBlock(d)}`;
  }
  return `
  <div class="row"><input type="text" id="fp" placeholder="file path" value="${inp("fp", "")}">
  <input type="text" id="sl" style="max-width:70px;flex:0" value="${inp("sl", "1")}">
  <input type="text" id="el" style="max-width:70px;flex:0" value="${inp("el", "160")}">
  <label><input type="checkbox" id="force"> force_read</label>
  <button class="act" id="doSlice">Read slice</button></div>${body}`;
}

function viewSovereign() {
  const st = state.data["sovereign_dual_modality_status"];
  const form = (name: string, label: string, fields: string, btn: string) => `
  <div class="card"><b>${label}</b><div class="row" style="margin-top:6px">${fields}<button class="act" data-run="${btn}">Run</button></div>
  ${state.data[name] ? jsonBlock(state.data[name]) : ""}</div>`;
  const f = (id: string, ph: string, v: string) => `<input type="text" id="${id}" placeholder="${ph}" value="${esc((document.getElementById(id) as HTMLInputElement | null)?.value ?? v)}" style="max-width:130px">`;
  return `
  <div class="card"><b>Sovereign Dual-Modality Status</b>
  ${st ? jsonBlock(st) : `<div class="muted">No status loaded.</div>`}</div>
  ${form("exodia_compaction_gate", "Exodia 25:1 gate", f("cr", "cache_reads", "0") + f("cw", "cache_writes", "1") + f("tn", "turns", "0"), "exodia")}
  ${form("tandem_edge_route", "Tandem edge route", f("pt", "phone_temp_c", "34") + f("vu", "vram_used_gb", "3.5"), "tandem")}
  ${form("apex_contactor_route_packet", "Apex contactor", f("rm", "requested_model", "gemini-flash") + f("ob", "objective", "test"), "apex")}`;
}

function render() {
  const views: Record<Tab, () => string> = {
    search: viewSearch,
    manifest: viewManifest,
    slice: viewSlice,
    sovereign: viewSovereign,
  };
  const labels: Record<Tab, string> = {
    search: "Vault Search",
    manifest: "Manifest & Audit",
    slice: "AST Slice",
    sovereign: "Sovereign & Exodia",
  };
  root.innerHTML = `
  <nav role="tablist">${(Object.keys(labels) as Tab[])
    .map((t) => `<button role="tab" aria-selected="${t === state.tab}" data-tab="${t}">${labels[t]}</button>`)
    .join("")}</nav>
  <div id="status" class="muted">${state.loading ? `Running ${esc(state.loading)}…` : esc(statusMsg)}</div>
  <section>${views[state.tab]()}</section>`;
  bind();
}

const val = (id: string) => (document.getElementById(id) as HTMLInputElement | null)?.value ?? "";

function bind() {
  root.querySelectorAll<HTMLElement>("[data-tab]").forEach((b) =>
    b.addEventListener("click", () => {
      state.tab = b.dataset.tab as Tab;
      statusMsg = "";
      render();
    }),
  );
  root.querySelector("#doSearch")?.addEventListener("click", () => {
    const q = val("q").trim();
    if (q) void call("stage0_vault_fts_query", { query: q, top_k: Number(val("topk")) || 5 });
  });
  root.querySelectorAll<HTMLElement>("[data-scope]").forEach((b) =>
    b.addEventListener("click", () => void call("stage0_vault_manifest_lookup", { scope: b.dataset.scope, limit: 15 })),
  );
  root.querySelector("#doSlice")?.addEventListener("click", () => {
    const fp = val("fp").trim();
    if (!fp) return;
    void call("stage0_ast_slice_and_parity", {
      filepath: fp,
      start_line: Number(val("sl")) || 1,
      end_line: Number(val("el")) || 160,
      force_read: (document.getElementById("force") as HTMLInputElement).checked,
    });
  });
  const hits = (): Json[] => state.data["stage0_vault_fts_query"]?.hits ?? [];
  const range = (h: Json) => String(h.line_range ?? "").match(/(\d+)\D+(\d+)/);
  root.querySelectorAll<HTMLElement>("[data-slice]").forEach((b) =>
    b.addEventListener("click", async () => {
      const h = hits()[Number(b.dataset.slice)];
      const m = range(h);
      state.tab = "slice";
      await call("stage0_ast_slice_and_parity", {
        filepath: h.path,
        start_line: m ? Number(m[1]) : 1,
        end_line: m ? Number(m[2]) : 160,
      });
    }),
  );
  root.querySelectorAll<HTMLElement>("[data-open]").forEach((b) =>
    b.addEventListener("click", async () => {
      const h = hits()[Number(b.dataset.open)];
      const p = String(h.path).replace(/\\/g, "/");
      const uri = /^[a-zA-Z]:/.test(p) ? `file:///${p}` : `file://${p.startsWith("/") ? "" : "/"}${p}`;
      try {
        const r: any = await app.request(
          { method: "com.google.antigravity/toggle-aux-pane", params: { tabType: "fileView", uri } },
          z.object({ isError: z.boolean().optional() }).passthrough(),
        );
        statusMsg = r?.isError ? "Could not open file in a side pane here." : "";
      } catch (e: any) {
        statusMsg = e?.code === -32601 ? "Open File is not supported by this host." : "Open File failed.";
      }
      render();
    }),
  );
  root.querySelectorAll<HTMLElement>("[data-attach]").forEach((b) =>
    b.addEventListener("click", async () => {
      const h = hits()[Number(b.dataset.attach)];
      try {
        await app.updateModelContext({
          content: [{ type: "text", text: `${h.path} ${h.line_range}\n${h.snippet}` }],
        });
        statusMsg = "Attached to next message.";
      } catch {
        statusMsg = "Attach failed.";
      }
      render();
    }),
  );
  root.querySelectorAll<HTMLElement>("[data-run]").forEach((b) =>
    b.addEventListener("click", () => {
      const run = b.dataset.run;
      if (run === "exodia")
        void call("exodia_compaction_gate", {
          cache_reads: Number(val("cr")) || 0,
          cache_writes: Number(val("cw")) || 1,
          turns: Number(val("tn")) || 0,
        });
      else if (run === "tandem")
        void call("tandem_edge_route", {
          phone_temp_c: Number(val("pt")) || 34,
          vram_used_gb: Number(val("vu")) || 3.5,
        });
      else if (run === "apex")
        void call("apex_contactor_route_packet", { requested_model: val("rm"), objective: val("ob") });
    }),
  );
}

function applyHost(ctx: any) {
  if (ctx?.theme) applyDocumentTheme(ctx.theme);
  if (ctx?.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
}

app.ontoolinput = ({ arguments: args }: any) => {
  state.loading = "tool call";
  statusMsg = args ? `Input: ${JSON.stringify(args).slice(0, 120)}` : "";
  render();
};
app.ontoolresult = (result: any) => {
  gotResult = true;
  state.loading = "";
  const data = extract(result);
  if (!data) return render();
  const name = guessTool(data);
  if (name) {
    state.data[name] = data;
    state.tab = TOOL_TAB[name];
  }
  statusMsg = "";
  render();
};
app.ontoolcancelled = () => {
  state.loading = "";
  statusMsg = "Tool call cancelled.";
  render();
};
app.onhostcontextchanged = applyHost;

function guessTool(d: Json): string | null {
  if (Array.isArray(d.hits)) return "stage0_vault_fts_query";
  if (d.counts && d.scope) return "stage0_vault_manifest_lookup";
  if (d.pinned_tool_order && d.version) return "sovereign_dual_modality_status";
  if (d.sha256 || d.code === "SECRET_PATH_AIRLOCK_DENY" || d.start_line !== undefined) return "stage0_ast_slice_and_parity";
  if (d.last_exodia_ratio !== undefined || d.exodia_state !== undefined || d.compact !== undefined) return "exodia_compaction_gate";
  return null;
}

async function main() {
  render();
  await app.connect();
  applyHost(app.getHostContext());
  caps = (app.getHostCapabilities() as Json) ?? {};
  render();

  if (!gotResult) {
    await Promise.all([
      call("sovereign_dual_modality_status", {}),
      call("stage0_vault_manifest_lookup", { scope: "summary", limit: 15 }),
    ]);
  }
}
void main();
