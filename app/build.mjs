import { build } from "esbuild";
import { mkdirSync, writeFileSync } from "node:fs";

const MAX_BYTES = 10 * 1024 * 1024;

const result = await build({
  entryPoints: ["src/workbench.ts"],
  bundle: true,
  minify: true,
  format: "iife",
  target: ["es2022"],
  write: false,
});
const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");

const css = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:12px;background:var(--color-background-primary,#fff);color:var(--color-text-primary,#1f1f1f);font-family:var(--font-sans,system-ui,sans-serif);font-size:13px}
h2{margin:0 0 8px;font-size:14px}
nav{display:flex;gap:4px;border-bottom:1px solid var(--color-border-primary,#d0d0d0);margin-bottom:12px;flex-wrap:wrap}
nav button{background:none;border:0;border-bottom:2px solid transparent;padding:6px 10px;color:var(--color-text-secondary,#555);cursor:pointer;font:inherit}
nav button[aria-selected=true]{color:var(--color-text-primary,#1f1f1f);border-bottom-color:var(--color-ring-primary,#3b82f6)}
section[hidden]{display:none}
.row{display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;align-items:center}
input,select,button.act{background:var(--color-background-secondary,#f5f5f5);color:var(--color-text-primary,#1f1f1f);border:1px solid var(--color-border-primary,#d0d0d0);border-radius:4px;padding:5px 8px;font:inherit}
input[type=text]{flex:1;min-width:140px}
button.act{cursor:pointer}
button.act:hover{border-color:var(--color-ring-primary,#3b82f6)}
button.act:disabled{opacity:.5;cursor:default}
.card{background:var(--color-background-secondary,#f5f5f5);border:1px solid var(--color-border-secondary,#e5e5e5);border-radius:6px;padding:8px;margin-bottom:8px}
.muted{color:var(--color-text-secondary,#666)}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-bottom:10px}
.kpi b{display:block;font-size:18px}
pre{margin:0;padding:8px;overflow:auto;background:var(--color-background-tertiary,#ececec);border-radius:4px;font-size:12px;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--color-border-secondary,#e5e5e5);vertical-align:top;word-break:break-all}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:11px;border:1px solid var(--color-border-primary,#d0d0d0)}
.ok{color:var(--color-text-success,#15803d)}
.err{color:var(--color-text-danger,#b91c1c)}
mark{background:var(--color-background-warning,#fde68a);color:inherit}
#status{min-height:18px;margin-bottom:8px}
`;

const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Alpha MCP Workbench</title><style>${css}</style></head>
<body><div id="root"></div><script>${js}</script></body></html>`;

const size = Buffer.byteLength(html);
if (size <= 0 || size >= MAX_BYTES) throw new Error(`workbench.html size out of range: ${size}`);
mkdirSync("dist", { recursive: true });
writeFileSync("dist/workbench.html", html);
console.log(`dist/workbench.html ${size} bytes`);
