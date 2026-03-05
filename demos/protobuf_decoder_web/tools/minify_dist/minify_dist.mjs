import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import esbuild from "esbuild";

function stripQuotes(raw) {
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes}B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)}KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)}MiB`;
}

function sha384Integrity(bytes) {
  const digest = crypto.createHash("sha384").update(bytes).digest("base64");
  return `sha384-${digest}`;
}

async function minifyFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext !== ".js" && ext !== ".css") {
    return { changed: false };
  }

  const before = await fs.readFile(filePath, "utf8");
  const beforeSize = Buffer.byteLength(before, "utf8");

  const loader = ext === ".css" ? "css" : "js";
  const format = ext === ".js" ? "esm" : undefined;
  const { code, warnings } = await esbuild.transform(before, {
    loader,
    format,
    minify: true,
    legalComments: "none",
  });

  if (warnings.length > 0) {
    for (const warning of warnings) {
      console.warn(`[esbuild] ${warning.text}`);
    }
  }

  const afterSize = Buffer.byteLength(code, "utf8");
  if (afterSize >= beforeSize) {
    return { changed: false, beforeSize, afterSize: beforeSize };
  }

  await fs.writeFile(filePath, code, "utf8");
  return { changed: true, beforeSize, afterSize };
}

async function rewriteLinkIntegrity(html, distDir) {
  const linkTagRe = /<link\b[^>]*?>/gi;
  const hrefAttrRe = /\bhref\s*=\s*(["']?)([^"'\s>]+)\1/i;
  const integrityAttrRe = /\bintegrity\s*=\s*(["']?)(sha384-[^"'\s>]+)\1/i;

  const sriByHref = new Map();
  let updatedCount = 0;

  let out = "";
  let lastIndex = 0;
  for (const match of html.matchAll(linkTagRe)) {
    const tag = match[0];
    out += html.slice(lastIndex, match.index);

    let nextTag = tag;
    const hrefMatch = tag.match(hrefAttrRe);
    const integrityMatch = tag.match(integrityAttrRe);
    if (hrefMatch && integrityMatch) {
      const href = stripQuotes(hrefMatch[2]);
      let sri = sriByHref.get(href);
      if (!sri) {
        const rel = href.startsWith("/") ? href.slice(1) : href;
        const assetPath = path.join(distDir, rel);
        const bytes = await fs.readFile(assetPath);
        sri = sha384Integrity(bytes);
        sriByHref.set(href, sri);
      }

      nextTag = tag.replace(
        integrityAttrRe,
        (_full, quote) => `integrity=${quote}${sri}${quote}`,
      );
      if (nextTag !== tag) {
        updatedCount += 1;
      }
    }

    out += nextTag;
    lastIndex = match.index + tag.length;
  }

  out += html.slice(lastIndex);
  return { html: out, updatedCount };
}

async function minifyIndexHtml(html) {
  const beforeSize = Buffer.byteLength(html, "utf8");

  const scriptTagRe = /<script\b[^>]*>[\s\S]*?<\/script>/gi;
  const scriptPartsRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/i;

  let withScriptsMinified = "";
  let lastIndex = 0;
  for (const match of html.matchAll(scriptTagRe)) {
    const tag = match[0];
    withScriptsMinified += html.slice(lastIndex, match.index);

    let nextTag = tag;
    const parts = tag.match(scriptPartsRe);
    if (parts) {
      const attrs = parts[1] ?? "";
      const code = parts[2] ?? "";
      const hasSrc = /\bsrc\s*=/.test(attrs);
      if (!hasSrc) {
        const isModule = /\btype\s*=\s*(["']?)module\1/i.test(attrs);
        const { code: minifiedCode, warnings } = await esbuild.transform(code, {
          loader: "js",
          format: isModule ? "esm" : undefined,
          minify: true,
          legalComments: "none",
        });

        if (warnings.length > 0) {
          for (const warning of warnings) {
            console.warn(`[esbuild] ${warning.text}`);
          }
        }

        nextTag = `<script${attrs}>${minifiedCode.trim()}</script>`;
      }
    }

    withScriptsMinified += nextTag;
    lastIndex = match.index + tag.length;
  }
  withScriptsMinified += html.slice(lastIndex);

  const collapsed = withScriptsMinified.replace(/>\s+</g, "><").trim();
  const afterSize = Buffer.byteLength(collapsed, "utf8");
  if (afterSize >= beforeSize) {
    return { html, changed: false, beforeSize, afterSize: beforeSize };
  }
  return { html: collapsed, changed: true, beforeSize, afterSize };
}

async function updateIndexHtml(indexPath, distDir) {
  const before = await fs.readFile(indexPath, "utf8");
  const integrityResult = await rewriteLinkIntegrity(before, distDir);
  const minifyResult = await minifyIndexHtml(integrityResult.html);

  const after = minifyResult.html;
  if (after !== before) {
    await fs.writeFile(indexPath, after, "utf8");
  }

  const beforeSize = Buffer.byteLength(before, "utf8");
  const afterSize = Buffer.byteLength(after, "utf8");
  return {
    updatedCount: integrityResult.updatedCount,
    changed: after !== before,
    beforeSize,
    afterSize,
    minified: minifyResult.changed,
  };
}

function parseArgs(argv) {
  const args = {
    distDir: null,
    wasmOpt: false,
  };

  for (const raw of argv) {
    if (raw === "--wasm-opt") {
      args.wasmOpt = true;
      continue;
    }
    if (raw.startsWith("-")) {
      throw new Error(`Unknown flag: ${raw}`);
    }
    if (args.distDir) {
      throw new Error(`Unexpected argument: ${raw}`);
    }
    args.distDir = raw;
  }

  if (!args.distDir) {
    throw new Error("Missing dist directory path.");
  }
  return args;
}

async function wasmOptIfAvailable(wasmPath) {
  const probe = spawnSync("wasm-opt", ["--version"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    return { ran: false, ok: true, message: "wasm-opt not found" };
  }

  const before = await fs.readFile(wasmPath);
  const beforeSize = before.byteLength;
  const tmpPath = `${wasmPath}.wasm-opt.tmp`;

  const res = spawnSync(
    "wasm-opt",
    ["-Oz", "--strip-dwarf", wasmPath, "-o", tmpPath],
    { encoding: "utf8" },
  );
  if (res.status !== 0) {
    await fs.rm(tmpPath, { force: true });
    return {
      ran: true,
      ok: false,
      message: res.stderr?.trim() || "wasm-opt failed",
    };
  }

  const after = await fs.readFile(tmpPath);
  const afterSize = after.byteLength;
  if (afterSize >= beforeSize) {
    await fs.rm(tmpPath, { force: true });
    return { ran: true, ok: true, beforeSize, afterSize: beforeSize };
  }

  await fs.rename(tmpPath, wasmPath);
  return { ran: true, ok: true, beforeSize, afterSize };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const distDir = path.resolve(process.cwd(), args.distDir);

  const stat = await fs.stat(distDir).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    throw new Error(`dist directory not found: ${distDir}`);
  }

  const indexPath = path.join(distDir, "index.html");
  const indexStat = await fs.stat(indexPath).catch(() => null);
  if (!indexStat || !indexStat.isFile()) {
    throw new Error(`dist/index.html not found: ${indexPath}`);
  }

  const entries = await fs.readdir(distDir, { withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile())
    .map((e) => path.join(distDir, e.name))
    .sort();

  let jsChanged = 0;
  let cssChanged = 0;
  let bytesBefore = 0;
  let bytesAfter = 0;

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== ".js" && ext !== ".css") {
      continue;
    }

    const result = await minifyFile(filePath);
    if (typeof result.beforeSize === "number" && typeof result.afterSize === "number") {
      bytesBefore += result.beforeSize;
      bytesAfter += result.afterSize;
    }
    if (result.changed) {
      if (ext === ".js") {
        jsChanged += 1;
      } else {
        cssChanged += 1;
      }
    }
  }

  let wasmSummary = null;
  if (args.wasmOpt) {
    const wasmFiles = files.filter((p) => p.toLowerCase().endsWith(".wasm"));
    for (const wasmPath of wasmFiles) {
      const res = await wasmOptIfAvailable(wasmPath);
      wasmSummary = res;
      if (!res.ok) {
        throw new Error(res.message);
      }
    }
  }

  const indexResult = await updateIndexHtml(indexPath, distDir);

  const reduced = bytesBefore >= bytesAfter ? bytesBefore - bytesAfter : 0;
  const suffix =
    reduced === 0 ? "" : ` (saved ${formatBytes(reduced)} / ${formatBytes(bytesBefore)})`;

  let wasmSuffix = "";
  if (wasmSummary?.ran && wasmSummary.beforeSize && wasmSummary.afterSize) {
    const saved = wasmSummary.beforeSize - wasmSummary.afterSize;
    wasmSuffix = `, wasm-opt saved ${formatBytes(saved)} / ${formatBytes(wasmSummary.beforeSize)}`;
  }

  console.log(
    `minify-dist: changed ${jsChanged} js, ${cssChanged} css${suffix}${wasmSuffix}; updated ${indexResult.updatedCount} integrity attributes; index.html ${indexResult.minified ? "minified" : "kept"} (${formatBytes(indexResult.beforeSize)} -> ${formatBytes(indexResult.afterSize)})`,
  );
}

main().catch((err) => {
  console.error(`minify-dist: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
