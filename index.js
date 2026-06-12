#!/usr/bin/env node
/**
 * NowSecure MCP Server
 *
 * Exposes NowSecure Platform data to MCP clients. Built specifically to work
 * around the broken UI PDF renderer (the "Enum JiraIntegrationCustomFieldType
 * cannot represent value" error on app.nowsecure.com/.../pdf) by pulling
 * findings through the REST + GraphQL APIs and, if needed, generating the PDF
 * locally instead of relying on NowSecure's report service.
 *
 * Auth: set NOWSECURE_TOKEN to your Platform API bearer token (PAT).
 *       Optionally override NOWSECURE_API_BASE (default https://api.nowsecure.com).
 *
 * Author: Tatavarthi Tarun 🎈💜  (https://www.linkedin.com/in/tatav)
 * License: MIT
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import PDFDocument from "pdfkit";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const API_BASE = process.env.NOWSECURE_API_BASE || "https://api.nowsecure.com";
const TOKEN = process.env.NOWSECURE_TOKEN || "";


const CREDIT = `nowsecure-mcp-server by 🎈💜`;

const SEVERITY_ORDER = ["blocker", "critical", "high", "medium", "low", "warn", "info"];
const DEFAULT_REMEDIATION_IMPACTS = ["blocker", "critical", "high", "medium"];
// Only findings with this status actually require remediation (open/failing).
// "pass" = control satisfied, "dismissed" = manually waived — both excluded.
const REMEDIATION_STATUSES = ["detected", "fail", "open", "reopened"];

function assertToken() {
  if (!TOKEN) {
    throw new Error(
      "NOWSECURE_TOKEN environment variable is not set. Add your NowSecure Platform API bearer token to the MCP server config."
    );
  }
}

function authHeaders(extra = {}) {
  return {
    Authorization: `Bearer ${TOKEN}`,
    ...extra,
  };
}

async function restGet(path, { searchParams } = {}) {
  assertToken();
  const url = new URL(path.startsWith("http") ? path : `${API_BASE}${path}`);
  if (searchParams) {
    for (const [k, v] of searchParams) url.searchParams.append(k, v);
  }
  const res = await fetch(url, { headers: authHeaders({ Accept: "application/json" }) });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`NowSecure REST ${res.status} ${res.statusText} for ${url.pathname}: ${body.slice(0, 500)}`);
  }
  return res.json();
}

async function graphql(query, variables = {}, { timeoutMs = 45000 } = {}) {
  assertToken();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${API_BASE}/graphql`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json", Accept: "application/json" }),
      body: JSON.stringify({ query, variables }),
      signal: ctl.signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      const e = new Error(`NowSecure GraphQL request timed out after ${timeoutMs}ms`);
      e.status = 504;
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const raw = await res.text();
  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    // Gateway errors (502/503/504) typically return HTML, not JSON.
    const e = new Error(`NowSecure GraphQL non-JSON response (${res.status}): ${raw.slice(0, 300)}`);
    e.status = res.status;
    throw e;
  }
  if (json.errors?.length) {
    throw new Error(`NowSecure GraphQL errors: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

/**
 * GraphQL with retry/backoff for transient gateway failures (502/503/504).
 * The heavy `context` (evidence) field on NowSecure's gateway intermittently
 * 503s, so callers that need it wrap with this and degrade gracefully.
 */
async function graphqlWithRetry(query, variables = {}, { retries = 3, baseDelayMs = 800 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await graphql(query, variables);
    } catch (err) {
      lastErr = err;
      const transient = [502, 503, 504].includes(err.status);
      if (!transient || attempt === retries) throw err;
      await new Promise((r) => setTimeout(r, baseDelayMs * Math.pow(2, attempt)));
    }
  }
  throw lastErr;
}

/**
 * Full findings query scoped to a SINGLE assessment via the top-level
 * `auto.assessments(refs:)` field. Scoping to one assessment (instead of
 * fanning out across every assessment on the app) is what keeps the heavy
 * `context` (evidence) + `check.issue` data from overwhelming the gateway —
 * the previous app-wide query 503'd because this app has 145 assessments.
 */
const ASSESSMENT_QUERY = `
query Assessment($refs: [UUID!]) {
  auto {
    assessments(refs: $refs) {
      ref
      score
      createdAt
      packageKey
      platformType
      applicationRef
      report {
        findings {
          title
          impactType
          severity
          findingStatus
          affected
          cvss
          cvssVector
          summary
          description
          recommendation
          shortRemediation
          hasCodeLocations
          canHaveActionableEvidence
          check {
            id
            title
            categories
            issue {
              impactSummary
              recommendation
              category
              cve
              codeSamples { platform syntax caption block }
              guidanceLinks { platform caption url }
            }
          }
          context {
            description
            items
            children {
              id
              description
              items
              children { id description items }
            }
          }
        }
      }
    }
  }
}`;

/**
 * Lightweight query to list an app's assessment refs (no report bodies) so we
 * can resolve the latest assessment when the caller doesn't specify one.
 */
const APP_ASSESSMENTS_QUERY = `
query AppAssessments($refs: [UUID!]) {
  auto {
    applications(refs: $refs) {
      ref
      packageKey
      platformType
      assessments { ref createdAt score }
    }
  }
}`;

function flattenContext(ctx, depth = 0, out = []) {
  if (!ctx) return out;
  if (ctx.description) out.push({ depth, text: ctx.description });
  if (Array.isArray(ctx.items)) {
    for (const it of ctx.items) {
      out.push({ depth: depth + 1, text: typeof it === "string" ? it : JSON.stringify(it) });
    }
  }
  if (Array.isArray(ctx.children)) {
    for (const child of ctx.children) flattenContext(child, depth + 1, out);
  }
  return out;
}

async function resolveAssessmentRef({ appRef, assessmentRef }) {
  if (assessmentRef) return { assessmentRef, appMeta: null };
  // No assessment specified — list the app's assessments (lightweight) and
  // pick the most recent one.
  const data = await graphql(APP_ASSESSMENTS_QUERY, { refs: [appRef] });
  const app = (data?.auto?.applications || [])[0];
  if (!app) throw new Error(`No application found for ref ${appRef}.`);
  const latest = [...(app.assessments || [])].sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  )[0];
  if (!latest) throw new Error(`No assessments found on app ${appRef}.`);
  return {
    assessmentRef: latest.ref,
    appMeta: { ref: app.ref, packageKey: app.packageKey, platformType: app.platformType },
  };
}

async function fetchAssessmentFindings({ appRef, assessmentRef, impactTypes }) {
  if (!appRef && !assessmentRef) {
    throw new Error("Provide at least an appRef (or an assessmentRef).");
  }

  const resolved = await resolveAssessmentRef({ appRef, assessmentRef });
  const targetRef = resolved.assessmentRef;

  // Single scoped query — fast even with the heavy context/evidence tree,
  // because it targets exactly one assessment instead of all ~145 on the app.
  const data = await graphqlWithRetry(ASSESSMENT_QUERY, { refs: [targetRef] });
  const assessment = (data?.auto?.assessments || [])[0];
  if (!assessment) throw new Error(`Assessment ${targetRef} not found or returned no data.`);

  const wanted = (impactTypes && impactTypes.length ? impactTypes : DEFAULT_REMEDIATION_IMPACTS).map((s) => s.toLowerCase());
  const allFindings = assessment.report?.findings || [];
  const findings = allFindings
    .filter((f) => wanted.includes(String(f.impactType || "").toLowerCase()))
    // Only findings that actually require remediation. Excludes "pass"
    // (control satisfied) and "dismissed" (manually waived).
    .filter((f) => REMEDIATION_STATUSES.includes(String(f.findingStatus || "").toLowerCase()))
    .map((f) => {
      const issue = f.check?.issue || {};
      return {
        title: f.title || f.check?.title || issue.title || "(untitled)",
        impactType: f.impactType,
        severity: f.severity || null,
        status: f.findingStatus || null,
        affected: f.affected ?? null,
        cvss: f.cvss,
        cvssVector: f.cvssVector || null,
        category: issue.category || (f.check?.categories || [])[0] || null,
        checkId: f.check?.id || null,
        cve: issue.cve || null,
        summary: f.summary || null,
        description: stripHtml(f.description || issue.description || ""),
        impactSummary: issue.impactSummary ? stripHtml(issue.impactSummary) : null,
        remediation: stripHtml(f.recommendation || issue.recommendation || f.shortRemediation || ""),
        codeSamples: (issue.codeSamples || []).map((c) => ({
          platform: c.platform || null,
          syntax: c.syntax || null,
          caption: c.caption || null,
          block: c.block || "",
        })),
        guidanceLinks: (issue.guidanceLinks || []).map((g) => ({
          caption: g.caption || g.url,
          url: g.url,
        })),
        evidence: flattenContext(f.context),
        hasCodeLocations: f.hasCodeLocations ?? null,
      };
    })
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(String(a.impactType).toLowerCase()) -
        SEVERITY_ORDER.indexOf(String(b.impactType).toLowerCase())
    );

  const counts = {};
  for (const f of findings) {
    const k = String(f.impactType || "unknown").toLowerCase();
    counts[k] = (counts[k] || 0) + 1;
  }

  const appInfo = {
    ref: assessment.applicationRef || resolved.appMeta?.ref || appRef || null,
    packageKey: assessment.packageKey || resolved.appMeta?.packageKey || null,
    platformType: assessment.platformType || resolved.appMeta?.platformType || null,
  };

  return {
    app: appInfo,
    assessment: { ref: assessment.ref, score: assessment.score, createdAt: assessment.createdAt },
    filter: { impactTypes: wanted, statuses: REMEDIATION_STATUSES },
    counts,
    total: findings.length,
    findings,
  };
}

function severityColor(impact) {
  switch (String(impact).toLowerCase()) {
    case "blocker": return "#7b1fa2";
    case "critical": return "#b00020";
    case "high": return "#d84315";
    case "medium": return "#ef6c00";
    case "low": return "#2e7d32";
    default: return "#555555";
  }
}

function sanitizeName(s) {
  return String(s || "report")
    .trim()
    .replace(/[\\/:*?"<>|]+/g, "")   // strip path/illegal chars
    .replace(/\s+/g, "_");
}

function timestampForFile(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}` +
    `_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  );
}

/**
 * Build the conventional report filename:
 *   [App_Name]_NowSecure_report_[yyyy-MM-dd_HHmmss].pdf
 * Falls back to the package key when no friendly app name is supplied.
 */
function defaultReportFilename(report, appName) {
  const name = sanitizeName(appName || report.app.packageKey || "app");
  return `${name}_NowSecure_report_${timestampForFile()}.pdf`;
}

async function buildPdf(report, outputPath) {
  const abs = resolve(outputPath);
  await mkdir(dirname(abs), { recursive: true });

  await new Promise((resolvePromise, reject) => {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    doc.info.Creator = `${CREDIT}`;

    const stream = createWriteStream(abs);
    stream.on("error", reject);
    stream.on("finish", resolvePromise);
    doc.pipe(stream);

    doc.fontSize(20).fillColor("#000").text("NowSecure Remediation Report", { align: "left" });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor("#555")
      .text(`Package: ${report.app.packageKey || "n/a"}  (${report.app.platformType || "n/a"})`)
      .text(`Assessment: ${report.assessment.ref}`)
      .text(`Score: ${report.assessment.score ?? "n/a"}    Created: ${report.assessment.createdAt || "n/a"}`)
      .text(`Generated locally: ${new Date().toISOString()}`)
      .text(`nowsecure-mcp-server 🎈💜`);
    doc.moveDown(1);

    doc.fontSize(13).fillColor("#000").text("Summary", { underline: true });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor("#333");
    const counts = report.counts || {};
    const summaryLine = SEVERITY_ORDER
      .filter((s) => counts[s])
      .map((s) => `${s.toUpperCase()}: ${counts[s]}`)
      .join("    ") || "No findings matched the remediation filter.";
    doc.text(summaryLine);
    doc.text(`Total findings needing remediation: ${report.total}`);
    if (report.filter) {
      doc.moveDown(0.2);
      doc.fontSize(9).fillColor("#777")
        .text(`Severities included: ${report.filter.impactTypes.join(", ")}`)
        .text(`Status included: ${report.filter.statuses.join(", ")} (passed and dismissed excluded)`);
    }
    doc.moveDown(1);

    doc.fontSize(13).fillColor("#000").text("Findings", { underline: true });
    doc.moveDown(0.5);

    if (!report.findings.length) {
      doc.fontSize(10).fillColor("#333").text("No open findings match the selected severity filter.");
    }

    report.findings.forEach((f, i) => {
      if (doc.y > 700) doc.addPage();
      doc.fontSize(11).fillColor(severityColor(f.impactType))
        .text(`${i + 1}. [${String(f.impactType).toUpperCase()}] ${f.title}`);
      doc.fontSize(9).fillColor("#555");
      const meta = [];
      if (f.cvss != null) meta.push(`CVSS: ${f.cvss}`);
      if (f.cvssVector) meta.push(f.cvssVector);
      if (f.category) meta.push(`Category: ${f.category}`);
      if (f.checkId) meta.push(`Check: ${f.checkId}`);
      if (f.status) meta.push(`Status: ${f.status}`);
      if (meta.length) doc.text(meta.join("   |   "));

      const section = (label, body) => {
        if (!body) return;
        if (doc.y > 730) doc.addPage();
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor("#000").text(label, { continued: false });
        doc.fontSize(9).fillColor("#222").text(body, { width: 495 });
      };

      section("Description:", f.description);
      section("Business impact:", f.impactSummary);
      section("Remediation:", f.remediation);

      // App-specific evidence (where it actually is in the app)
      if (f.evidence && f.evidence.length) {
        if (doc.y > 720) doc.addPage();
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor("#000").text("Evidence (detected in this build):");
        doc.fontSize(8).fillColor("#333").font("Courier");
        for (const e of f.evidence) {
          const indent = "  ".repeat(Math.max(0, e.depth));
          doc.text(`${indent}- ${e.text}`, { width: 495 });
        }
        doc.font("Helvetica");
      }

      // Code samples for the fix
      if (f.codeSamples && f.codeSamples.length) {
        if (doc.y > 700) doc.addPage();
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor("#000").text("Fix examples:");
        for (const c of f.codeSamples) {
          if (c.caption) doc.fontSize(8).fillColor("#555").text(`${c.caption}${c.syntax ? ` (${c.syntax})` : ""}`);
          if (c.block) {
            doc.fontSize(8).fillColor("#111").font("Courier").text(stripHtml(c.block), { width: 495 });
            doc.font("Helvetica");
          }
        }
      }

      // Guidance links
      if (f.guidanceLinks && f.guidanceLinks.length) {
        doc.moveDown(0.2);
        doc.fontSize(8).fillColor("#000").text("References:");
        for (const g of f.guidanceLinks) {
          doc.fontSize(8).fillColor("#1565c0").text(`- ${g.caption}: ${g.url}`, { width: 495, link: g.url });
        }
      }

      doc.moveDown(0.8);
    });

    doc.end();
  });

  return abs;
}

function stripHtml(s) {
  return String(s)
    .replace(/<\/?[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// ----------------------------- MCP wiring -----------------------------

const TOOLS = [
  {
    name: "list_applications",
    description:
      "List applications in your NowSecure portfolio (REST /v2/portfolio/applications). Use to discover app refs and the latest assessment per app.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "number", description: "Number of apps to return (default 20)." },
        orderBy: { type: "string", description: "Field to order by, e.g. 'score' (default).", default: "score" },
      },
    },
  },
  {
    name: "get_remediation_findings",
    description:
      "Pull findings that need remediation for an assessment, as structured JSON. Bypasses the broken NowSecure UI PDF renderer by querying GraphQL directly. Returns only open findings that require remediation (status detected/fail/open), filtered by severity (default: blocker, critical, high, medium). Passed and dismissed findings are excluded.",
    inputSchema: {
      type: "object",
      properties: {
        appRef: { type: "string", description: "Application ref (UUID), e.g. 123e4567-e89b-12d3-a456-426614174000." },
        assessmentRef: { type: "string", description: "Assessment ref (UUID). If omitted, the latest assessment is used." },
        impactTypes: {
          type: "array",
          items: { type: "string" },
          description: "Severities to include. Default: ['blocker','critical','high','medium'].",
        },
      },
      required: ["appRef"],
    },
  },
  {
    name: "generate_remediation_pdf",
    description:
      "Generate a clean remediation PDF locally from NowSecure findings (rendered by this server, NOT NowSecure's broken report service). Includes only open findings requiring remediation (default severities: blocker, critical, high, medium). Guaranteed to work even when the UI/REST PDF export fails. The server auto-names the file as [App_Name]_NowSecure_report_[yyyy-MM-dd_HHmmss].pdf when given outputDir + appName.",
    inputSchema: {
      type: "object",
      properties: {
        appRef: { type: "string", description: "Application ref (UUID)." },
        assessmentRef: { type: "string", description: "Assessment ref (UUID). If omitted, the latest assessment is used." },
        outputDir: { type: "string", description: "Directory to save the report into (e.g. the current workspace root). The server auto-generates the filename. Defaults to the server's working directory if neither outputDir nor outputPath is given." },
        appName: { type: "string", description: "Human-readable app name used in the auto-generated filename (e.g. 'My App'). Spaces become underscores. Falls back to the package key if omitted." },
        outputPath: { type: "string", description: "Explicit full file path. Overrides outputDir/appName auto-naming when provided, e.g. C:/Users/you/Downloads/remediation.pdf." },
        impactTypes: {
          type: "array",
          items: { type: "string" },
          description: "Severities to include. Default: ['blocker','critical','high','medium'].",
        },
      },
      required: ["appRef"],
    },
  },
  {
    name: "run_graphql",
    description:
      "Run an arbitrary GraphQL query/mutation against the NowSecure Platform API. Escape hatch for schema introspection and custom queries.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "GraphQL query string." },
        variables: { type: "object", description: "Optional variables object." },
      },
      required: ["query"],
    },
  },
  {
    name: "download_assessment_pdf",
    description:
      "Attempt to download NowSecure's own PDF via the REST report endpoint (/report/assessment/ref/{ref}.pdf). This is a different code path than the broken UI export and may succeed. Falls back gracefully with an error if NowSecure's renderer also fails.",
    inputSchema: {
      type: "object",
      properties: {
        assessmentRef: { type: "string", description: "Assessment ref (UUID)." },
        outputPath: { type: "string", description: "Where to write the PDF." },
        onlyRemediation: {
          type: "boolean",
          description: "If true (default), filters to open/detected findings with remediation resources and hides screenshots.",
          default: true,
        },
      },
      required: ["assessmentRef", "outputPath"],
    },
  },
];

const server = new Server(
  { name: "nowsecure-mcp-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    switch (name) {
      case "list_applications": {
        const sp = new URLSearchParams();
        sp.append("filters", "[]");
        sp.append("orderBy[0]", args.orderBy || "score");
        sp.append("pageSize", String(args.pageSize || 20));
        sp.append("includeSummaryInfo", "true");
        const data = await restGet(`/v2/portfolio/applications?${sp.toString()}`);
        return jsonResult(data);
      }
      case "get_remediation_findings": {
        const report = await fetchAssessmentFindings({
          appRef: args.appRef,
          assessmentRef: args.assessmentRef,
          impactTypes: args.impactTypes,
        });
        return jsonResult(report);
      }
      case "generate_remediation_pdf": {
        const report = await fetchAssessmentFindings({
          appRef: args.appRef,
          assessmentRef: args.assessmentRef,
          impactTypes: args.impactTypes,
        });
        // Resolve output path. Precedence:
        //   1. explicit outputPath (used verbatim)
        //   2. outputDir + auto-generated conventional filename
        //   3. cwd + auto-generated conventional filename
        let target;
        if (args.outputPath) {
          target = args.outputPath;
        } else {
          const dir = args.outputDir || process.cwd();
          target = `${dir.replace(/[\\/]+$/, "")}/${defaultReportFilename(report, args.appName)}`;
        }
        const path = await buildPdf(report, target);
        return textResult(
          `PDF generated locally at: ${path}\n` +
          `Findings included: ${report.total} (${Object.entries(report.counts).map(([k, v]) => `${k}:${v}`).join(", ") || "none"})\n` +
          `This bypasses NowSecure's broken report renderer entirely.\n` +
          `— nowsecure-mcp-server by 🎈💜`
        );
      }
      case "run_graphql": {
        const data = await graphql(args.query, args.variables || {});
        return jsonResult(data);
      }
      case "download_assessment_pdf": {
        const path = await downloadNowSecurePdf(args);
        return textResult(`NowSecure REST PDF saved to: ${path}`);
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error in ${name}: ${err.message}` }],
    };
  }
});

async function downloadNowSecurePdf({ assessmentRef, outputPath, onlyRemediation = true }) {
  assertToken();
  const abs = resolve(outputPath);
  await mkdir(dirname(abs), { recursive: true });
  const url = new URL(`${API_BASE}/report/assessment/ref/${assessmentRef}.pdf`);
  if (onlyRemediation) {
    url.searchParams.append("status[]", "detected");
    url.searchParams.append("finding.remediationResources", "true");
    url.searchParams.append("finding.description", "true");
    url.searchParams.append("finding.businessImpact", "true");
    url.searchParams.append("screenshots", "false");
    for (const s of ["critical", "high", "medium", "low"]) url.searchParams.append("impactType[]", s);
  }
  const res = await fetch(url, { headers: authHeaders({ Accept: "application/pdf" }) });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `NowSecure REST PDF ${res.status} ${res.statusText}: ${body.slice(0, 500)}\n` +
      `If this also fails on the server side, use generate_remediation_pdf instead (renders locally).`
    );
  }
  const buf = Buffer.from(await res.arrayBuffer());
  const { writeFile } = await import("node:fs/promises");
  await writeFile(abs, buf);
  return abs;
}

function jsonResult(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}
function textResult(text) {
  return { content: [{ type: "text", text }] };
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Logs go to stderr so they don't corrupt the stdio JSON-RPC stream.
  console.error(`${CREDIT} — API base: ${API_BASE}. Token set: ${TOKEN ? "yes" : "NO"}`);
}

// Only auto-start when run directly (not when imported by a test harness).
import { fileURLToPath } from "node:url";
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}

export { fetchAssessmentFindings, buildPdf, graphql, graphqlWithRetry };
