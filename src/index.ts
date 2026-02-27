/**
 * WOPR Tools Plugin
 *
 * Provides opt-in http_fetch and exec_command A2A tools.
 * These are security-sensitive capabilities that admins explicitly install.
 */

import { createExecCommandHandler } from "./exec-command.js";
import { createHttpFetchHandler } from "./http-fetch.js";
import { parseList } from "./security-policy.js";
import type { ConfigSchema, PluginManifest, ToolsPluginConfig, WOPRPlugin, WOPRPluginContext } from "./types.js";

let ctx: WOPRPluginContext | null = null;
const cleanups: Array<() => void> = [];

function getToolsConfig(): ToolsPluginConfig {
  if (!ctx) return {};
  const raw = ctx.getConfig<Record<string, unknown>>() ?? {};
  // Config fields may arrive as comma-separated strings — normalize to arrays.
  return {
    ...raw,
    allowedDomains: raw.allowedDomains !== undefined ? parseList(raw.allowedDomains) : undefined,
    blockedDomains: raw.blockedDomains !== undefined ? parseList(raw.blockedDomains) : undefined,
    allowedCommands: raw.allowedCommands !== undefined ? parseList(raw.allowedCommands) : undefined,
  } as ToolsPluginConfig;
}

const configSchema: ConfigSchema = {
  title: "Tools Plugin",
  description: "Configure security policies for HTTP fetch and shell exec tools",
  fields: [
    {
      name: "allowedDomains",
      type: "text",
      label: "Allowed Domains",
      placeholder: "api.example.com, cdn.example.com (comma-separated, empty = all)",
      description: "Comma-separated list of allowed domains for http_fetch. Empty means all domains allowed.",
      setupFlow: "paste",
    },
    {
      name: "blockedDomains",
      type: "text",
      label: "Blocked Domains",
      placeholder: "internal.corp, 169.254.169.254 (comma-separated)",
      description:
        "Comma-separated list of blocked domains (takes priority over allowed list). Always block metadata endpoints.",
      setupFlow: "paste",
    },
    {
      name: "allowedCommands",
      type: "text",
      label: "Allowed Commands",
      placeholder: "ls, cat, grep, ... (comma-separated, empty = default safe set)",
      description: "Comma-separated list of allowed commands for exec_command (non-sandboxed mode only).",
      setupFlow: "paste",
    },
  ],
};

const manifest: PluginManifest = {
  name: "@wopr-network/wopr-plugin-tools",
  version: "1.0.0",
  description: "HTTP fetch and shell exec tools — opt-in security-sensitive capabilities for WOPR bots",
  author: "WOPR",
  license: "MIT",
  repository: "https://github.com/wopr-network/wopr-plugin-tools",
  capabilities: ["http_fetch", "exec_command"],
  category: "tools",
  tags: ["http", "fetch", "exec", "shell", "tools", "security"],
  icon: "wrench",
  configSchema,
  lifecycle: {
    shutdownBehavior: "graceful",
    shutdownTimeoutMs: 5000,
  },
};

function buildA2AConfig(
  httpFetchHandler: ReturnType<typeof createHttpFetchHandler>,
  execCommandHandler: ReturnType<typeof createExecCommandHandler>,
) {
  return {
    name: "wopr-plugin-tools",
    version: "1.0.0",
    tools: [
      {
        name: "http_fetch",
        description:
          "Make an HTTP request to an external URL. Supports arbitrary headers including Authorization, API keys, etc.",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", description: "URL to fetch" },
            method: { type: "string", description: "HTTP method (default: GET)" },
            headers: {
              type: "object",
              description: "Request headers as key-value pairs",
              additionalProperties: { type: "string" },
            },
            body: { type: "string", description: "Request body (for POST, PUT, PATCH)" },
            timeout: { type: "number", description: "Timeout in ms (default: 30000)" },
            includeHeaders: { type: "boolean", description: "Include response headers in output (default: false)" },
          },
          required: ["url"],
        },
        handler: httpFetchHandler,
      },
      {
        name: "exec_command",
        description:
          "Execute a shell command. Only safe commands allowed (ls, cat, grep, etc.) unless admin configures otherwise.",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "Command to execute" },
            cwd: { type: "string", description: "Working directory" },
            timeout: { type: "number", description: "Timeout in ms (default: 10000, max: 60000)" },
          },
          required: ["command"],
        },
        handler: execCommandHandler,
      },
    ],
  };
}

const plugin: WOPRPlugin = {
  name: "wopr-plugin-tools",
  version: "1.0.0",
  description: "HTTP fetch and shell exec tools (opt-in security capabilities)",
  manifest,

  async init(context: WOPRPluginContext) {
    cleanups.length = 0;
    ctx = context;
    ctx.registerConfigSchema("wopr-plugin-tools", configSchema);
    cleanups.push(() => {
      if (ctx?.unregisterConfigSchema) {
        ctx.unregisterConfigSchema("wopr-plugin-tools");
      }
    });

    if (!ctx.registerA2AServer) {
      ctx.log.error("registerA2AServer not available - cannot register tools. Is WOPR core up to date?");
      return;
    }

    const httpFetchHandler = createHttpFetchHandler(getToolsConfig);
    const execCommandHandler = createExecCommandHandler(getToolsConfig);

    ctx.registerA2AServer(buildA2AConfig(httpFetchHandler, execCommandHandler));

    ctx.log.info("Tools plugin initialized: http_fetch, exec_command registered as A2A tools");
  },

  async shutdown() {
    for (const cleanup of cleanups) {
      cleanup();
    }
    cleanups.length = 0;
    ctx = null;
    // NOTE: A2A tools registered via registerA2AServer remain registered after
    // shutdown — the platform does not expose unregisterA2AServer. This is a
    // known platform limitation affecting all plugins, not specific to this one.
  },
};

export default plugin;
