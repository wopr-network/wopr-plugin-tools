/**
 * WOPR Tools Plugin
 *
 * Provides opt-in http_fetch and exec_command A2A tools.
 * These are security-sensitive capabilities that admins explicitly install.
 */

import { createExecCommandHandler } from "./exec-command.js";
import { createHttpFetchHandler } from "./http-fetch.js";
import { parseList } from "./security-policy.js";
import type { ConfigSchema, ToolsPluginConfig, WOPRPlugin, WOPRPluginContext } from "./types.js";

let ctx: WOPRPluginContext | null = null;

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
    },
    {
      name: "blockedDomains",
      type: "text",
      label: "Blocked Domains",
      placeholder: "internal.corp, 169.254.169.254 (comma-separated)",
      description:
        "Comma-separated list of blocked domains (takes priority over allowed list). Always block metadata endpoints.",
    },
    {
      name: "allowedCommands",
      type: "text",
      label: "Allowed Commands",
      placeholder: "ls, cat, grep, ... (comma-separated, empty = default safe set)",
      description: "Comma-separated list of allowed commands for exec_command (non-sandboxed mode only).",
    },
  ],
};

const plugin: WOPRPlugin = {
  name: "wopr-plugin-tools",
  version: "1.0.0",
  description: "HTTP fetch and shell exec tools (opt-in security capabilities)",

  async init(context: WOPRPluginContext) {
    ctx = context;
    ctx.registerConfigSchema("wopr-plugin-tools", configSchema);

    if (!ctx.registerA2AServer) {
      ctx.log.error("registerA2AServer not available - cannot register tools. Is WOPR core up to date?");
      return;
    }

    const httpFetchHandler = createHttpFetchHandler(getToolsConfig);
    const execCommandHandler = createExecCommandHandler(getToolsConfig);

    // TODO: Tools registered via registerA2AServer bypass the withSecurityCheck
    // wrapper used by core tools. The plugin tool path in a2a-mcp.ts does not
    // call checkToolPermission before invoking the handler. This is a pre-existing
    // gap for ALL plugin tools, not specific to this plugin. The TOOL_CAPABILITY_MAP
    // entries for http_fetch and exec_command remain in core security/types.ts for
    // policy enforcement, but they are not enforced at call time for plugin tools.
    // Track this in a follow-up issue (e.g., WOP-568).
    ctx.registerA2AServer({
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
    });

    // TODO: No unregisterA2AServer exists in core. On plugin shutdown, tools remain
    // in the pluginTools Map until the MCP server is rebuilt without this plugin.
    // The core plugin lifecycle should handle cleanup. File a follow-up issue if
    // stale tool entries cause problems after plugin removal.
    ctx.log.info("Tools plugin initialized: http_fetch, exec_command registered as A2A tools");
  },

  async shutdown() {
    ctx = null;
  },
};

export default plugin;
