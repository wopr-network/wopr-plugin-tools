/**
 * exec_command A2A tool handler.
 *
 * Ported from wopr core src/core/a2a-tools/http-exec.ts (exec_command portion).
 * Registered as an A2A tool via the plugin's registerA2AServer call.
 *
 * Security hardening (WOP-1068):
 * - Uses execFile instead of exec (no shell interpolation)
 * - Strips environment variables (prevents secret leakage)
 * - Validates cwd against path traversal and sensitive directories
 * - Blocks access to sensitive file paths in arguments
 * - Configurable output size limit
 *
 * NOTE: The sandbox integration (Docker exec, session directory resolution,
 * cross-session checks) requires core APIs that are NOT available via
 * WOPRPluginContext. This plugin version implements the non-sandboxed
 * (host command) path only. Sandboxed sessions will need the core security
 * module to be exposed via a future plugin API extension.
 *
 * For now, when the plugin cannot determine sandbox status, it falls back
 * to the safe (non-sandboxed) command allowlist behavior.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parse as parseShellQuote } from "shell-quote";
import { checkCommandPolicy, checkCwdPolicy } from "./security-policy.js";
import type { A2AToolResult, ToolsPluginConfig } from "./types.js";

const execFileAsync = promisify(execFile);

/** Minimal safe environment for child processes. */
const SAFE_ENV_KEYS = ["PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TZ"];

function buildSafeEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of SAFE_ENV_KEYS) {
    if (process.env[key]) {
      env[key] = process.env[key] as string;
    }
  }
  return env;
}

export interface ExecCommandArgs {
  command: string;
  cwd?: string;
  timeout?: number;
}

export function createExecCommandHandler(getConfig: () => ToolsPluginConfig) {
  return async (args: Record<string, unknown>): Promise<A2AToolResult> => {
    const { command, cwd, timeout = 10000 } = args as unknown as ExecCommandArgs;

    const config = getConfig();
    const maxExecTimeout = config.maxExecTimeout ?? 60000;
    const effectiveTimeout = Math.min(timeout, maxExecTimeout);
    const maxOutputSize = config.maxOutputSize ?? 10000;
    const stripEnv = config.stripEnv !== false; // default true

    // Validate cwd
    const cwdError = checkCwdPolicy(cwd);
    if (cwdError) {
      return { content: [{ type: "text", text: cwdError }], isError: true };
    }

    // Non-sandboxed path: enforce command allowlist + sensitive path checks
    // TODO: Sandbox exec not supported — WOPRPluginContext does not expose
    // session name to A2A tool handlers. The A2AToolDefinition handler signature
    // is (args) => Result, but core passes (args, {sessionName}) at runtime.
    // A future plugin-types change could add ToolContext to the handler signature,
    // enabling sandbox routing via ctx.getExtension("sandbox").
    const commandError = checkCommandPolicy(command, config);
    if (commandError) {
      return { content: [{ type: "text", text: commandError }], isError: true };
    }

    // Parse command into executable + args for execFile (no shell)
    // shell-quote handles quoted arguments correctly (e.g. echo "hello world")
    const parsedParts = parseShellQuote(command);
    const parts = parsedParts.filter((p): p is string => typeof p === "string");
    if (parts.length === 0) {
      return { content: [{ type: "text", text: "Empty command" }], isError: true };
    }
    const executable = parts[0];
    const execArgs = parts.slice(1);

    try {
      const { stdout, stderr } = await execFileAsync(executable, execArgs, {
        cwd: cwd || undefined,
        timeout: effectiveTimeout,
        maxBuffer: 1024 * 1024,
        env: stripEnv ? buildSafeEnv() : undefined,
      });
      let output = stdout;
      if (stderr) output += `\n[stderr]\n${stderr}`;
      if (output.length > maxOutputSize) output = `${output.substring(0, maxOutputSize)}\n... (truncated)`;
      return { content: [{ type: "text", text: output || "(no output)" }] };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Command failed: ${message}` }], isError: true };
    }
  };
}
