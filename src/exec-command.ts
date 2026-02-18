/**
 * exec_command A2A tool handler.
 *
 * Ported from wopr core src/core/a2a-tools/http-exec.ts (exec_command portion).
 * Registered as an A2A tool via the plugin's registerA2AServer call.
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

import { exec } from "node:child_process";
import { promisify } from "node:util";
import { checkCommandPolicy } from "./security-policy.js";
import type { A2AToolResult, ToolsPluginConfig } from "./types.js";

const execAsync = promisify(exec);

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

    // Non-sandboxed path: enforce command allowlist
    // TODO: Sandbox exec not supported — WOPRPluginContext does not expose
    // execInSandbox or isSessionSandboxed from core security module.
    // File a follow-up issue to expose sandbox APIs via plugin context.
    const commandError = checkCommandPolicy(command, config);
    if (commandError) {
      return { content: [{ type: "text", text: commandError }], isError: true };
    }

    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: cwd || undefined,
        timeout: effectiveTimeout,
        maxBuffer: 1024 * 1024,
      });
      let output = stdout;
      if (stderr) output += `\n[stderr]\n${stderr}`;
      if (output.length > 10000) output = `${output.substring(0, 10000)}\n... (truncated)`;
      return { content: [{ type: "text", text: output || "(no output)" }] };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `Command failed: ${message}` }], isError: true };
    }
  };
}
