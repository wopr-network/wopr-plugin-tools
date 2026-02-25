/**
 * Security policy enforcement for http_fetch and exec_command.
 *
 * This module contains the allowlist/blocklist logic that was previously
 * hardcoded in core. Making it configurable per-plugin gives admins
 * fine-grained control.
 */

import type { ToolsPluginConfig } from "./types.js";

const DEFAULT_ALLOWED_COMMANDS = [
  "ls",
  "cat",
  "grep",
  "find",
  "echo",
  "date",
  "pwd",
  "whoami",
  "head",
  "tail",
  "wc",
  "sort",
  "uniq",
  "diff",
  "which",
  "file",
  "stat",
  "du",
  "df",
  "uptime",
  "hostname",
  "uname",
];

const SHELL_OPERATORS = [";", "&&", "||", "|", "`", "$("];

/**
 * Parse a config value that may be a string (comma-separated) or already an array.
 */
export function parseList(val: unknown): string[] {
  if (Array.isArray(val)) return val as string[];
  if (typeof val === "string")
    return val
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  return [];
}

/**
 * Check if a URL is allowed by the domain policy.
 * Returns null if allowed, or an error message string if blocked.
 */
export function checkDomainPolicy(url: string, config: ToolsPluginConfig): string | null {
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return `Invalid URL: ${url}`;
  }

  // Blocked domains are checked first (override allow)
  if (config.blockedDomains?.length) {
    for (const blocked of config.blockedDomains) {
      if (hostname === blocked || hostname.endsWith(`.${blocked}`)) {
        return `Domain '${hostname}' is blocked by security policy`;
      }
    }
  }

  // If allowedDomains is set and non-empty, only those are permitted
  if (config.allowedDomains?.length) {
    const allowed = config.allowedDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
    if (!allowed) {
      return `Domain '${hostname}' is not in the allowed domains list`;
    }
  }

  return null; // Allowed
}

/**
 * Check if a command is allowed by the exec policy (non-sandboxed mode only).
 * Returns null if allowed, or an error message string if blocked.
 */
export function checkCommandPolicy(command: string, config: ToolsPluginConfig): string | null {
  const allowedCommands = config.allowedCommands ?? DEFAULT_ALLOWED_COMMANDS;
  const blockOperators = config.blockShellOperators !== false; // default true

  // Check shell operators first — they take priority and produce a clearer error message.
  if (blockOperators) {
    for (const op of SHELL_OPERATORS) {
      if (command.includes(op)) {
        return "Shell operators not allowed on host. Enable sandboxing for full shell access.";
      }
    }
  }

  const firstWord = command.trim().split(/\s+/)[0];
  if (!allowedCommands.includes(firstWord)) {
    return `Command '${firstWord}' not allowed. Allowed: ${allowedCommands.join(", ")}. Enable sandboxing for full shell access.`;
  }

  return null; // Allowed
}

export { DEFAULT_ALLOWED_COMMANDS, SHELL_OPERATORS };
