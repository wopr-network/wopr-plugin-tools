/**
 * Type definitions for the WOPR tools plugin.
 *
 * Shared types are re-exported from @wopr-network/plugin-types.
 * Plugin-specific types are defined here.
 */

export type {
  A2AServerConfig,
  A2AToolDefinition,
  A2AToolResult,
  ConfigField,
  ConfigSchema,
  PluginCommand,
  PluginManifest,
  WOPRPlugin,
  WOPRPluginContext,
} from "@wopr-network/plugin-types";

/**
 * Configuration for the tools plugin.
 * Admins configure security policies via plugin config.
 */
export interface ToolsPluginConfig {
  /** Allowed domains for http_fetch (empty = all allowed) */
  allowedDomains?: string[];
  /** Blocked domains for http_fetch (checked first, overrides allowedDomains) */
  blockedDomains?: string[];
  /** Maximum timeout in ms for http_fetch (default: 30000) */
  maxTimeout?: number;
  /** Maximum response body size in characters (default: 10000) */
  maxResponseSize?: number;
  /** Allowed commands for exec_command when not sandboxed (default: safe set) */
  allowedCommands?: string[];
  /** Whether to block shell operators in exec_command (default: true) */
  blockShellOperators?: boolean;
  /** Maximum exec timeout in ms (default: 60000) */
  maxExecTimeout?: number;
}
