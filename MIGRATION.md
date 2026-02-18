# Migration Guide

## Migrating from WOPR core built-in http_fetch / exec_command

As of the WOPR release that removes `http-exec.ts` from core, the `http_fetch`
and `exec_command` A2A tools are **no longer bundled with WOPR**. They are now
provided by this plugin as an explicit opt-in.

### Impact

**Existing bots will lose access to `http_fetch` and `exec_command` after the
core update until this plugin is installed.**

### To restore these tools

```bash
wopr plugin install @wopr-network/wopr-plugin-tools
```

Or add to your `plugins.json`:

```json
{
  "plugins": [
    "@wopr-network/wopr-plugin-tools"
  ]
}
```

Then restart the WOPR daemon.

### Security note

These tools expose HTTP fetch (SSRF surface) and shell exec (RCE surface).
Only install this plugin on bots that require these capabilities. Configure
`allowedDomains`, `blockedDomains`, and `allowedCommands` in the plugin
settings to restrict access appropriately.
