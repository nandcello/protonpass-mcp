# Proton Pass CLI MCP

A small stdio MCP server that exposes three Proton Pass actions:

- `create_alias` creates a hide-my-email alias and returns its address.
- `create_login` creates a login item with a password generated inside Proton Pass.
- `get_totp` returns the current one-time code or codes for a login item.

The generated login password is never passed into the MCP server and is never
returned to the model. The server invokes Proton Pass CLI's
`--generate-password` option so the password is generated and stored by Proton
Pass itself.

## Requirements

- [Vite+](https://viteplus.dev/) (`vp`)
- Bun 1.3.14 (resolved automatically by Vite+)
- Node.js 20 or newer (managed by Vite+)
- [Proton Pass CLI](https://proton.me/blog/proton-pass-cli) available as
  `pass-cli`
- An authenticated Proton Pass CLI session

Authenticate before starting the MCP client:

```sh
pass-cli login
pass-cli test
```

## Install and test

```sh
cd /path/to/protonpass-mcp
vp install
vp check
vp run test
```

Vite+ delegates package installation and dependency changes to the Bun version
pinned in `package.json`. Use `vp add`, `vp remove`, and `vp update` for normal
dependency maintenance; use `vp pm <command>` when a Bun-specific package
manager command is needed. `bun.lock` is the only package-manager lockfile for
this project.

## Add to Codex

Register the local stdio server:

```sh
codex mcp add protonpass \
  --env PROTONPASS_CLI_PATH=/absolute/path/to/pass-cli \
  -- node /absolute/path/to/protonpass-mcp/src/index.js
```

Alternatively, add it to `~/.codex/config.toml`:

```toml
[mcp_servers.protonpass]
command = "node"
args = ["/absolute/path/to/protonpass-mcp/src/index.js"]

[mcp_servers.protonpass.env]
PROTONPASS_CLI_PATH = "/absolute/path/to/pass-cli"
```

Restart the MCP client or start a new task after changing its MCP
configuration.

## Tool inputs

### `create_alias`

```json
{
  "prefix": "github",
  "vaultName": "Personal"
}
```

`vaultName` and `shareId` are optional and mutually exclusive. If both are
omitted, Proton Pass CLI's default vault is used.

### `create_login`

```json
{
  "title": "GitHub",
  "email": "github-alias@example.com",
  "urls": ["https://github.com"],
  "vaultName": "Personal",
  "passwordLength": 24,
  "includeUppercase": true,
  "includeSymbols": true
}
```

At least one of `username` or `email` is required. The password length defaults
to 24. The login result confirms that a password was generated but deliberately
does not reveal it.

### `get_totp`

Select the login with exactly one of `uri`, `itemId`, or `itemTitle`:

```json
{
  "itemTitle": "GitHub",
  "vaultName": "Personal",
  "field": "Authenticator"
}
```

`field` is optional and is useful when an item has multiple TOTP fields.
`get_totp` returns the current codes and their field metadata, but never returns
the underlying TOTP secret.

## Configuration

- `PROTONPASS_CLI_PATH`: Proton Pass CLI executable; defaults to `pass-cli`.
- `PROTONPASS_TIMEOUT_MS`: command timeout in milliseconds; defaults to 60000.

The server uses direct process execution without a shell. It writes protocol
messages only to stdout and does not log tool arguments or CLI output.
