# Proton Pass CLI MCP

A small stdio MCP server that exposes five Proton Pass and SimpleLogin actions:

- `search_aliases` searches account-wide aliases and returns a page of matches.
- `create_alias` creates a hide-my-email alias and returns its address.
- `get_or_create_alias_contact` gets or creates a contact for an alias and returns its reverse-alias address.
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
- A SimpleLogin API key for `search_aliases` and `get_or_create_alias_contact`

Authenticate before starting the MCP client:

```sh
pass-cli login
pass-cli test
```

Copy `.env.example` to `.env` and add a SimpleLogin API key:

```sh
cp .env.example .env
```

The server loads `.env` from its project directory without overriding variables
already provided by the parent process. `.env` is ignored by Git; only
`.env.example` is tracked.

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
  -- node /absolute/path/to/protonpass-mcp/src/index.js \
  --share-id VAULT_SHARE_ID
```

Alternatively, add it to `~/.codex/config.toml`:

```toml
[mcp_servers.protonpass]
command = "node"
args = [
  "/absolute/path/to/protonpass-mcp/src/index.js",
  "--share-id",
  "VAULT_SHARE_ID",
]

[mcp_servers.protonpass.env]
PROTONPASS_CLI_PATH = "/absolute/path/to/pass-cli"
SIMPLELOGIN_API_KEY = "YOUR_SIMPLELOGIN_API_KEY"
```

Restart the MCP client or start a new task after changing its MCP
configuration.

Exactly one vault selector is required when the server starts:

- `--share-id VAULT_SHARE_ID` selects a vault by its unique share ID and is
  recommended.
- `--vault-name VAULT_NAME` selects a vault by name.

Find a vault's share ID with `pass-cli vault list`. The selected vault is fixed
for the lifetime of the server. Vault selectors are operator configuration, are
not exposed as tool inputs or results, and are required by every Proton Pass CLI
command.

`search_aliases` and `get_or_create_alias_contact` are exceptions to vault
scoping: Proton Pass CLI does not expose alias search or alias-contact
operations, so these tools use the account-wide SimpleLogin API. The API key can
access aliases outside the selected Proton Pass vault.

## Tool inputs

### `create_alias`

```json
{
  "prefix": "github"
}
```

### `search_aliases`

```json
{
  "query": "github",
  "page": 0
}
```

`page` is optional and defaults to `0`. Each page contains at most 20 matches.
Results include only the alias address, display name, and enabled state.

### `create_login`

```json
{
  "title": "GitHub",
  "email": "github-alias@example.com",
  "urls": ["https://github.com"],
  "passwordLength": 24,
  "includeUppercase": true,
  "includeSymbols": true
}
```

At least one of `username` or `email` is required. The password length defaults
to 24. The login result confirms that a password was generated but deliberately
does not reveal it.

### `get_or_create_alias_contact`

```json
{
  "alias": "github-alias@example.com",
  "contact": "support@example.org"
}
```

The result includes `reverseAlias`, the address to use when sending mail from
the alias to that contact. If the contact already exists, the same operation
returns its reverse alias with `created` set to `false` and `existed` set to
`true`.

### `get_totp`

Select the login with exactly one of `itemId` or `itemTitle`:

```json
{
  "itemTitle": "GitHub",
  "field": "Authenticator"
}
```

`field` is optional and is useful when an item has multiple TOTP fields.
`get_totp` returns the current codes and their field metadata, but never returns
the underlying TOTP secret.

## Configuration

- `PROTONPASS_CLI_PATH`: Proton Pass CLI executable; defaults to `pass-cli`.
- `PROTONPASS_TIMEOUT_MS`: command timeout in milliseconds; defaults to 60000.
- `SIMPLELOGIN_API_KEY`: SimpleLogin API key required by `search_aliases` and
  `get_or_create_alias_contact`.
- `SIMPLELOGIN_API_BASE_URL`: API base URL; defaults to
  `https://app.simplelogin.io` and can be changed for self-hosted SimpleLogin.
- `SIMPLELOGIN_TIMEOUT_MS`: SimpleLogin request timeout in milliseconds;
  defaults to 60000.

The server invokes Proton Pass CLI directly without a shell and calls
SimpleLogin over HTTPS (or loopback HTTP for local self-hosting). It writes
protocol messages only to stdout and does not log tool arguments, API keys, CLI
output, or SimpleLogin API responses.
