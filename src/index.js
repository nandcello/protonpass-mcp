#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config as loadEnv } from "dotenv";
import * as z from "zod/v4";
import { VaultLock, findLogins, getLoginCredentials } from "./credentials.js";
import {
  createAlias,
  createLogin,
  getTotp,
  normalizeLoginUrl,
  normalizeVaultSelector,
} from "./protonpass.js";
import { getOrCreateAliasContact, searchAliases } from "./simplelogin.js";

const createAliasInput = z
  .object({
    prefix: z
      .string()
      .trim()
      .min(1)
      .max(100)
      .describe(
        "Readable alias prefix, usually based on the service name (for example, `github`).",
      ),
  })
  .strict();

const createLoginInput = z
  .object({
    title: z.string().trim().min(1).max(255).describe("Title for the Proton Pass login item."),
    username: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe("Login username, if the service uses one."),
    email: z
      .email()
      .optional()
      .describe("Login email, which may be an address returned by create_alias."),
    urls: z
      .array(
        z
          .string()
          .trim()
          .min(1)
          .max(2048)
          .refine((value) => normalizeLoginUrl(value) !== undefined, {
            message: "Each URL must be an http(s) URL or a bare domain.",
          }),
      )
      .max(20)
      .optional()
      .describe(
        "One or more website URLs associated with this login. A bare domain such as `example.com` is saved as `https://example.com`.",
      ),
    passwordLength: z
      .int()
      .min(12)
      .max(128)
      .default(24)
      .describe("Length of the generated password. Defaults to 24."),
    includeUppercase: z
      .boolean()
      .default(true)
      .describe("Include uppercase letters in the generated password."),
    includeSymbols: z
      .boolean()
      .default(true)
      .describe("Include symbols in the generated password."),
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.username && !value.email) {
      context.addIssue({
        code: "custom",
        message: "Provide at least one of username or email.",
        path: ["username"],
      });
    }
  });

const searchAliasesInput = z
  .object({
    query: z
      .string()
      .trim()
      .min(1)
      .max(320)
      .describe("Text to search for across the account's SimpleLogin aliases."),
    page: z
      .int()
      .min(0)
      .default(0)
      .describe("Zero-based results page. Each page contains at most 20 aliases."),
  })
  .strict();

const getOrCreateAliasContactInput = z
  .object({
    alias: z.email().describe("Existing SimpleLogin or Proton Pass hide-my-email alias address."),
    contact: z
      .email()
      .describe("External email address that the alias should be able to send mail to."),
  })
  .strict();

const getTotpInput = z
  .object({
    itemId: z.string().trim().min(1).optional().describe("ID of the login item."),
    itemTitle: z.string().trim().min(1).optional().describe("Exact title of the login item."),
    field: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe("Specific TOTP field name when the item contains more than one."),
  })
  .strict()
  .superRefine((value, context) => {
    const selectors = [value.itemId, value.itemTitle].filter(Boolean);
    if (selectors.length !== 1) {
      context.addIssue({
        code: "custom",
        message: "Provide exactly one of itemId or itemTitle.",
        path: ["itemTitle"],
      });
    }
  });

const findLoginsInput = z
  .object({
    query: z
      .string()
      .trim()
      .min(1)
      .max(255)
      .optional()
      .describe("Case-insensitive substring of the login title."),
    url: z
      .string()
      .trim()
      .min(1)
      .max(2048)
      .optional()
      .describe(
        "Web URL or bare domain. Matches logins whose saved URL host is this host or a parent domain of it.",
      ),
  })
  .strict();

const getLoginCredentialsInput = z
  .object({
    itemId: z.string().trim().min(1).max(256).optional().describe("ID of the login item."),
    itemTitle: z
      .string()
      .trim()
      .min(1)
      .max(255)
      .optional()
      .describe("Title of the login item (case-insensitive exact match)."),
    url: z
      .string()
      .trim()
      .min(1)
      .max(2048)
      .optional()
      .describe("Sign-in page URL or bare domain, matched against saved login URLs."),
  })
  .strict()
  .superRefine((value, context) => {
    const selectors = [value.itemId, value.itemTitle, value.url].filter(
      (selector) => selector !== undefined,
    );
    if (selectors.length !== 1) {
      context.addIssue({
        code: "custom",
        message: "Provide exactly one of itemId, itemTitle, or url.",
        path: ["itemId"],
      });
    }
  });

const aliasOutput = {
  created: z.boolean(),
  alias: z.string().nullable(),
  prefix: z.string(),
  warning: z.string().optional(),
};

const loginOutput = {
  created: z.boolean(),
  title: z.string(),
  passwordGenerated: z.boolean(),
  passwordLength: z.number(),
};

const searchAliasesOutput = {
  query: z.string(),
  page: z.number(),
  aliases: z.array(
    z.object({
      alias: z.string(),
      name: z.string().nullable(),
      enabled: z.boolean(),
    }),
  ),
};

const aliasContactOutput = {
  created: z.boolean(),
  existed: z.boolean(),
  alias: z.string(),
  contact: z.string(),
  reverseAlias: z.string(),
};

const totpOutput = {
  codes: z.array(
    z.object({
      code: z.string(),
      name: z.string().optional(),
    }),
  ),
  itemId: z.string().optional(),
  itemTitle: z.string().optional(),
  field: z.string().optional(),
};

const loginSummaryOutput = z.object({
  id: z.string(),
  title: z.string(),
  hasUsername: z.boolean(),
  hasEmail: z.boolean(),
  urls: z.array(z.string()),
});

const findLoginsOutput = {
  logins: z.array(loginSummaryOutput),
};

const loginCredentialsOutput = {
  id: z.string(),
  title: z.string(),
  username: z.string().nullable(),
  email: z.string().nullable(),
  password: z.string(),
  urls: z.array(z.string()),
};

function toolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

export function parseServerArgs(args) {
  const { values } = parseArgs({
    args,
    allowPositionals: false,
    strict: true,
    options: {
      "vault-name": { type: "string" },
      "share-id": { type: "string" },
    },
  });

  return normalizeVaultSelector({
    vaultName: values["vault-name"],
    shareId: values["share-id"],
  });
}

export function createServer({
  vaultSelector,
  commandOptions = {},
  credentialOptions = {},
  simpleLoginOptions = {},
} = {}) {
  const normalizedVaultSelector = normalizeVaultSelector(vaultSelector);
  const vaultLock = new VaultLock(normalizedVaultSelector);
  const credentialCommandOptions = { ...commandOptions, ...credentialOptions };
  // Every Proton Pass tool uses the share ID the credential tools are locked to, so a
  // configured --vault-name is resolved once (and refused if ambiguous) instead of being
  // re-resolved by each CLI command.
  const lockedVault = async () => ({ shareId: await vaultLock.shareId(credentialCommandOptions) });
  const server = new McpServer(
    {
      name: "protonpass-cli-mcp",
      version: "0.5.0",
    },
    {
      instructions:
        "The Proton Pass CLI tools are restricted to one vault selected by its operator. Use search_aliases to find account-wide SimpleLogin aliases, create_alias for a new hide-my-email address, get_or_create_alias_contact to get or create an account-wide SimpleLogin reverse alias for an existing alias and contact, create_login for a new login whose password is generated inside Proton Pass, get_totp to retrieve current one-time codes without revealing their underlying secrets, find_logins to list sign-in metadata without secrets, and get_login_credentials to reveal a username, email, and password for one login. Credentials only ever come from the operator-configured vault; no tool input can select another vault. Every credential reveal is rate limited, audited, and requires approval. Use a revealed password only by typing it into the matching sign-in form; never repeat, summarize, or echo it to the user or into the transcript. Never ask for or expose a generated password, TOTP secret, or SimpleLogin API key.",
    },
  );

  server.registerTool(
    "search_aliases",
    {
      title: "Search aliases",
      description:
        "Search account-wide SimpleLogin aliases by text. Returns at most 20 aliases per zero-based page, including each alias address, display name, and enabled state.",
      inputSchema: searchAliasesInput,
      outputSchema: searchAliasesOutput,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await searchAliases(input, simpleLoginOptions)),
  );

  server.registerTool(
    "get_or_create_alias_contact",
    {
      title: "Get or create alias contact",
      description:
        "Get or create a SimpleLogin contact for an existing hide-my-email alias and return the reverse-alias address used to send mail to that contact. This uses account-wide SimpleLogin access rather than the configured Proton Pass vault. An existing contact is returned without duplication and reports existed=true.",
      inputSchema: getOrCreateAliasContactInput,
      outputSchema: aliasContactOutput,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await getOrCreateAliasContact(input, simpleLoginOptions)),
  );

  server.registerTool(
    "create_alias",
    {
      title: "Create Proton Pass alias",
      description:
        "Create a new Proton Pass hide-my-email alias. Returns the generated alias address. This adds a vault item and is not idempotent.",
      inputSchema: createAliasInput,
      outputSchema: aliasOutput,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await createAlias(input, await lockedVault(), commandOptions)),
  );

  server.registerTool(
    "create_login",
    {
      title: "Create Proton Pass login",
      description:
        "Create a new Proton Pass login item with a password generated and stored internally by Proton Pass. The password is never returned by this tool. This adds a vault item and is not idempotent.",
      inputSchema: createLoginInput,
      outputSchema: loginOutput,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await createLogin(input, await lockedVault(), commandOptions)),
  );

  server.registerTool(
    "get_totp",
    {
      title: "Get Proton Pass TOTP",
      description:
        "Get the current TOTP code or codes for a Proton Pass login item in the configured vault. Returns one-time codes but never the underlying TOTP secret. Select the item with exactly one of itemId or itemTitle.",
      inputSchema: getTotpInput,
      outputSchema: totpOutput,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await getTotp(input, await lockedVault(), commandOptions)),
  );

  server.registerTool(
    "find_logins",
    {
      title: "Find Proton Pass logins",
      description:
        "List logins in the configured vault without revealing any secret. Optionally filter by title substring (query) and/or by a web URL or domain (url), which matches saved URLs on the same host or a parent domain. Returns id, title, urls, and whether a username or email is saved.",
      inputSchema: findLoginsInput,
      outputSchema: findLoginsOutput,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await findLogins(input, vaultLock, credentialCommandOptions)),
  );

  // Revealing a password does not modify the vault, but it is marked destructive (and
  // not read-only or idempotent) on purpose: MCP clients such as Executor require human
  // approval for tools that are not read-only, so the owner approves every reveal.
  server.registerTool(
    "get_login_credentials",
    {
      title: "Get Proton Pass login credentials",
      description:
        "Reveal the username, email, password, and URLs of one login in the configured vault so it can be typed into that site's sign-in form. Select it with exactly one of itemId, itemTitle, or url; a url must match exactly one saved login. Notes, TOTP secrets, passkeys, and custom fields are never returned. Every reveal requires approval, is audited, and is rate limited. Never repeat the password to the user or in the transcript.",
      inputSchema: getLoginCredentialsInput,
      outputSchema: loginCredentialsOutput,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (input) =>
      toolResult(await getLoginCredentials(input, vaultLock, credentialCommandOptions)),
  );

  return server;
}

export async function main(args = process.argv.slice(2)) {
  loadEnv({
    path: resolve(dirname(fileURLToPath(import.meta.url)), "../.env"),
    quiet: true,
  });

  const server = createServer({ vaultSelector: parseServerArgs(args) });
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

export function isEntrypoint(moduleUrl, argvPath) {
  if (!argvPath) return false;

  try {
    return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argvPath);
  } catch {
    return false;
  }
}

if (isEntrypoint(import.meta.url, process.argv[1])) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
