#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config as loadEnv } from "dotenv";
import * as z from "zod/v4";
import { createAlias, createLogin, getTotp, normalizeVaultSelector } from "./protonpass.js";
import { createAliasContact } from "./simplelogin.js";

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
      .array(z.url())
      .max(20)
      .optional()
      .describe("One or more website URLs associated with this login."),
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

const createAliasContactInput = z
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

export function createServer({ vaultSelector, commandOptions = {}, simpleLoginOptions = {} } = {}) {
  const normalizedVaultSelector = normalizeVaultSelector(vaultSelector);
  const server = new McpServer(
    {
      name: "protonpass-cli-mcp",
      version: "0.4.0",
    },
    {
      instructions:
        "The Proton Pass CLI tools are restricted to one vault selected by its operator. Use create_alias for a new hide-my-email address, create_alias_contact to create an account-wide SimpleLogin reverse alias for an existing alias and contact, create_login for a new login whose password is generated inside Proton Pass, and get_totp to retrieve current one-time codes without revealing their underlying secrets. Never ask for or expose a generated password, TOTP secret, or SimpleLogin API key.",
    },
  );

  server.registerTool(
    "create_alias_contact",
    {
      title: "Create alias contact",
      description:
        "Create a SimpleLogin contact for an existing hide-my-email alias and return the reverse-alias address used to send mail to that contact. This uses account-wide SimpleLogin access rather than the configured Proton Pass vault. Repeating the same alias and contact is safe and reports existed=true.",
      inputSchema: createAliasContactInput,
      outputSchema: aliasContactOutput,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (input) => toolResult(await createAliasContact(input, simpleLoginOptions)),
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
    async (input) => toolResult(await createAlias(input, normalizedVaultSelector, commandOptions)),
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
    async (input) => toolResult(await createLogin(input, normalizedVaultSelector, commandOptions)),
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
    async (input) => toolResult(await getTotp(input, normalizedVaultSelector, commandOptions)),
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
