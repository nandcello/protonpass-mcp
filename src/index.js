#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { createAlias, createLogin, getTotp } from "./protonpass.js";

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
  vaultName: z.string().optional(),
  shareId: z.string().optional(),
  warning: z.string().optional(),
};

const loginOutput = {
  created: z.boolean(),
  title: z.string(),
  passwordGenerated: z.boolean(),
  passwordLength: z.number(),
  vaultName: z.string().optional(),
  shareId: z.string().optional(),
};

const totpOutput = {
  codes: z.array(
    z.object({
      code: z.string(),
      name: z.string().optional(),
    }),
  ),
  uri: z.string().optional(),
  itemId: z.string().optional(),
  itemTitle: z.string().optional(),
  field: z.string().optional(),
  vaultName: z.string().optional(),
  shareId: z.string().optional(),
};

function toolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

export function normalizeVaultSelector({ vaultName, shareId } = {}) {
  const normalizedVaultName = vaultName?.trim();
  const normalizedShareId = shareId?.trim();

  if (Boolean(normalizedVaultName) === Boolean(normalizedShareId)) {
    throw new Error("Provide exactly one of --vault-name or --share-id.");
  }

  return normalizedShareId
    ? Object.freeze({ shareId: normalizedShareId })
    : Object.freeze({ vaultName: normalizedVaultName });
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

export function createServer(options = {}) {
  const vaultSelector = normalizeVaultSelector(options);
  const server = new McpServer(
    {
      name: "protonpass-cli-mcp",
      version: "0.3.0",
    },
    {
      instructions:
        "This server is restricted to one vault selected by its operator. Use create_alias for a new hide-my-email address, create_login for a new login whose password is generated inside Proton Pass, and get_totp to retrieve current one-time codes without revealing their underlying secrets. The create tools add vault items and are not idempotent. Never ask for or expose a generated password or TOTP secret.",
    },
  );

  const commandOptions = options.commandOptions ?? {};
  const scopedInput = (input) => ({ ...input, ...vaultSelector });

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
    async (input) => toolResult(await createAlias(scopedInput(input), commandOptions)),
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
    async (input) => toolResult(await createLogin(scopedInput(input), commandOptions)),
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
    async (input) => toolResult(await getTotp(scopedInput(input), commandOptions)),
  );

  return server;
}

export async function main(args = process.argv.slice(2)) {
  const server = createServer(parseServerArgs(args));
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
