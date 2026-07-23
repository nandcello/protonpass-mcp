import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { onTestFinished, test } from "vite-plus/test";
import { createServer, isEntrypoint, parseServerArgs } from "../src/index.js";
import { normalizeVaultSelector } from "../src/protonpass.js";

test("MCP client can list, validate, and call all tools", async () => {
  const calls = [];
  const simpleLoginCalls = [];
  const runner = async (args) => {
    calls.push(args);
    if (args.includes("alias")) {
      return {
        stdout: JSON.stringify({
          id: "item-123",
          alias: "github-alias@example.com",
        }),
        stderr: "",
      };
    }
    if (args.includes("totp")) {
      return {
        stdout: JSON.stringify({
          Authenticator: "012345",
        }),
        stderr: "",
      };
    }
    return { stdout: "Created item", stderr: "" };
  };
  const fetchImpl = async (url, init) => {
    simpleLoginCalls.push({ url: String(url), init });
    if (new URL(url).pathname === "/api/v2/aliases") {
      return new Response(
        JSON.stringify({
          aliases: [
            {
              id: 42,
              email: "github-alias@example.com",
              name: "GitHub",
              enabled: true,
            },
          ],
        }),
      );
    }

    return new Response(
      JSON.stringify({
        contact: "support@example.org",
        reverse_alias_address: "reply+github-support@example.net",
        existed: false,
      }),
      { status: 201 },
    );
  };

  const server = createServer({
    vaultSelector: { shareId: "vault-share-123" },
    commandOptions: { runner },
    simpleLoginOptions: { apiKey: "test-api-key", fetchImpl },
  });
  const client = new Client(
    { name: "protonpass-mcp-test", version: "0.2.0" },
    { capabilities: {} },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  onTestFinished(async () => {
    await client.close();
    await server.close();
  });

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map((tool) => tool.name).sort(), [
    "create_alias",
    "create_login",
    "get_or_create_alias_contact",
    "get_totp",
    "search_aliases",
  ]);

  const aliasSearch = await client.callTool({
    name: "search_aliases",
    arguments: { query: "github" },
  });
  assert.equal(aliasSearch.isError, undefined);
  assert.deepEqual(aliasSearch.structuredContent, {
    query: "github",
    page: 0,
    aliases: [
      {
        alias: "github-alias@example.com",
        name: "GitHub",
        enabled: true,
      },
    ],
  });

  const alias = await client.callTool({
    name: "create_alias",
    arguments: { prefix: "github" },
  });
  assert.equal(alias.isError, undefined);
  assert.deepEqual(alias.structuredContent, {
    created: true,
    alias: "github-alias@example.com",
    prefix: "github",
  });

  const aliasContact = await client.callTool({
    name: "get_or_create_alias_contact",
    arguments: {
      alias: "github-alias@example.com",
      contact: "support@example.org",
    },
  });
  assert.equal(aliasContact.isError, undefined);
  assert.deepEqual(aliasContact.structuredContent, {
    created: true,
    existed: false,
    alias: "github-alias@example.com",
    contact: "support@example.org",
    reverseAlias: "reply+github-support@example.net",
  });

  const login = await client.callTool({
    name: "create_login",
    arguments: {
      title: "GitHub",
      email: "github-alias@example.com",
      urls: ["https://github.com"],
    },
  });
  assert.equal(login.isError, undefined);
  assert.deepEqual(login.structuredContent, {
    created: true,
    title: "GitHub",
    passwordGenerated: true,
    passwordLength: 24,
  });

  const totp = await client.callTool({
    name: "get_totp",
    arguments: {
      itemTitle: "GitHub",
    },
  });
  assert.equal(totp.isError, undefined);
  assert.deepEqual(totp.structuredContent, {
    codes: [{ name: "Authenticator", code: "012345" }],
    itemTitle: "GitHub",
  });

  const invalidLogin = await client.callTool({
    name: "create_login",
    arguments: { title: "Missing identity" },
  });
  assert.equal(invalidLogin.isError, true);

  const invalidTotp = await client.callTool({
    name: "get_totp",
    arguments: { itemId: "item-123", itemTitle: "Duplicate selector" },
  });
  assert.equal(invalidTotp.isError, true);

  assert.equal(calls.length, 3);
  assert.equal(simpleLoginCalls.length, 3);
  assert.equal(simpleLoginCalls[0].init.headers.Authentication, "test-api-key");
  assert.deepEqual(JSON.parse(simpleLoginCalls[0].init.body), {
    query: "github",
  });
  assert.deepEqual(JSON.parse(simpleLoginCalls[1].init.body), {
    query: "github-alias@example.com",
  });
  assert.deepEqual(JSON.parse(simpleLoginCalls[2].init.body), {
    contact: "support@example.org",
  });
  assert.equal(
    calls[1].some((value) => value === "--password"),
    false,
  );
  for (const args of calls) {
    const selectorIndex = args.indexOf("--share-id");
    assert.notEqual(selectorIndex, -1);
    assert.equal(args[selectorIndex + 1], "vault-share-123");
  }
});

test("MCP tools cannot override the configured vault or use a Pass URI", async () => {
  const calls = [];
  const simpleLoginCalls = [];
  const server = createServer({
    vaultSelector: { vaultName: "Personal" },
    commandOptions: {
      runner: async (args) => {
        calls.push(args);
        return { stdout: JSON.stringify({ Authenticator: "012345" }), stderr: "" };
      },
    },
    simpleLoginOptions: {
      apiKey: "configured-key",
      fetchImpl: async (...args) => {
        simpleLoginCalls.push(args);
        return new Response("{}");
      },
    },
  });
  const client = new Client(
    { name: "protonpass-mcp-scope-test", version: "0.2.0" },
    { capabilities: {} },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  onTestFinished(async () => {
    await client.close();
    await server.close();
  });

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const vaultOverride = await client.callTool({
    name: "get_totp",
    arguments: { itemTitle: "GitHub", shareId: "other-vault" },
  });
  const uriBypass = await client.callTool({
    name: "get_totp",
    arguments: { uri: "pass://other-vault/item-123" },
  });
  const apiOverride = await client.callTool({
    name: "get_or_create_alias_contact",
    arguments: {
      alias: "alias@example.com",
      contact: "contact@example.org",
      apiKey: "other-key",
    },
  });
  const baseUrlOverride = await client.callTool({
    name: "get_or_create_alias_contact",
    arguments: {
      alias: "alias@example.com",
      contact: "contact@example.org",
      baseUrl: "https://attacker.example",
    },
  });

  assert.equal(vaultOverride.isError, true);
  assert.equal(uriBypass.isError, true);
  assert.equal(apiOverride.isError, true);
  assert.equal(baseUrlOverride.isError, true);
  assert.deepEqual(calls, []);
  assert.deepEqual(simpleLoginCalls, []);
});

test("server startup requires exactly one non-empty vault selector", () => {
  assert.deepEqual(parseServerArgs(["--share-id", " vault-share-123 "]), {
    shareId: "vault-share-123",
  });
  assert.deepEqual(parseServerArgs(["--vault-name", " Personal "]), {
    vaultName: "Personal",
  });

  for (const options of [
    undefined,
    {},
    { shareId: " " },
    { vaultName: "Personal", shareId: "vault-share-123" },
  ]) {
    assert.throws(() => normalizeVaultSelector(options), /exactly one/);
  }

  assert.throws(() => parseServerArgs([]), /exactly one/);
  assert.throws(
    () => parseServerArgs(["--vault-name", "Personal", "--share-id", "vault-share-123"]),
    /exactly one/,
  );
});

test("isEntrypoint compares decoded real filesystem paths", () => {
  const indexUrl = new URL("../src/index.js", import.meta.url);
  assert.equal(isEntrypoint(indexUrl, fileURLToPath(indexUrl)), true);
  assert.equal(isEntrypoint(indexUrl, undefined), false);

  const directory = mkdtempSync(join(tmpdir(), "protonpass entrypoint "));
  const entrypoint = join(directory, "entry point.js");
  writeFileSync(entrypoint, "");

  try {
    assert.equal(isEntrypoint(pathToFileURL(entrypoint), entrypoint), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
