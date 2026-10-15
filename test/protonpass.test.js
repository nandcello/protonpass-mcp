import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import {
  ProtonPassCliError,
  buildCreateAliasArgs,
  buildCreateLoginArgs,
  buildGetTotpArgs,
  createAlias,
  createLogin,
  failureReason,
  getTotp,
  parseAliasAddress,
  parseTotpCodes,
  runPassCli,
} from "../src/protonpass.js";

test("buildCreateAliasArgs uses JSON output and a vault name", () => {
  assert.deepEqual(buildCreateAliasArgs({ prefix: "github" }, { vaultName: "Personal" }), [
    "item",
    "alias",
    "create",
    "--vault-name",
    "Personal",
    "--prefix",
    "github",
    "--output",
    "json",
  ]);
});

test("buildCreateLoginArgs generates the password inside Proton Pass", () => {
  const args = buildCreateLoginArgs(
    {
      title: "GitHub",
      email: "github-alias@example.com",
      urls: ["https://github.com"],
      passwordLength: 32,
      includeUppercase: false,
      includeSymbols: true,
    },
    { shareId: "share-123" },
  );

  assert.deepEqual(args, [
    "item",
    "create",
    "login",
    "--share-id",
    "share-123",
    "--title",
    "GitHub",
    "--email",
    "github-alias@example.com",
    "--url",
    "https://github.com",
    "--generate-password=32,false,true",
  ]);
  assert.equal(args.includes("--password"), false);
});

test("buildGetTotpArgs selects an item title and requests JSON", () => {
  assert.deepEqual(
    buildGetTotpArgs(
      {
        itemTitle: "GitHub",
        field: "Authenticator",
      },
      { vaultName: "Personal" },
    ),
    [
      "item",
      "totp",
      "--vault-name",
      "Personal",
      "--item-title",
      "GitHub",
      "--field",
      "Authenticator",
      "--output",
      "json",
    ],
  );
});

test("command builders require a vault and getTotp rejects Pass URIs", () => {
  assert.throws(() => buildCreateAliasArgs({ prefix: "github" }), /exactly one/);
  assert.throws(
    () => buildGetTotpArgs({ uri: "pass://other-vault/item-456" }, { shareId: "configured-vault" }),
    /exactly one of itemId or itemTitle/,
  );
});

test("parseAliasAddress accepts only the documented alias field", () => {
  assert.equal(
    parseAliasAddress(
      JSON.stringify({
        id: "item-123",
        alias: "github-alias@example.com",
      }),
    ),
    "github-alias@example.com",
  );
  assert.equal(
    parseAliasAddress(
      JSON.stringify({
        mailbox: "private@example.com",
        item: { content: { aliasEmail: "nested@example.com" } },
      }),
    ),
    undefined,
  );
  assert.equal(parseAliasAddress("private@example.com"), undefined);
});

test("createAlias returns only the generated alias metadata", async () => {
  let receivedArgs;
  const result = await createAlias(
    { prefix: "example" },
    { shareId: "share-123" },
    {
      runner: async (args) => {
        receivedArgs = args;
        return {
          stdout: JSON.stringify({
            id: "item-123",
            alias: "generated-alias@example.com",
            mailbox: "private@example.com",
          }),
          stderr: "",
        };
      },
    },
  );

  assert.equal(receivedArgs.at(-1), "json");
  assert.deepEqual(result, {
    created: true,
    alias: "generated-alias@example.com",
    prefix: "example",
  });
  assert.equal(JSON.stringify(result).includes("private@example.com"), false);
});

test("createAlias warns without inferring an address from unknown output", async () => {
  const result = await createAlias(
    { prefix: "example" },
    { shareId: "share-123" },
    {
      runner: async () => ({
        stdout: JSON.stringify({ mailbox: "private@example.com" }),
        stderr: "",
      }),
    },
  );

  assert.deepEqual(result, {
    created: true,
    alias: null,
    prefix: "example",
    warning: "The alias was created, but its address could not be parsed from the CLI response.",
  });
});

test("createLogin never returns a generated password", async () => {
  let receivedArgs;
  const result = await createLogin(
    {
      title: "Example",
      username: "example-user",
      passwordLength: 24,
    },
    { shareId: "share-123" },
    {
      runner: async (args) => {
        receivedArgs = args;
        return { stdout: "Created item", stderr: "" };
      },
    },
  );

  assert.equal(
    receivedArgs.some((value) => value.startsWith("--password=")),
    false,
  );
  assert.equal(
    receivedArgs.some((value) => value.startsWith("--generate-password=")),
    true,
  );
  assert.deepEqual(result, {
    created: true,
    title: "Example",
    passwordGenerated: true,
    passwordLength: 24,
  });
});

test("parseTotpCodes preserves names from Proton Pass JSON output", () => {
  assert.deepEqual(
    parseTotpCodes(
      JSON.stringify({
        Authenticator: "012345",
        Backup: "987654",
      }),
    ),
    [
      { name: "Authenticator", code: "012345" },
      { name: "Backup", code: "987654" },
    ],
  );
});

test("parseTotpCodes rejects unknown and metadata-only response shapes", () => {
  for (const response of [
    [],
    { metadata: { type: "totp", status: "active" } },
    { type: "totp", status: "active" },
    { Authenticator: "not-a-code" },
  ]) {
    assert.throws(() => parseTotpCodes(JSON.stringify(response)), ProtonPassCliError);
  }
});

test("parseTotpCodes does not retain malformed private output", () => {
  assert.throws(
    () => parseTotpCodes("private@example.com is not JSON"),
    (error) => {
      assert.ok(error instanceof ProtonPassCliError);
      assert.equal(error.message, "Could not parse the Proton Pass CLI TOTP response.");
      assert.equal(error.message.includes("private@example.com"), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("getTotp returns only named codes", async () => {
  let receivedArgs;
  const result = await getTotp(
    { itemId: "item-456" },
    { shareId: "share-123" },
    {
      runner: async (args) => {
        receivedArgs = args;
        return {
          stdout: JSON.stringify({
            Authenticator: "012345",
          }),
          stderr: "",
        };
      },
    },
  );

  assert.equal(receivedArgs.at(-1), "json");
  assert.deepEqual(result, {
    codes: [{ name: "Authenticator", code: "012345" }],
    itemId: "item-456",
  });
});

test("runPassCli reports a missing executable without leaking internals", async () => {
  await assert.rejects(
    runPassCli([], {
      cliPath: "/private/location/protonpass-cli-command-that-does-not-exist",
      env: {},
    }),
    (error) => {
      assert.ok(error instanceof ProtonPassCliError);
      assert.equal(
        error.message,
        "Could not find Proton Pass CLI. Install it or set PROTONPASS_CLI_PATH.",
      );
      assert.equal(error.message.includes("/private/location"), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("runPassCli reports the exit code and a redacted stderr line, never stdout", async () => {
  await assert.rejects(
    runPassCli(
      [
        "-e",
        'process.stdout.write("stdout-secret-password"); process.stderr.write("Error: vault-private rejected private@example.com pst_abc::def"); process.exit(2)',
      ],
      { cliPath: process.execPath },
    ),
    (error) => {
      assert.ok(error instanceof ProtonPassCliError);
      assert.equal(
        error.message,
        "Proton Pass CLI failed (exit 2): Error: vault-private rejected [email] [redacted]",
      );
      assert.equal(error.message.includes("stdout-secret-password"), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("runPassCli falls back to a session hint when stderr is empty", async () => {
  await assert.rejects(
    runPassCli(["-e", 'process.stdout.write("stdout only"); process.exit(1)'], {
      cliPath: process.execPath,
    }),
    {
      name: "ProtonPassCliError",
      message:
        "Proton Pass CLI failed (exit 1). Run `pass-cli info` to check the authenticated session.",
    },
  );
});

test("failureReason prefers the Error line over pass-cli tracing output", () => {
  const stderr = [
    "\u001b[2m2026-10-15T14:50:57.972255Z\u001b[0m \u001b[31mERROR\u001b[0m \u001b[2mpass-cli/src/main.rs\u001b[0m\u001b[2m:\u001b[0m\u001b[2m335:\u001b[0m Command is not logout there is no session",
    "Error: This operation requires an authenticated client",
    "",
  ].join("\n");
  assert.equal(failureReason(stderr), "Error: This operation requires an authenticated client");
  assert.equal(
    failureReason("2026-10-15T14:50:57Z ERROR pass/src/item/create.rs:88: Failed to create item\n"),
    "Failed to create item",
  );
  assert.equal(failureReason(`Error: ${"word ".repeat(100)}`).length, 200);
  assert.equal(failureReason(`Error: token ${"A1b2".repeat(10)}`), "Error: token [redacted]");
  assert.equal(failureReason("Error: bad\u0007bell\u202eltr"), "Error: bad bell ltr");
  assert.equal(failureReason(""), undefined);
  assert.equal(failureReason(undefined), undefined);
});

test("runPassCli reports command timeouts", async () => {
  await assert.rejects(
    runPassCli(["-e", "setInterval(() => {}, 1_000)"], {
      cliPath: process.execPath,
      timeoutMs: 50,
    }),
    (error) => {
      assert.ok(error instanceof ProtonPassCliError);
      assert.equal(error.message, "Proton Pass CLI timed out after 50 ms.");
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});
