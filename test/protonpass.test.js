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
  generatePasswordSettings,
  getTotp,
  normalizeLoginUrl,
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
    "--generate-password=32,symbols",
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

/**
 * Mirrors `generate_custom_password` in pass-cli 2.4.2
 * (pass-cli/src/commands/item/create/login.rs): after the length, every comma-separated
 * part must be the name of an option to enable, or the command fails after login.
 */
function passCli242PasswordSettings(settings) {
  const [length, ...options] = settings.split(",");
  if (!/^\d+$/.test(length)) throw new Error(`Invalid length: ${length}`);

  const config = { length: Number(length), numbers: true, uppercase: false, symbols: false };
  for (const option of options) {
    const name = option.trim().toLowerCase();
    if (name !== "uppercase" && name !== "symbols") {
      throw new Error(`Unknown password option: ${option}`);
    }
    config[name] = true;
  }
  return config;
}

function passCli242Runner(calls) {
  return async (args, options) => {
    calls.push({ args, reason: options.env?.PROTON_PASS_AGENT_REASON });
    const flag = args.find((value) => value.startsWith("--generate-password="));
    try {
      passCli242PasswordSettings(flag.slice("--generate-password=".length));
    } catch (error) {
      throw new ProtonPassCliError(`Proton Pass CLI failed (exit 1): Error: ${error.message}`);
    }
    return { stdout: "item-123", stderr: "" };
  };
}

test("the previous positional boolean settings reproduce the live create_login failure", async () => {
  assert.throws(() => passCli242PasswordSettings("24,true,true"), /Unknown password option: true/);

  const legacyRunner = passCli242Runner([]);
  await assert.rejects(
    legacyRunner(
      [
        "item",
        "create",
        "login",
        "--share-id",
        "s",
        "--title",
        "BEL USA UltiPro",
        "--generate-password=24,true,true",
      ],
      {},
    ),
    { message: "Proton Pass CLI failed (exit 1): Error: Unknown password option: true" },
  );
});

test("createLogin password settings are accepted by pass-cli 2.4.2 for every option combination", async () => {
  for (const includeUppercase of [true, false]) {
    for (const includeSymbols of [true, false]) {
      const calls = [];
      const result = await createLogin(
        {
          title: "BEL USA UltiPro",
          email: "bel.ultipro.tribesman749@passmail.com",
          passwordLength: 32,
          includeUppercase,
          includeSymbols,
        },
        { shareId: "agent-share" },
        { runner: passCli242Runner(calls), env: {} },
      );

      assert.equal(result.created, true);
      const flag = calls[0].args.find((value) => value.startsWith("--generate-password="));
      assert.deepEqual(passCli242PasswordSettings(flag.slice("--generate-password=".length)), {
        length: 32,
        numbers: true,
        uppercase: includeUppercase,
        symbols: includeSymbols,
      });
    }
  }

  assert.equal(
    generatePasswordSettings({ length: 24, uppercase: true, symbols: true }),
    "24,uppercase,symbols",
  );
  assert.equal(generatePasswordSettings({ length: 12, uppercase: false, symbols: false }), "12");
});

test("createLogin normalizes bare hosts and sets a fixed agent reason", async () => {
  const calls = [];
  await createLogin(
    {
      title: "CAI\nWorkday",
      email: "cai.workday.repugnant179@passmail.com",
      urls: ["cai.wd5.myworkdayjobs.com", " https://example.org/login "],
    },
    { shareId: "agent-share" },
    { runner: passCli242Runner(calls), env: {} },
  );

  assert.deepEqual(calls[0].args, [
    "item",
    "create",
    "login",
    "--share-id",
    "agent-share",
    "--title",
    "CAI\nWorkday",
    "--email",
    "cai.workday.repugnant179@passmail.com",
    "--url",
    "https://cai.wd5.myworkdayjobs.com",
    "--url",
    "https://example.org/login",
    "--generate-password=24,uppercase,symbols",
  ]);
  assert.equal(calls[0].reason, "protonpass-mcp create login CAI Workday");

  await assert.rejects(
    createLogin(
      { title: "Bad", email: "a@b.co", urls: ["javascript:alert(1)"] },
      { shareId: "s" },
      { runner: passCli242Runner([]) },
    ),
    { name: "ProtonPassCliError", message: "Each login URL must be a web URL or domain." },
  );
});

test("normalizeLoginUrl accepts web URLs and bare hosts only", () => {
  assert.equal(normalizeLoginUrl("cai.wd5.myworkdayjobs.com"), "https://cai.wd5.myworkdayjobs.com");
  assert.equal(normalizeLoginUrl("example.com/login?x=1"), "https://example.com/login?x=1");
  assert.equal(normalizeLoginUrl("http://localhost:3000"), "http://localhost:3000");
  assert.equal(normalizeLoginUrl("HTTPS://Example.com"), "HTTPS://Example.com");
  for (const value of [
    "",
    "  ",
    "javascript:alert(1)",
    "ftp://example.com",
    "mailto:a@b.co",
    "https://user:pass@example.com",
    "https://",
  ]) {
    assert.equal(normalizeLoginUrl(value), undefined, value);
  }
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
