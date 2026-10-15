import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { onTestFinished, test } from "vite-plus/test";
import {
  AuditLogError,
  CredentialRefusal,
  RevealRateLimiter,
  VaultLock,
  agentReason,
  findLogins,
  getLoginCredentials,
  hostMatches,
  hostOf,
  parseItemList,
  parseLoginView,
} from "../src/credentials.js";

const AGENT_SHARE = "share-agent";
const OTHER_SHARE = "share-personal";
const SECRETS = [
  "hunter2-password",
  "NOTE-SECRET",
  "TOTPSECRETBASE32",
  "EXTRA-FIELD-SECRET",
  "PASSKEY-SECRET",
  "attachment-secret.pdf",
  "HISTORY-SECRET",
];

function viewItem({
  id,
  title,
  shareId = AGENT_SHARE,
  urls = [],
  username = "",
  email = "",
  password = "hunter2-password",
}) {
  return {
    item: {
      id,
      ...(shareId === null ? {} : { share_id: shareId }),
      vault_id: "vault-1",
      content: {
        title,
        note: "NOTE-SECRET",
        item_uuid: "uuid-1",
        content: {
          Login: {
            email,
            username,
            password,
            urls,
            totp_uri: "otpauth://totp/x?secret=TOTPSECRETBASE32",
            passkeys: [{ key_id: "k", content: "PASSKEY-SECRET" }],
          },
        },
        extra_fields: [{ name: "pin", content: { Hidden: "EXTRA-FIELD-SECRET" } }],
      },
      state: "Active",
      password_history: ["HISTORY-SECRET"],
    },
    attachments: [{ name: "attachment-secret.pdf" }],
  };
}

const defaultItems = [
  viewItem({
    id: "kalibrr",
    title: "Kalibrr",
    urls: ["https://www.kalibrr.com/login"],
    email: "agent-kalibrr@example.com",
  }),
  viewItem({
    id: "github",
    title: "GitHub",
    urls: ["https://github.com"],
    username: "agent-gh",
    password: "gh-password",
  }),
];

function fakeCli({
  vaults = [
    { name: "AGENT", vault_id: "v-agent", share_id: AGENT_SHARE },
    { name: "Personal", vault_id: "v-personal", share_id: OTHER_SHARE },
  ],
  items = defaultItems,
  extraListRows = [],
  viewOverride,
} = {}) {
  const calls = [];
  const runner = async (args, options) => {
    calls.push({ args, reason: options.env?.PROTON_PASS_AGENT_REASON });
    if (args[0] === "vault") return { stdout: JSON.stringify({ vaults }), stderr: "" };

    const shareId = args[args.indexOf("--share-id") + 1];
    if (args[1] === "list") {
      const rows = items
        .filter((entry) => entry.item.share_id === shareId)
        .map(({ item }) => ({
          id: item.id,
          share_id: item.share_id,
          title: item.content.title,
          item_type: "login",
        }));
      return { stdout: JSON.stringify({ items: [...rows, ...extraListRows] }), stderr: "" };
    }

    const itemId = args[args.indexOf("--item-id") + 1];
    const found = viewOverride?.(itemId) ?? items.find((entry) => entry.item.id === itemId);
    if (!found) throw new Error("not found");
    return { stdout: JSON.stringify(found), stderr: "" };
  };
  return { calls, runner };
}

function tempDir() {
  const directory = mkdtempSync(join(tmpdir(), "protonpass-credentials-"));
  onTestFinished(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function setup({ cli = fakeCli(), env = {}, vault = { vaultName: "AGENT" }, now } = {}) {
  const directory = tempDir();
  const auditLogPath = join(directory, "state", "audit.log");
  const options = {
    runner: cli.runner,
    env,
    auditLogPath,
    rateLimiter: new RevealRateLimiter(now ? { now } : {}),
    ...(now ? { now } : {}),
  };
  return { cli, options, auditLogPath, directory, lock: new VaultLock(vault) };
}

function auditEntries(path) {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

test("vault name resolves once to a single share ID used by every item command", async () => {
  const { cli, options, lock } = setup();

  await findLogins({}, lock, options);
  await getLoginCredentials({ itemId: "github" }, lock, options);

  assert.equal(cli.calls.filter((call) => call.args[0] === "vault").length, 1);
  for (const { args } of cli.calls.filter((call) => call.args[0] === "item")) {
    assert.equal(args[args.indexOf("--share-id") + 1], AGENT_SHARE);
    assert.equal(args.includes("--vault-name"), false);
  }
});

test("an ambiguous or missing vault name is refused", async () => {
  const duplicate = setup({
    cli: fakeCli({
      vaults: [
        { name: "AGENT", share_id: "a" },
        { name: "AGENT", share_id: "b" },
      ],
    }),
  });
  await assert.rejects(findLogins({}, duplicate.lock, duplicate.options), {
    name: "CredentialRefusal",
    code: "vault_unresolved",
    message: /more than one vault/,
  });
  assert.equal(
    duplicate.cli.calls.some((call) => call.args[0] === "item"),
    false,
  );

  const missing = setup({ cli: fakeCli({ vaults: [{ name: "Personal", share_id: "p" }] }) });
  await assert.rejects(
    getLoginCredentials({ itemId: "github" }, missing.lock, missing.options),
    /configured vault was not found/,
  );
});

test("an item view from another share is refused and returns nothing", async () => {
  for (const shareId of [OTHER_SHARE, null]) {
    const cli = fakeCli({
      viewOverride: () => viewItem({ id: "github", title: "GitHub", shareId }),
    });
    const { options, lock, auditLogPath } = setup({ cli });

    const error = await getLoginCredentials({ itemId: "github" }, lock, options).catch((e) => e);
    assert.ok(error instanceof CredentialRefusal);
    assert.equal(error.code, "vault_mismatch");
    assert.equal(error.message.includes("hunter2-password"), false);
    assert.deepEqual(
      auditEntries(auditLogPath).map((entry) => [entry.outcome, entry.reason]),
      [["refused", "vault_mismatch"]],
    );
  }

  assert.throws(
    () => parseLoginView(JSON.stringify(viewItem({ id: "x", title: "X", shareId: "y" })), "z"),
    { code: "vault_mismatch" },
  );
});

test("item list rows from other shares are dropped and never viewed", async () => {
  const cli = fakeCli({
    extraListRows: [
      { id: "leak", share_id: OTHER_SHARE, title: "GitHub leak", item_type: "login" },
      { id: "no-share", title: "GitHub orphan", item_type: "login" },
    ],
  });
  const { options, lock } = setup({ cli });

  const { logins } = await findLogins({ query: "git" }, lock, options);
  assert.deepEqual(
    logins.map((login) => login.id),
    ["github"],
  );
  await assert.rejects(getLoginCredentials({ itemId: "leak" }, lock, options), {
    code: "no_match",
  });
  assert.equal(
    cli.calls.some((call) => call.args.includes("leak") || call.args.includes("no-share")),
    false,
  );
  assert.deepEqual(parseItemList(JSON.stringify([{ id: "a", share_id: "x" }]), "y"), []);
});

test("get_login_credentials returns only sign-in fields", async () => {
  const { options, lock } = setup();

  const result = await getLoginCredentials({ itemTitle: "kalibrr" }, lock, options);
  assert.deepEqual(result, {
    id: "kalibrr",
    title: "Kalibrr",
    username: null,
    email: "agent-kalibrr@example.com",
    password: "hunter2-password",
    urls: ["https://www.kalibrr.com/login"],
  });

  const serialized = JSON.stringify(result);
  for (const secret of SECRETS.filter((value) => value !== "hunter2-password")) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test("find_logins returns metadata without any secret", async () => {
  const { options, lock } = setup();

  const result = await findLogins({}, lock, options);
  assert.deepEqual(result.logins, [
    {
      id: "kalibrr",
      title: "Kalibrr",
      hasUsername: false,
      hasEmail: true,
      urls: ["https://www.kalibrr.com/login"],
    },
    {
      id: "github",
      title: "GitHub",
      hasUsername: true,
      hasEmail: false,
      urls: ["https://github.com"],
    },
  ]);

  const serialized = JSON.stringify(result);
  for (const secret of [...SECRETS, "gh-password", "agent-gh", "agent-kalibrr@example.com"]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test("find_logins uses list content when present instead of viewing items", async () => {
  const cli = fakeCli({ items: [] });
  cli.runner = async (args, options) => {
    cli.calls.push({ args, reason: options.env?.PROTON_PASS_AGENT_REASON });
    return {
      stdout: JSON.stringify({
        items: [
          {
            id: "row",
            share_id: AGENT_SHARE,
            content: { title: "Row", content: { Login: { username: "u", urls: ["a.example"] } } },
          },
        ],
      }),
      stderr: "",
    };
  };
  const { options, lock } = setup({ cli, vault: { shareId: AGENT_SHARE } });

  const { logins } = await findLogins({ url: "a.example" }, lock, options);
  assert.deepEqual(logins, [
    { id: "row", title: "Row", hasUsername: true, hasEmail: false, urls: ["a.example"] },
  ]);
  assert.equal(
    cli.calls.some((call) => call.args[1] === "view"),
    false,
  );
});

test("url selection matches hosts and subdomains and refuses zero or many matches", async () => {
  const items = [
    ...defaultItems,
    viewItem({ id: "ex-1", title: "Example one", urls: ["https://example.org"] }),
    viewItem({ id: "ex-2", title: "Example two", urls: ["example.org/login"] }),
  ];
  const { options, lock, auditLogPath } = setup({ cli: fakeCli({ items }) });

  for (const url of ["kalibrr.com", "https://www.kalibrr.com/jobs", "https://login.kalibrr.com"]) {
    const result = await getLoginCredentials({ url }, lock, options);
    assert.equal(result.id, "kalibrr", url);
  }

  for (const url of ["evilkalibrr.com", "https://kalibrr.com.evil.example", "nothing.test"]) {
    await assert.rejects(getLoginCredentials({ url }, lock, options), { code: "no_match" });
  }

  const ambiguous = await getLoginCredentials({ url: "https://www.example.org" }, lock, options)
    .then(() => assert.fail("expected refusal"))
    .catch((error) => error);
  assert.equal(ambiguous.code, "ambiguous_match");
  assert.match(ambiguous.message, /ex-1 \(Example one\), ex-2 \(Example two\)/);
  assert.equal(ambiguous.message.includes("hunter2-password"), false);

  await assert.rejects(getLoginCredentials({ url: "javascript:alert(1)" }, lock, options), {
    code: "invalid_url",
  });

  const refused = auditEntries(auditLogPath).find((entry) => entry.reason === "ambiguous_match");
  assert.equal(refused.host, "www.example.org");

  const { logins } = await findLogins({ url: "https://sub.github.com/x" }, lock, options);
  assert.deepEqual(
    logins.map((login) => login.id),
    ["github"],
  );
});

test("host helpers normalize URLs and bare domains", () => {
  assert.equal(hostOf("Kalibrr.COM."), "kalibrr.com");
  assert.equal(hostOf("https://a.b.example:8443/path?q"), "a.b.example");
  assert.equal(hostOf("ftp://example.com"), undefined);
  assert.equal(hostOf(""), undefined);
  assert.equal(hostMatches("https://www.kalibrr.com", "kalibrr.com"), true);
  assert.equal(hostMatches("kalibrr.com", "a.b.kalibrr.com"), true);
  assert.equal(hostMatches("app.kalibrr.com", "kalibrr.com"), false);
  assert.equal(hostMatches("kalibrr.com", "notkalibrr.com"), false);
});

test("the sixth reveal in an hour is refused by default and the window rolls", async () => {
  let clock = Date.parse("2026-10-15T00:00:00Z");
  const { options, lock, auditLogPath } = setup({ now: () => clock });

  for (let index = 0; index < 5; index += 1) {
    await getLoginCredentials({ itemId: "github" }, lock, options);
    clock += 60_000;
  }
  await assert.rejects(getLoginCredentials({ itemId: "github" }, lock, options), {
    code: "rate_limited",
  });

  const last = auditEntries(auditLogPath).at(-1);
  assert.equal(last.outcome, "refused");
  assert.equal(last.reason, "rate_limited");

  clock = Date.parse("2026-10-15T01:00:00Z");
  assert.equal((await getLoginCredentials({ itemId: "github" }, lock, options)).id, "github");
});

test("PROTONPASS_REVEALS_PER_HOUR overrides the limit and invalid values use the default", async () => {
  const limited = setup({ env: { PROTONPASS_REVEALS_PER_HOUR: "2" } });
  await getLoginCredentials({ itemId: "github" }, limited.lock, limited.options);
  await getLoginCredentials({ itemId: "github" }, limited.lock, limited.options);
  await assert.rejects(getLoginCredentials({ itemId: "github" }, limited.lock, limited.options), {
    code: "rate_limited",
  });

  for (const value of ["0", "-1", "abc", "2.5"]) {
    const fallback = setup({ env: { PROTONPASS_REVEALS_PER_HOUR: value } });
    for (let index = 0; index < 5; index += 1) {
      await getLoginCredentials({ itemId: "github" }, fallback.lock, fallback.options);
    }
    await assert.rejects(
      getLoginCredentials({ itemId: "github" }, fallback.lock, fallback.options),
      { code: "rate_limited" },
    );
  }
});

test("refused reveals do not consume the rate limit", async () => {
  const { options, lock } = setup({ env: { PROTONPASS_REVEALS_PER_HOUR: "1" } });

  await assert.rejects(getLoginCredentials({ itemId: "missing" }, lock, options), {
    code: "no_match",
  });
  assert.equal((await getLoginCredentials({ itemId: "github" }, lock, options)).id, "github");
});

test("the audit log is private and never contains credential values", async () => {
  const { options, lock, auditLogPath } = setup();

  await getLoginCredentials({ itemId: "kalibrr" }, lock, options);
  await getLoginCredentials({ itemTitle: "GitHub" }, lock, options);
  await getLoginCredentials({ url: "nowhere.example" }, lock, options).catch(() => {});

  const text = readFileSync(auditLogPath, "utf8");
  for (const value of [
    "hunter2-password",
    "gh-password",
    "agent-gh",
    "agent-kalibrr@example.com",
  ]) {
    assert.equal(text.includes(value), false, value);
  }

  const entries = auditEntries(auditLogPath);
  assert.deepEqual(
    entries.map(({ tool, outcome, reason, itemId, itemTitle, host }) => ({
      tool,
      outcome,
      reason,
      itemId,
      itemTitle,
      host,
    })),
    [
      {
        tool: "get_login_credentials",
        outcome: "success",
        reason: "revealed",
        itemId: "kalibrr",
        itemTitle: "Kalibrr",
        host: undefined,
      },
      {
        tool: "get_login_credentials",
        outcome: "success",
        reason: "revealed",
        itemId: "github",
        itemTitle: "GitHub",
        host: undefined,
      },
      {
        tool: "get_login_credentials",
        outcome: "refused",
        reason: "no_match",
        itemId: undefined,
        itemTitle: undefined,
        host: "nowhere.example",
      },
    ],
  );
  assert.ok(entries.every((entry) => !Number.isNaN(Date.parse(entry.timestamp))));

  assert.equal(statSync(auditLogPath).mode & 0o777, 0o600);
  assert.equal(statSync(join(auditLogPath, "..")).mode & 0o777, 0o700);
});

test("an unwritable audit log fails closed without a password", async () => {
  const directory = tempDir();
  const blocker = join(directory, "not-a-directory");
  writeFileSync(blocker, "");
  const { options, lock } = setup({ env: { PROTONPASS_REVEALS_PER_HOUR: "1" } });
  options.auditLogPath = join(blocker, "audit.log");

  const error = await getLoginCredentials({ itemId: "github" }, lock, options).catch((e) => e);
  assert.ok(error instanceof AuditLogError);
  assert.equal(error.message.includes("gh-password"), false);

  // The failed attempt released its rate-limit slot.
  options.auditLogPath = join(directory, "audit.log");
  assert.equal((await getLoginCredentials({ itemId: "github" }, lock, options)).id, "github");
});

test("PROTONPASS_AUDIT_LOG selects the audit log path", async () => {
  const directory = tempDir();
  const path = join(directory, "custom", "audit.jsonl");
  const { options, lock } = setup({ env: { PROTONPASS_AUDIT_LOG: path } });
  delete options.auditLogPath;

  await getLoginCredentials({ itemId: "github" }, lock, options);
  assert.equal(auditEntries(path)[0].itemId, "github");
});

test("every CLI call carries a fixed, server-generated agent reason", async () => {
  const { cli, options, lock } = setup();

  await getLoginCredentials({ url: "https://www.kalibrr.com/login?next=/x" }, lock, options);
  await getLoginCredentials({ itemId: "github" }, lock, options);

  assert.ok(cli.calls.length > 0);
  for (const { reason } of cli.calls) {
    assert.match(reason, /^protonpass-mcp sign-in for \S.*$/);
  }
  assert.deepEqual(
    cli.calls.map(({ args, reason }) => [args.slice(0, 2).join(" "), reason]),
    [
      ["vault list", "protonpass-mcp sign-in for saved logins"],
      ["item list", "protonpass-mcp sign-in for www.kalibrr.com"],
      ["item view", "protonpass-mcp sign-in for Kalibrr"],
      ["item view", "protonpass-mcp sign-in for GitHub"],
      ["item list", "protonpass-mcp sign-in for saved login"],
      ["item view", "protonpass-mcp sign-in for GitHub"],
    ],
  );

  assert.equal(agentReason("Evil\nTitle\u0000‮ x"), "protonpass-mcp sign-in for Evil Title x");
  assert.equal(agentReason("a".repeat(500)).length, 300);
  assert.equal(agentReason("  "), "protonpass-mcp sign-in for saved login");
});

test("CLI failures and malformed output never leak stdout", async () => {
  const leaky = "not json hunter2-password";
  const { options, lock } = setup({
    cli: { calls: [], runner: async () => ({ stdout: leaky, stderr: leaky }) },
    vault: { shareId: AGENT_SHARE },
  });

  const listError = await findLogins({}, lock, options).catch((e) => e);
  assert.match(listError.message, /Could not parse/);
  assert.equal(listError.message.includes("hunter2"), false);

  const revealError = await getLoginCredentials({ itemId: "x" }, lock, options).catch((e) => e);
  assert.equal(revealError.message.includes("hunter2"), false);

  const crashing = setup({
    cli: {
      calls: [],
      runner: async () => {
        throw new TypeError("hunter2-password");
      },
    },
  });
  const crash = await getLoginCredentials({ itemId: "x" }, crashing.lock, crashing.options).catch(
    (e) => e,
  );
  assert.equal(crash.message, "Could not retrieve login credentials.");
});
