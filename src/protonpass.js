import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const EMAIL_ADDRESS = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOTP_CODE = /^\d{6,10}$/;
const MAX_FAILURE_REASON_LENGTH = 200;
// pass-cli colors its tracing output; the escape character is matched on purpose.
// oxlint-disable-next-line no-control-regex
const ANSI_ESCAPE = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const LOG_PREFIX = /^\d{4}-\d{2}-\d{2}T\S+\s+(?:ERROR|WARN|INFO|DEBUG|TRACE)\s+\S+:\d+:\s*/;

export class ProtonPassCliError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProtonPassCliError";
  }
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

/**
 * Reduces CLI stderr to one short, secret-free reason. Prefers the final `Error:` line
 * over tracing output, and redacts email addresses, access tokens and long token-like
 * strings. Stdout is never used because it can contain item contents.
 */
export function failureReason(stderr) {
  const lines = String(stderr ?? "")
    .replace(ANSI_ESCAPE, "")
    .split(/\r?\n/)
    .map((line) =>
      line
        .replace(/[\p{Cc}\p{Cf}]/gu, " ")
        .trim()
        .replace(LOG_PREFIX, ""),
    )
    .filter(Boolean);
  const line = lines.find((candidate) => /^error\b/i.test(candidate)) ?? lines[0];
  if (!line) return undefined;

  return line
    .replace(/[^\s@'"<>]+@[^\s@'"<>]+/g, "[email]")
    .replace(/pst_\S+/g, "[redacted]")
    .replace(/[A-Za-z0-9+/_=-]{32,}/g, "[redacted]")
    .slice(0, MAX_FAILURE_REASON_LENGTH);
}

function configuredTimeout(env) {
  const value = Number.parseInt(env.PROTONPASS_TIMEOUT_MS ?? "", 10);
  return Number.isSafeInteger(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

export async function runPassCli(args, options = {}) {
  const env = options.env ?? process.env;
  const cliPath = options.cliPath ?? env.PROTONPASS_CLI_PATH ?? "pass-cli";
  const timeout = options.timeoutMs ?? configuredTimeout(env);

  try {
    const result = await execFileAsync(cliPath, args, {
      encoding: "utf8",
      env,
      maxBuffer: MAX_OUTPUT_BYTES,
      timeout,
      windowsHide: true,
    });

    return {
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new ProtonPassCliError(
        "Could not find Proton Pass CLI. Install it or set PROTONPASS_CLI_PATH.",
      );
    }

    if (error?.killed || error?.signal === "SIGTERM") {
      throw new ProtonPassCliError(`Proton Pass CLI timed out after ${timeout} ms.`);
    }

    const exit = Number.isInteger(error?.code) ? `exit ${error.code}` : "abnormal exit";
    const reason = failureReason(error?.stderr);
    throw new ProtonPassCliError(
      reason
        ? `Proton Pass CLI failed (${exit}): ${reason}`
        : `Proton Pass CLI failed (${exit}). Run \`pass-cli info\` to check the authenticated session.`,
    );
  }
}

function vaultArgs(vaultSelector) {
  const normalized = normalizeVaultSelector(vaultSelector);
  return normalized.shareId
    ? ["--share-id", normalized.shareId]
    : ["--vault-name", normalized.vaultName];
}

export function buildCreateAliasArgs(input, vaultSelector) {
  return [
    "item",
    "alias",
    "create",
    ...vaultArgs(vaultSelector),
    "--prefix",
    input.prefix,
    "--output",
    "json",
  ];
}

export function buildCreateLoginArgs(input, vaultSelector) {
  const args = ["item", "create", "login", ...vaultArgs(vaultSelector), "--title", input.title];

  if (input.username) args.push("--username", input.username);
  if (input.email) args.push("--email", input.email);
  for (const url of input.urls ?? []) args.push("--url", url);

  const length = input.passwordLength ?? 24;
  const uppercase = input.includeUppercase ?? true;
  const symbols = input.includeSymbols ?? true;
  args.push(`--generate-password=${length},${uppercase},${symbols}`);

  return args;
}

export function buildGetTotpArgs(input, vaultSelector) {
  const selectors = [input.itemId, input.itemTitle].filter(Boolean);
  if (selectors.length !== 1) {
    throw new ProtonPassCliError("Provide exactly one of itemId or itemTitle.");
  }

  const args = ["item", "totp", ...vaultArgs(vaultSelector)];
  if (input.itemId) args.push("--item-id", input.itemId);
  if (input.itemTitle) args.push("--item-title", input.itemTitle);
  if (input.field) args.push("--field", input.field);
  args.push("--output", "json");

  return args;
}

export function parseAliasAddress(stdout) {
  const output = stdout.trim();
  if (!output) return undefined;

  try {
    const response = JSON.parse(output);
    if (
      response &&
      typeof response === "object" &&
      !Array.isArray(response) &&
      typeof response.alias === "string"
    ) {
      const alias = response.alias.trim();
      return EMAIL_ADDRESS.test(alias) ? alias : undefined;
    }
  } catch {
    // The command was explicitly asked for JSON; unknown output is unsafe to infer.
  }

  return undefined;
}

export function parseTotpCodes(stdout) {
  const output = stdout.trim();
  if (!output) {
    throw new ProtonPassCliError("Proton Pass CLI returned no TOTP codes for this item.");
  }

  let parsed;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new ProtonPassCliError("Could not parse the Proton Pass CLI TOTP response.");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ProtonPassCliError("Proton Pass CLI returned an unexpected TOTP response.");
  }

  const entries = Object.entries(parsed);
  if (entries.length === 0) {
    throw new ProtonPassCliError("Proton Pass CLI returned no TOTP codes for this item.");
  }

  return entries.map(([name, value]) => {
    const code = typeof value === "string" ? value.trim() : "";
    if (!name.trim() || !TOTP_CODE.test(code)) {
      throw new ProtonPassCliError("Proton Pass CLI returned an unexpected TOTP response.");
    }

    return { name, code };
  });
}

export async function createAlias(input, vaultSelector, options = {}) {
  const runner = options.runner ?? runPassCli;
  const { stdout } = await runner(buildCreateAliasArgs(input, vaultSelector), options);
  const alias = parseAliasAddress(stdout);

  return {
    created: true,
    alias: alias ?? null,
    prefix: input.prefix,
    ...(alias
      ? {}
      : {
          warning:
            "The alias was created, but its address could not be parsed from the CLI response.",
        }),
  };
}

export async function createLogin(input, vaultSelector, options = {}) {
  const runner = options.runner ?? runPassCli;
  await runner(buildCreateLoginArgs(input, vaultSelector), options);

  return {
    created: true,
    title: input.title,
    passwordGenerated: true,
    passwordLength: input.passwordLength ?? 24,
  };
}

export async function getTotp(input, vaultSelector, options = {}) {
  const runner = options.runner ?? runPassCli;
  const { stdout } = await runner(buildGetTotpArgs(input, vaultSelector), options);

  return {
    codes: parseTotpCodes(stdout),
    ...(input.itemId ? { itemId: input.itemId } : {}),
    ...(input.itemTitle ? { itemTitle: input.itemTitle } : {}),
    ...(input.field ? { field: input.field } : {}),
  };
}
