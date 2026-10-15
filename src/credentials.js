import { constants as fsConstants } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  ProtonPassCliError,
  normalizeVaultSelector,
  runPassCli,
  sanitizeAgentReason,
} from "./protonpass.js";

export const DEFAULT_REVEALS_PER_HOUR = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const MAX_LOGIN_LOOKUPS = 50;
const REASON_PREFIX = "protonpass-mcp sign-in for ";

/** A deliberate refusal. Its message is safe to show and never contains CLI output. */
export class CredentialRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CredentialRefusal";
    this.code = code;
  }
}

export class AuditLogError extends Error {
  constructor() {
    super("The credential audit log could not be written, so no credentials were returned.");
    this.name = "AuditLogError";
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function parseJson(stdout, what) {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new ProtonPassCliError(`Could not parse the Proton Pass CLI ${what} response.`);
  }
}

/**
 * Builds the fixed PROTON_PASS_AGENT_REASON value. Only an item title or host is
 * interpolated, stripped of control characters and capped at Proton's 300-char limit.
 */
export function agentReason(label) {
  return sanitizeAgentReason(REASON_PREFIX + (sanitizeAgentReason(label) || "saved login"));
}

function agentOptions(options, label) {
  return {
    ...options,
    env: { ...(options.env ?? process.env), PROTON_PASS_AGENT_REASON: agentReason(label) },
  };
}

export function parseVaultList(stdout) {
  const parsed = parseJson(stdout, "vault list");
  const vaults = Array.isArray(parsed) ? parsed : parsed?.vaults;
  if (!Array.isArray(vaults)) {
    throw new ProtonPassCliError("Proton Pass CLI returned an unexpected vault list.");
  }

  return vaults.filter(isObject).map((vault) => ({
    name: typeof vault.name === "string" ? vault.name : "",
    shareId: nonEmptyString(vault.share_id),
  }));
}

/**
 * Resolves the operator-configured vault to a single share ID. A configured name is
 * resolved once, because `--vault-name` silently picks the first of several matches.
 */
export class VaultLock {
  #selector;
  #resolving;

  constructor(vaultSelector) {
    this.#selector = normalizeVaultSelector(vaultSelector);
  }

  shareId(options = {}) {
    if (this.#selector.shareId) return Promise.resolve(this.#selector.shareId);

    this.#resolving ??= this.#resolve(options).catch((error) => {
      this.#resolving = undefined;
      throw error;
    });
    return this.#resolving;
  }

  async #resolve(options) {
    const runner = options.runner ?? runPassCli;
    const { stdout } = await runner(
      ["vault", "list", "--output", "json"],
      agentOptions(options, "saved logins"),
    );
    const matches = parseVaultList(stdout).filter(
      (vault) => vault.name === this.#selector.vaultName,
    );

    if (matches.length !== 1 || !matches[0].shareId) {
      throw new CredentialRefusal(
        "vault_unresolved",
        matches.length > 1
          ? "The configured vault name matches more than one vault. Configure the server with --share-id instead."
          : "The configured vault was not found.",
      );
    }

    return matches[0].shareId;
  }
}

/** Accepts `{ item: {...} }` or a bare item, with content nested as ItemData or flat. */
function itemParts(item) {
  const data = isObject(item.content) ? item.content : item;
  const typed = isObject(data.content) ? data.content : data;

  return {
    title: nonEmptyString(data.title) ?? nonEmptyString(item.title) ?? "",
    login: [typed.Login, typed.login].find(isObject),
  };
}

function loginUrls(login) {
  const urls = Array.isArray(login.urls) ? login.urls : [];
  return urls
    .map((entry) => (isObject(entry) ? entry.url : entry))
    .filter((url) => typeof url === "string" && url.trim())
    .map((url) => url.trim());
}

function isLoginType(row) {
  const type = row.item_type ?? row.type;
  return type === undefined || String(type).toLowerCase() === "login";
}

export function parseItemList(stdout, lockedShareId) {
  const parsed = parseJson(stdout, "item list");
  const items = Array.isArray(parsed) ? parsed : parsed?.items;
  if (!Array.isArray(items)) {
    throw new ProtonPassCliError("Proton Pass CLI returned an unexpected item list.");
  }

  // Rows from any other share are dropped, even though --share-id was requested.
  return items
    .filter((row) => isObject(row) && row.share_id === lockedShareId && isLoginType(row))
    .flatMap((row) => {
      const id = nonEmptyString(row.id) ?? nonEmptyString(row.item_id);
      if (!id) return [];
      const { title, login } = itemParts(row);
      return [{ id, title, summary: login ? loginSummary(id, title, login) : undefined }];
    });
}

function loginSummary(id, title, login) {
  return {
    id,
    title,
    hasUsername: Boolean(nonEmptyString(login.username)),
    hasEmail: Boolean(nonEmptyString(login.email)),
    urls: loginUrls(login),
  };
}

/**
 * Parses `item view` output and keeps only the sign-in fields. Notes, TOTP, passkeys,
 * extra fields, attachments and history are never copied out. An item whose share_id
 * is missing or differs from the locked vault is refused outright.
 */
export function parseLoginView(stdout, lockedShareId) {
  const parsed = parseJson(stdout, "item view");
  const item = isObject(parsed?.item) ? parsed.item : parsed;
  if (!isObject(item)) {
    throw new ProtonPassCliError("Proton Pass CLI returned an unexpected item.");
  }
  if (item.share_id !== lockedShareId) {
    throw new CredentialRefusal(
      "vault_mismatch",
      "The item is not in the configured vault, so it was not returned.",
    );
  }

  const id = nonEmptyString(item.id) ?? nonEmptyString(item.item_id);
  const { title, login } = itemParts(item);
  if (!id || !login) {
    throw new CredentialRefusal("not_login", "The selected item is not a login.");
  }

  return {
    ...loginSummary(id, title, login),
    username: nonEmptyString(login.username) ?? null,
    email: nonEmptyString(login.email) ?? null,
    password: nonEmptyString(login.password) ?? null,
  };
}

/** Returns the lowercase hostname of a URL or bare domain, or undefined. */
export function hostOf(value) {
  const text = String(value ?? "").trim();
  if (!text) return undefined;

  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : `https://${text}`);
    if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    return host || undefined;
  } catch {
    return undefined;
  }
}

/**
 * True when `lookupHost` is the saved URL's host or one of its subdomains. A leading
 * `www.` on the saved host is ignored, so a saved www.example.com matches example.com.
 */
export function hostMatches(savedUrl, lookupHost) {
  const savedHost = hostOf(savedUrl)?.replace(/^www\./, "");
  if (!savedHost || !lookupHost) return false;
  return lookupHost === savedHost || lookupHost.endsWith(`.${savedHost}`);
}

function configuredLimit(env) {
  const raw = String(env.PROTONPASS_REVEALS_PER_HOUR ?? "").trim();
  const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  return Number.isSafeInteger(value) && value > 0 ? value : DEFAULT_REVEALS_PER_HOUR;
}

/** Rolling one-hour reveal counter. Slots are reserved up front and released on failure. */
export class RevealRateLimiter {
  #times = [];
  #now;

  constructor({ now = Date.now } = {}) {
    this.#now = now;
  }

  tryAcquire(limit) {
    const now = this.#now();
    this.#times = this.#times.filter((time) => now - time < RATE_WINDOW_MS);
    if (this.#times.length >= limit) return undefined;

    const slot = { time: now };
    this.#times.push(now);
    return slot;
  }

  release(slot) {
    const index = this.#times.indexOf(slot.time);
    if (index !== -1) this.#times.splice(index, 1);
  }
}

// Shared across server instances because HTTP gateways may build one server per request.
const sharedRateLimiter = new RevealRateLimiter();

export function defaultAuditLogPath(env = process.env) {
  const stateHome = nonEmptyString(env.XDG_STATE_HOME) ?? join(homedir(), ".local", "state");
  return join(stateHome, "protonpass-mcp", "audit.log");
}

/** Appends one JSON line to a 0600 audit log in a 0700 directory, without following symlinks. */
export async function appendAuditEntry(path, entry) {
  try {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const flags =
      fsConstants.O_WRONLY |
      fsConstants.O_APPEND |
      fsConstants.O_CREAT |
      (fsConstants.O_NOFOLLOW ?? 0);
    const handle = await open(path, flags, 0o600);
    try {
      await handle.chmod(0o600);
      await handle.appendFile(`${JSON.stringify(entry)}\n`, "utf8");
    } finally {
      await handle.close();
    }
  } catch {
    throw new AuditLogError();
  }
}

function selectionLabel(selection) {
  return selection.host ?? selection.itemTitle ?? "saved login";
}

async function listLogins(shareId, label, options) {
  const runner = options.runner ?? runPassCli;
  const { stdout } = await runner(
    [
      "item",
      "list",
      "--share-id",
      shareId,
      "--filter-type",
      "login",
      "--filter-state",
      "active",
      "--output",
      "json",
    ],
    agentOptions(options, label),
  );
  return parseItemList(stdout, shareId);
}

async function viewLogin(shareId, row, options) {
  const runner = options.runner ?? runPassCli;
  const { stdout } = await runner(
    ["item", "view", "--share-id", shareId, "--item-id", row.id, "--output", "json"],
    agentOptions(options, row.title),
  );
  const login = parseLoginView(stdout, shareId);
  if (login.id !== row.id) {
    throw new CredentialRefusal("item_mismatch", "Proton Pass CLI returned a different item.");
  }
  return login;
}

/** Lists login summaries in the locked vault, viewing items only when list rows lack content. */
async function findInVault(shareId, { query, host }, options, viewed) {
  let rows = await listLogins(shareId, host ?? "saved logins", options);

  if (query) {
    const needle = query.toLowerCase();
    rows = rows.filter((row) => row.title.toLowerCase().includes(needle));
  }

  const needViews = rows.filter((row) => !row.summary);
  if (needViews.length > MAX_LOGIN_LOOKUPS) {
    throw new CredentialRefusal(
      "too_many_items",
      `More than ${MAX_LOGIN_LOOKUPS} logins match. Narrow the search with query.`,
    );
  }

  const summaries = [];
  for (const row of rows) {
    if (row.summary) {
      summaries.push(row.summary);
      continue;
    }
    const login = await viewLogin(shareId, row, options);
    viewed.set(login.id, login);
    summaries.push(publicSummary(login));
  }

  return host
    ? summaries.filter((summary) => summary.urls.some((url) => hostMatches(url, host)))
    : summaries;
}

function publicSummary({ id, title, hasUsername, hasEmail, urls }) {
  return { id, title, hasUsername, hasEmail, urls };
}

export async function findLogins(input, vaultLock, options = {}) {
  let host;
  if (input.url !== undefined) {
    host = hostOf(input.url);
    if (!host) throw new CredentialRefusal("invalid_url", "url must be a web URL or domain.");
  }

  const shareId = await vaultLock.shareId(options);
  const logins = await findInVault(shareId, { query: input.query, host }, options, new Map());
  return { logins };
}

function describeMatches(matches) {
  return matches.map((match) => `${match.id} (${match.title || "untitled"})`).join(", ");
}

async function selectLogin(shareId, selection, options, viewed) {
  if (selection.host) {
    const matches = await findInVault(shareId, { host: selection.host }, options, viewed);
    if (matches.length !== 1) {
      throw new CredentialRefusal(
        matches.length ? "ambiguous_match" : "no_match",
        matches.length
          ? `More than one login matches ${selection.host}: ${describeMatches(matches)}. Select one by itemId.`
          : `No login in the configured vault matches ${selection.host}.`,
      );
    }
    return matches[0];
  }

  const rows = await listLogins(shareId, selectionLabel(selection), options);
  const matches = selection.itemId
    ? rows.filter((row) => row.id === selection.itemId)
    : rows.filter((row) => row.title.toLowerCase() === selection.itemTitle.toLowerCase());

  if (matches.length !== 1) {
    throw new CredentialRefusal(
      matches.length ? "ambiguous_match" : "no_match",
      matches.length
        ? `More than one login has that title: ${describeMatches(matches)}. Select one by itemId.`
        : "No login in the configured vault matches that selection.",
    );
  }
  return matches[0];
}

function safeError(error) {
  if (
    error instanceof CredentialRefusal ||
    error instanceof AuditLogError ||
    error instanceof ProtonPassCliError
  ) {
    return error;
  }
  return new ProtonPassCliError("Could not retrieve login credentials.");
}

/**
 * Reveals one login from the locked vault. Every attempt is audited without credential
 * values; a successful reveal is returned only after its audit entry is written.
 */
export async function getLoginCredentials(input, vaultLock, options = {}) {
  const env = options.env ?? process.env;
  const auditLogPath =
    options.auditLogPath ?? nonEmptyString(env.PROTONPASS_AUDIT_LOG) ?? defaultAuditLogPath(env);
  const limiter = options.rateLimiter ?? sharedRateLimiter;
  const now = options.now ?? Date.now;

  const selection = {
    itemId: input.itemId,
    itemTitle: input.itemTitle,
    host: input.url === undefined ? undefined : hostOf(input.url),
  };
  const audit = (outcome, reason, item) =>
    appendAuditEntry(auditLogPath, {
      timestamp: new Date(now()).toISOString(),
      tool: "get_login_credentials",
      outcome,
      reason,
      ...(item ? { itemId: item.id, itemTitle: item.title } : {}),
      ...(!item && selection.itemId ? { itemId: selection.itemId } : {}),
      ...(!item && selection.itemTitle ? { itemTitle: selection.itemTitle } : {}),
      ...(selection.host ? { host: selection.host } : {}),
    });

  let item;
  let slot;
  try {
    if (input.url !== undefined && !selection.host) {
      throw new CredentialRefusal("invalid_url", "url must be a web URL or domain.");
    }

    slot = limiter.tryAcquire(configuredLimit(env));
    if (!slot) {
      throw new CredentialRefusal(
        "rate_limited",
        "The hourly credential reveal limit has been reached. Try again later.",
      );
    }

    const shareId = await vaultLock.shareId(options);
    const viewed = new Map();
    const selected = await selectLogin(shareId, selection, options, viewed);
    item = selected;
    const login = viewed.get(selected.id) ?? (await viewLogin(shareId, selected, options));
    item = login;
    if (!login.password) {
      throw new CredentialRefusal("no_password", "The selected login has no saved password.");
    }

    // Fail closed: the password is returned only after the reveal has been recorded.
    await audit("success", "revealed", login);
    return {
      id: login.id,
      title: login.title,
      username: login.username,
      email: login.email,
      password: login.password,
      urls: login.urls,
    };
  } catch (error) {
    if (slot) limiter.release(slot);
    if (!(error instanceof AuditLogError)) {
      const refused = error instanceof CredentialRefusal;
      await audit(refused ? "refused" : "error", refused ? error.code : "cli_error", item).catch(
        () => {},
      );
    }
    throw safeError(error);
  }
}
