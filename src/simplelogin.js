const DEFAULT_API_BASE_URL = "https://app.simplelogin.io";
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const EMAIL_ADDRESS = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class SimpleLoginApiError extends Error {
  constructor(message) {
    super(message);
    this.name = "SimpleLoginApiError";
  }
}

function configuredTimeout(env) {
  const value = Number.parseInt(env.SIMPLELOGIN_TIMEOUT_MS ?? "", 10);
  return Number.isSafeInteger(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

function apiConfiguration(options) {
  const env = options.env ?? process.env;
  const apiKey = (options.apiKey ?? env.SIMPLELOGIN_API_KEY)?.trim();
  if (!apiKey) {
    throw new SimpleLoginApiError(
      "SimpleLogin API access is not configured. Set SIMPLELOGIN_API_KEY.",
    );
  }

  const baseUrl = (options.baseUrl ?? env.SIMPLELOGIN_API_BASE_URL ?? DEFAULT_API_BASE_URL).trim();
  let parsedBaseUrl;
  try {
    parsedBaseUrl = new URL(baseUrl);
  } catch {
    throw new SimpleLoginApiError("SIMPLELOGIN_API_BASE_URL is not a valid URL.");
  }

  if (
    parsedBaseUrl.protocol !== "https:" &&
    !(parsedBaseUrl.protocol === "http:" && LOOPBACK_HOSTS.has(parsedBaseUrl.hostname))
  ) {
    throw new SimpleLoginApiError(
      "SIMPLELOGIN_API_BASE_URL must use HTTPS unless it targets a loopback address.",
    );
  }

  return {
    apiKey,
    baseUrl: parsedBaseUrl,
    timeoutMs: options.timeoutMs ?? configuredTimeout(env),
  };
}

async function cancelResponseBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The response is already being rejected; cancellation is best-effort cleanup.
  }
}

async function readResponseText(response) {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) return text + decoder.decode();

      bytesRead += value.byteLength;
      if (bytesRead > MAX_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The size error below is the actionable failure.
        }
        throw new SimpleLoginApiError("SimpleLogin API returned an unexpectedly large response.");
      }

      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

async function parseResponse(response) {
  if (!response.ok) {
    await cancelResponseBody(response);
    if (response.status === 401) {
      throw new SimpleLoginApiError("SimpleLogin API key was rejected.");
    }
    throw new SimpleLoginApiError("SimpleLogin API request failed.");
  }

  const text = await readResponseText(response);

  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Unexpected response shape");
    }
    return parsed;
  } catch {
    throw new SimpleLoginApiError("Could not parse the SimpleLogin API response.");
  }
}

export async function requestSimpleLogin(path, request = {}, options = {}) {
  const { apiKey, baseUrl, timeoutMs } = apiConfiguration(options);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  const headers = {
    Accept: "application/json",
    Authentication: apiKey,
  };
  const init = {
    method: request.method ?? "GET",
    headers,
    redirect: "error",
    signal: controller.signal,
  };

  if (request.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(request.body);
  }

  try {
    const response = await fetchImpl(new URL(path, baseUrl), init);
    return await parseResponse(response);
  } catch (error) {
    if (error instanceof SimpleLoginApiError) throw error;
    if (controller.signal.aborted) {
      throw new SimpleLoginApiError(`SimpleLogin API timed out after ${timeoutMs} ms.`);
    }
    throw new SimpleLoginApiError("Could not reach the SimpleLogin API.");
  } finally {
    clearTimeout(timeout);
  }
}

function parseAliases(response) {
  if (!Array.isArray(response.aliases)) {
    throw new SimpleLoginApiError("SimpleLogin API returned an unexpected alias response.");
  }

  return response.aliases.map((candidate) => {
    const alias =
      candidate && typeof candidate === "object" && typeof candidate.email === "string"
        ? candidate.email.trim()
        : "";
    const name =
      candidate &&
      typeof candidate === "object" &&
      (candidate.name === null || candidate.name === undefined)
        ? null
        : candidate?.name;

    if (
      !candidate ||
      typeof candidate !== "object" ||
      !EMAIL_ADDRESS.test(alias) ||
      !Number.isSafeInteger(candidate.id) ||
      candidate.id <= 0 ||
      typeof candidate.enabled !== "boolean" ||
      (name !== null && typeof name !== "string")
    ) {
      throw new SimpleLoginApiError("SimpleLogin API returned an unexpected alias response.");
    }

    return {
      id: candidate.id,
      alias,
      name,
      enabled: candidate.enabled,
    };
  });
}

function findExactAlias(response, alias) {
  const normalizedAlias = alias.toLowerCase();
  return parseAliases(response).find(
    (candidate) => candidate.alias.toLowerCase() === normalizedAlias,
  );
}

function parseCreatedContact(response) {
  const reverseAlias =
    typeof response.reverse_alias_address === "string" ? response.reverse_alias_address.trim() : "";

  if (!EMAIL_ADDRESS.test(reverseAlias) || typeof response.existed !== "boolean") {
    throw new SimpleLoginApiError("SimpleLogin API returned an unexpected contact response.");
  }

  return {
    existed: response.existed,
    reverseAlias,
  };
}

export async function searchAliases(input, options = {}) {
  const page = input.page ?? 0;
  const response = await requestSimpleLogin(
    `/api/v2/aliases?page_id=${encodeURIComponent(page)}`,
    {
      method: "POST",
      body: { query: input.query },
    },
    options,
  );

  return {
    query: input.query,
    page,
    aliases: parseAliases(response).map(({ id: _id, ...alias }) => alias),
  };
}

export async function getOrCreateAliasContact(input, options = {}) {
  const aliasResponse = await requestSimpleLogin(
    "/api/v2/aliases?page_id=0",
    {
      method: "POST",
      body: { query: input.alias },
    },
    options,
  );
  const alias = findExactAlias(aliasResponse, input.alias);

  if (!alias) {
    throw new SimpleLoginApiError("Alias was not found in the configured SimpleLogin account.");
  }

  const contactResponse = await requestSimpleLogin(
    `/api/aliases/${encodeURIComponent(alias.id)}/contacts`,
    {
      method: "POST",
      body: { contact: input.contact },
    },
    options,
  );
  const contact = parseCreatedContact(contactResponse);

  return {
    created: !contact.existed,
    existed: contact.existed,
    alias: input.alias,
    contact: input.contact,
    reverseAlias: contact.reverseAlias,
  };
}

export async function verifySimpleLoginApi(options = {}) {
  await requestSimpleLogin("/api/user_info", {}, options);
  return { authenticated: true };
}
