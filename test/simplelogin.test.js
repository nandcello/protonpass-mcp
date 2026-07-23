import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import {
  SimpleLoginApiError,
  getOrCreateAliasContact,
  requestSimpleLogin,
  searchAliases,
  verifySimpleLoginApi,
} from "../src/simplelogin.js";

test("searchAliases returns a safe page of matching aliases", async () => {
  const calls = [];
  const result = await searchAliases(
    { query: "shop", page: 2 },
    {
      apiKey: "secret-api-key",
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return new Response(
          JSON.stringify({
            aliases: [
              {
                id: 11,
                email: "shopping@example.com",
                name: "Shopping",
                enabled: true,
                mailbox: { email: "private@example.org", id: 9 },
                note: "Private note",
              },
              {
                id: 12,
                email: "old-shopping@example.com",
                name: null,
                enabled: false,
              },
            ],
          }),
        );
      },
    },
  );

  assert.deepEqual(result, {
    query: "shop",
    page: 2,
    aliases: [
      {
        alias: "shopping@example.com",
        name: "Shopping",
        enabled: true,
      },
      {
        alias: "old-shopping@example.com",
        name: null,
        enabled: false,
      },
    ],
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://app.simplelogin.io/api/v2/aliases?page_id=2");
  assert.equal(calls[0].init.headers.Authentication, "secret-api-key");
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].init.body), { query: "shop" });
});

test("searchAliases rejects malformed alias results", async () => {
  await assert.rejects(
    searchAliases(
      { query: "shop" },
      {
        apiKey: "secret-api-key",
        fetchImpl: async () =>
          new Response(
            JSON.stringify({
              aliases: [{ id: 11, email: "shopping@example.com", enabled: "yes" }],
            }),
          ),
      },
    ),
    /unexpected alias response/,
  );
});

test("getOrCreateAliasContact finds the exact alias and creates a contact", async () => {
  const calls = [];
  const result = await getOrCreateAliasContact(
    {
      alias: "shopping@example.com",
      contact: "merchant@example.org",
    },
    {
      apiKey: "secret-api-key",
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        if (new URL(url).pathname === "/api/v2/aliases") {
          return new Response(
            JSON.stringify({
              aliases: [
                { id: 10, email: "other@example.com", enabled: true },
                { id: 11, email: "shopping@example.com", enabled: true },
              ],
            }),
          );
        }

        return new Response(
          JSON.stringify({
            contact: "merchant@example.org",
            reverse_alias: "merchant at example.org <reply+merchant@example.net>",
            reverse_alias_address: "reply+merchant@example.net",
            existed: false,
          }),
          { status: 201 },
        );
      },
    },
  );

  assert.deepEqual(result, {
    created: true,
    existed: false,
    alias: "shopping@example.com",
    contact: "merchant@example.org",
    reverseAlias: "reply+merchant@example.net",
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://app.simplelogin.io/api/v2/aliases?page_id=0");
  assert.equal(calls[0].init.headers.Authentication, "secret-api-key");
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    query: "shopping@example.com",
  });
  assert.equal(calls[1].url, "https://app.simplelogin.io/api/aliases/11/contacts");
  assert.equal(calls[1].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    contact: "merchant@example.org",
  });
});

test("getOrCreateAliasContact reports an existing contact as idempotent", async () => {
  let call = 0;
  const result = await getOrCreateAliasContact(
    {
      alias: "shopping@example.com",
      contact: "merchant@example.org",
    },
    {
      apiKey: "secret-api-key",
      fetchImpl: async () => {
        call += 1;
        return call === 1
          ? new Response(
              JSON.stringify({
                aliases: [{ id: 11, email: "shopping@example.com", enabled: true }],
              }),
            )
          : new Response(
              JSON.stringify({
                reverse_alias_address: "reply+merchant@example.net",
                existed: true,
              }),
            );
      },
    },
  );

  assert.deepEqual(result, {
    created: false,
    existed: true,
    alias: "shopping@example.com",
    contact: "merchant@example.org",
    reverseAlias: "reply+merchant@example.net",
  });
});

test("getOrCreateAliasContact does not mutate when the exact alias is absent", async () => {
  let calls = 0;
  await assert.rejects(
    getOrCreateAliasContact(
      {
        alias: "missing@example.com",
        contact: "merchant@example.org",
      },
      {
        apiKey: "secret-api-key",
        fetchImpl: async () => {
          calls += 1;
          return new Response(
            JSON.stringify({
              aliases: [{ id: 11, email: "similar@example.com", enabled: true }],
            }),
          );
        },
      },
    ),
    /Alias was not found/,
  );
  assert.equal(calls, 1);
});

test("getOrCreateAliasContact rejects a contact response without a boolean existed field", async () => {
  for (const existed of [undefined, "true"]) {
    let call = 0;
    await assert.rejects(
      getOrCreateAliasContact(
        {
          alias: "shopping@example.com",
          contact: "merchant@example.org",
        },
        {
          apiKey: "secret-api-key",
          fetchImpl: async () => {
            call += 1;
            return call === 1
              ? new Response(
                  JSON.stringify({
                    aliases: [{ id: 11, email: "shopping@example.com", enabled: true }],
                  }),
                )
              : new Response(
                  JSON.stringify({
                    reverse_alias_address: "reply+merchant@example.net",
                    existed,
                  }),
                );
          },
        },
      ),
      /unexpected contact response/,
    );
  }
});

test("SimpleLogin API errors do not expose API response content", async () => {
  await assert.rejects(
    requestSimpleLogin(
      "/api/user_info",
      {},
      {
        apiKey: "secret-api-key",
        fetchImpl: async () =>
          new Response(JSON.stringify({ error: "private@example.com secret detail" }), {
            status: 403,
          }),
      },
    ),
    (error) => {
      assert.ok(error instanceof SimpleLoginApiError);
      assert.equal(error.message, "SimpleLogin API request failed.");
      assert.equal(error.message.includes("private@example.com"), false);
      assert.equal(error.message.includes("secret-api-key"), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("SimpleLogin API stops reading responses at the byte limit", async () => {
  let cancelled = false;
  const responseBody = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(256 * 1024));
    },
    cancel() {
      cancelled = true;
    },
  });

  await assert.rejects(
    requestSimpleLogin(
      "/api/user_info",
      {},
      {
        apiKey: "secret-api-key",
        fetchImpl: async () => new Response(responseBody),
      },
    ),
    /unexpectedly large response/,
  );
  assert.equal(cancelled, true);
});

test("SimpleLogin API requires a key and reports rejected keys safely", async () => {
  await assert.rejects(verifySimpleLoginApi({ env: {} }), /Set SIMPLELOGIN_API_KEY/);

  await assert.rejects(
    verifySimpleLoginApi({
      apiKey: "rejected-key",
      fetchImpl: async () => new Response("{}", { status: 401 }),
    }),
    (error) => {
      assert.ok(error instanceof SimpleLoginApiError);
      assert.equal(error.message, "SimpleLogin API key was rejected.");
      assert.equal(error.message.includes("rejected-key"), false);
      return true;
    },
  );
});

test("SimpleLogin API refuses to send keys over non-loopback HTTP", async () => {
  await assert.rejects(
    verifySimpleLoginApi({
      apiKey: "secret-api-key",
      baseUrl: "http://simplelogin.example",
      fetchImpl: async () => new Response("{}"),
    }),
    /must use HTTPS/,
  );
});

test("SimpleLogin API reports timeouts without leaking request details", async () => {
  await assert.rejects(
    verifySimpleLoginApi({
      apiKey: "secret-api-key",
      timeoutMs: 10,
      fetchImpl: async (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    }),
    (error) => {
      assert.ok(error instanceof SimpleLoginApiError);
      assert.equal(error.message, "SimpleLogin API timed out after 10 ms.");
      return true;
    },
  );
});
