import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import {
  SimpleLoginApiError,
  createAliasContact,
  requestSimpleLogin,
  verifySimpleLoginApi,
} from "../src/simplelogin.js";

test("createAliasContact finds the exact alias and creates a contact", async () => {
  const calls = [];
  const result = await createAliasContact(
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
                { id: 10, email: "other@example.com" },
                { id: 11, email: "shopping@example.com" },
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
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    query: "shopping@example.com",
  });
  assert.equal(calls[1].url, "https://app.simplelogin.io/api/aliases/11/contacts");
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    contact: "merchant@example.org",
  });
});

test("createAliasContact reports an existing contact as idempotent", async () => {
  let call = 0;
  const result = await createAliasContact(
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
                aliases: [{ id: 11, email: "shopping@example.com" }],
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

test("createAliasContact does not mutate when the exact alias is absent", async () => {
  let calls = 0;
  await assert.rejects(
    createAliasContact(
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
              aliases: [{ id: 11, email: "similar@example.com" }],
            }),
          );
        },
      },
    ),
    /Alias was not found/,
  );
  assert.equal(calls, 1);
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
