import { serialize } from "../mod.ts";
import sdData from "./fixtures/serialize-deserialize.ts";
import sData from "./fixtures/serialize-only.ts";

// url_test.ts
import {
  assertEquals,
  assertMatch,
  assertThrows,
} from "jsr:@std/assert@1.0.11";

const encoder = new TextEncoder();

Deno.test("should serialize only phc objects", () => {
  sData.deserialized.forEach((_g, i) => {
    assertEquals(serialize(sData.deserialized[i]), sData.serialized[i]);
  });
});

Deno.test("should serialize correct phc objects", () => {
  sdData.deserialized.forEach((_g, i) => {
    assertEquals(
      serialize(sdData.deserialized[i]),
      sdData.serialized[i],
    );
  });
});

Deno.test("should throw errors if trying to serialize with invalid arguments", async (t) => {
  await t.step("opts must be an object", async () => {
    // @ts-expect-error: test null
    const err: Error = await assertThrows(() => serialize(null)) as Error;
    assertEquals(err.message, "opts must be an object");
  });

  await t.step("opts is empty", async () => {
    // @ts-expect-error: test empty
    const err: Error = await assertThrows(() => serialize({})) as Error;
    assertEquals(err.message, "opts is empty");
  });

  await t.step("id must be valid", async () => {
    const err: Error = await assertThrows(() =>
      serialize({ id: "i_n_v_a_l_i_d" })
    ) as Error;
    assertMatch(err.message, /id must satisfy/);
  });

  await t.step("params must be an object", async () => {
    const err: Error = await assertThrows(() =>
      // @ts-expect-error: param null
      serialize({ id: "pbkdf2", params: null })
    ) as Error;
    assertEquals(err.message, "params must be an object");
  });

  await t.step("params values must be strings", async () => {
    const err: Error = await assertThrows(() =>
      // @ts-expect-error: param i null
      serialize({ id: "pbkdf2", params: { i: {} } })
    ) as Error;
    assertMatch(err.message, /params values must satisfy/);
  });

  await t.step("params names must be valid", async () => {
    const err: Error = await assertThrows(() =>
      serialize({ id: "pbkdf2", params: { rounds_: "1000" } })
    ) as Error;
    assertMatch(err.message, /params names must satisfy/);
  });

  await t.step("params values must be valid", async () => {
    const err: Error = await assertThrows(() =>
      serialize({ id: "pbkdf2", params: { rounds: "1000@" } })
    ) as Error;
    assertMatch(err.message, /params values must satisfy/);
  });

  await t.step("salt must be a ArrayBuffer or Uint8Array", async () => {
    const err: Error = await assertThrows(() =>
      // @ts-expect-error: salt
      serialize({ id: "pbkdf2", params: { rounds: "1000" }, salt: "string" })
    ) as Error;
    assertEquals(err.message, "salt must be a ArrayBuffer or Uint8Array");
  });

  await t.step("version must be a positive integer", async () => {
    const err: Error = await assertThrows(() =>
      serialize({ id: "argon2id", version: -10 })
    ) as Error;
    assertEquals(err.message, "version must be a positive integer number");
  });

  await t.step("hash must be a ArrayBuffer or Uint8Array", async () => {
    const err: Error = await assertThrows(() =>
      serialize({
        id: "pbkdf2",
        params: { rounds: "1000" },
        salt: encoder.encode("string"),
        // @ts-expect-error: hash must be ArrayBuffer or Uint8Array
        hash: "string",
      })
    ) as Error;
    assertEquals(err.message, "hash must be a ArrayBuffer or Uint8Array");
  });
});
