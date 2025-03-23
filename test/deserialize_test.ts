import { deserialize } from "../mod.ts";
import sdData from "./fixtures/serialize-deserialize.ts";
import sData from "./fixtures/serialize-only.ts";

import {
  assertEquals,
  assertMatch,
  assertObjectMatch,
  assertThrows,
} from "jsr:@std/assert@1.0.11";

Deno.test("should deserialize correct phc strings", () => {
  sdData.serialized.forEach((_g, i) => {
    assertObjectMatch(
      deserialize(sdData.serialized[i]),
      // @ts-expect-error : type
      sdData.deserialized[i],
    );
  });
});

Deno.test("should thow errors if trying to deserialize an invalid phc string", async (t) => {
  await t.step("PHC string must be a non-empty string", async () => {
    // @ts-expect-error : test null
    const err: Error = await assertThrows(() => deserialize(null)) as Error;
    assertEquals(err.message, "PHC string must be a non-empty string");
  });

  await t.step("PHC string must start with '$'", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("a$invalid")
    ) as Error;
    assertEquals(err.message, "PHC string must start with '$'");
  });

  await t.step("PHC string contains too many fields:", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$b$c$d$e$f")
    ) as Error;
    assertMatch(err.message, /PHC string contains too many fields:/);
  });

  await t.step("PHC string must start with '$'", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("invalid")
    ) as Error;
    assertEquals(err.message, "PHC string must start with '$'");
  });

  await t.step("id must satisfy", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$i_n_v_a_l_i_d")
    ) as Error;
    assertMatch(err.message, /id must satisfy/);
  });

  await t.step("params names must satisfy", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$pbkdf2$rounds_=1000")
    ) as Error;
    assertMatch(err.message, /params names must satisfy/);
  });

  await t.step("params values must satisfy", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$pbkdf2$rounds=1000@")
    ) as Error;
    assertMatch(err.message, /params values must satisfy/);
  });

  await t.step("params must be in the format name=value", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$pbkdf2$rounds:1000")
    ) as Error;
    assertMatch(err.message, /params must be in the format name=value/);
  });

  await t.step("PHC string contains unrecognized fields", async () => {
    const err: Error = await assertThrows(() =>
      deserialize("$argon2i$unrecognized$m=120,t=5000,p=2$EkCWX6pSTqWruiR0")
    ) as Error;
    assertMatch(err.message, /PHC string contains unrecognized fields/);
  });

  await t.step("PHC string contains too many fields: 5/4", async () => {
    const err: Error = await assertThrows(() =>
      deserialize(
        "$argon2i$unrecognized$v=19$m=120,t=5000,p=2$EkCWX6pSTqWruiR0",
      )
    ) as Error;
    assertEquals(err.message, "PHC string contains too many fields: 5/4");
  });

  await t.step("PHC string contains unrecognized fields", async () => {
    const err: Error = await assertThrows(() =>
      deserialize(
        "$argon2i$v=19$unrecognized$m=120,t=5000,p=2$EkCWX6pSTqWruiR0",
      )
    ) as Error;
    assertMatch(err.message, /PHC string contains unrecognized fields/);
  });
});
