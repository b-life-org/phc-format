import { timingSafeEqual } from "jsr:@std/crypto@^1.0.4";
import { deserialize, serialize } from "../mod.ts";
import { hash } from "jsr:@denosaurs/argontwo@0.2.0";

const encoder = new TextEncoder();

// Store the salt and hash, this could be done with a PHC string or just as is.
// Using a PHC string you would use the `serialize` function to encode it
const salt1 = new Uint8Array(40);
crypto.getRandomValues(salt1);
const hash1 = new Uint8Array(hash(encoder.encode("example password"), salt1));

// Serializing as PHC, this is when you would want to store it in the database
const phc1 = serialize({
  id: "argon2id",
  version: 19,
  params: {
    m: 4096,
    t: 3,
    p: 1,
  },
  salt: salt1,
  hash: hash1,
});

// Deserializing the PHC string, probably directly fetched from a database in a real-life scenario
const { salt: _salt2, hash: hash2 } = deserialize(phc1);

// Using timing safe equal protects against timing based attacks
if (hash2) {
  console.log("equal hash ? ", timingSafeEqual(hash1, hash2 as Uint8Array));
}

// You would probably not compare the `hash1` variable with `hash2` as they should be identical
// Instead you would hash the plaintext password which has been sent in with the deserialized salt
// and compare it with the deserialized hash which you have fetched from the database and earlier
// stored as an PHC string.
