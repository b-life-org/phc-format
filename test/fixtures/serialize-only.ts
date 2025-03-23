import { decodeBase64 } from "@std/encoding";
import { PhcOptions } from "../../mod.ts";

const serialized = [
  "$argon2id$v=19$m=4096,t=3,p=1$is3l4odzaPZ9wfe4FjMJ1vQSHMspqMJQETyy3bwgfLqHZPo6aoUxqw$IwTKxtAEG7E1xyMfhhBC11q6HDG6zM1QmXzBSUU861k",
];

const deserialized: PhcOptions[] = [
  {
    id: "argon2id",
    version: 19,
    params: {
      m: 4096,
      t: 3,
      p: 1,
    },
    salt: decodeBase64(
      "is3l4odzaPZ9wfe4FjMJ1vQSHMspqMJQETyy3bwgfLqHZPo6aoUxqw",
    ),
    hash: decodeBase64(
      "IwTKxtAEG7E1xyMfhhBC11q6HDG6zM1QmXzBSUU861k",
    ),
  },
];

export default { deserialized, serialized };
