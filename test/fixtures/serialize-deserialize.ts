import { decodeBase64 } from "@std/encoding";
import { PhcOptions } from "../../mod.ts";

const serialized = [
  "$argon2i$m=120,t=5000,p=2",
  "$argon2i$m=120,t=4294967295,p=2",
  "$argon2i$m=2040,t=5000,p=255",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQ",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQA",
  "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",

  "$argon2i$m=120,t=5000,p=2$/LtFjH5rVL8",
  "$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI",
  "$argon2i$m=120,t=5000,p=2$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI",
  "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",

  "$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
  "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$EkCWX6pSTqWruiR0",
  "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
  "$scrypt$ln=1,r=16,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEL80Aad7QlI+DJqdToPyB8X6NPg+y4NNijPNeIMONGJBg",
  "$argon2i$v=19$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
];

const deserialized: PhcOptions[] = [
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2 },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 4294967295, p: 2 },
  },
  {
    id: "argon2i",
    params: { m: 2040, t: 5000, p: 255 },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, keyid: "Hj5+dsK0" },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, keyid: "Hj5+dsK0ZQ" },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, keyid: "Hj5+dsK0ZQA" },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, data: "sRlHhRmKUGzdOmXn01XmXygd5Kc" },
  },
  {
    id: "argon2i",
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2 },
    salt: decodeBase64("/LtFjH5rVL8"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2 },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2 },
    salt: decodeBase64(
      "BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
    ),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, keyid: "Hj5+dsK0" },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, data: "sRlHhRmKUGzdOmXn01XmXygd5Kc" },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
  },
  {
    id: "argon2i",
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2 },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
    hash: decodeBase64("iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, keyid: "Hj5+dsK0" },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
    hash: decodeBase64("iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM"),
  },
  {
    id: "argon2i",
    params: { m: 120, t: 5000, p: 2, data: "sRlHhRmKUGzdOmXn01XmXygd5Kc" },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
    hash: decodeBase64("iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM"),
  },
  {
    id: "argon2i",
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
    salt: decodeBase64("4fXXG0spB92WPB1NitT8/OH0VKI"),
    hash: decodeBase64("iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM"),
  },
  {
    id: "argon2i",
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
    salt: decodeBase64("iHSDPHzUhPzK7rCcJgOFfg"),
    hash: decodeBase64("EkCWX6pSTqWruiR0"),
  },
  {
    id: "argon2i",
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
    salt: decodeBase64("iHSDPHzUhPzK7rCcJgOFfg"),
    hash: decodeBase64(
      "J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
    ),
  },
  {
    id: "scrypt",
    params: {
      ln: 1,
      r: 16,
      p: 1,
    },
    salt: new Uint8Array(),
    hash: decodeBase64(
      "d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEL80Aad7QlI+DJqdToPyB8X6NPg+y4NNijPNeIMONGJBg",
    ),
  },
  {
    id: "argon2i",
    version: 19,
    params: {
      m: 120,
      t: 5000,
      p: 2,
      keyid: "Hj5+dsK0",
      data: "sRlHhRmKUGzdOmXn01XmXygd5Kc",
    },
    salt: decodeBase64("iHSDPHzUhPzK7rCcJgOFfg"),
    hash: decodeBase64(
      "J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
    ),
  },
];

export default { deserialized, serialized };
