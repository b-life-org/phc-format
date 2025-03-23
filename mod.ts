import { decodeBase64, encodeBase64 } from "@std/encoding";

// --- Regular expressions for validation (PHC spec-compliant) ---
const ID_REGEX = /^[a-z0-9-]{1,32}$/;
const NAME_REGEX = /^[a-z0-9-]{1,32}$/;
const VALUE_REGEX = /^[a-zA-Z0-9+.-]+$/;
const BASE64_REGEX = /^([a-zA-Z0-9/+.-]+|)$/;
const VERSION_REGEX = /^v=(\d+)$/;

/**
 * Represents the components of a PHC string.
 */
export interface PhcOptions {
  /** Algorithm identifier (e.g., "argon2id") */
  id: string;
  /** Optional version (e.g., v=19) */
  version?: number;
  /** Optional parameters (e.g., m=65536,t=3,p=4) */
  params?: Record<string, string | number>;
  /** Optional salt (ArrayBuffer | Uint8Array) */
  salt?: ArrayBuffer | Uint8Array;
  /** Optional hash (ArrayBuffer | Uint8Array) */
  hash?: ArrayBuffer | Uint8Array;
}

type Params = Record<string, string | number>;

/**
 * Validates a parameter key.
 * @param key Parameter name.
 */
function validateParamKey(key: string): void {
  if (!NAME_REGEX.test(key)) {
    throw new TypeError(`params names must satisfy ${NAME_REGEX}`);
  }
}

/**
 * Validates a parameter value.
 * @param value Parameter value.
 */
function validateParamValue(value: string | number): void {
  if (typeof value === "number") return;
  if (!VALUE_REGEX.test(value)) {
    throw new TypeError(`params values must satisfy ${VALUE_REGEX}`);
  }
}

/**
 * Serializes parameters to a PHC-compliant string.
 * @param params Key-value pairs.
 * @returns e.g., "m=65536,t=3,p=4"
 */
function serializeParams(params: Params | undefined): string {
  if (typeof params !== "object" || params === null) {
    throw new TypeError("params must be an object");
  }

  if (Object.keys(params).length === 0) {
    throw new TypeError("opts is empty");
  }

  return Object.entries(params)
    .map(([key, val]) => {
      validateParamKey(key);
      validateParamValue(val);
      return `${key}=${val}`;
    })
    .join(",");
}

/**
 * Parses a PHC param string into a key-value object.
 * @param str e.g., "m=65536,t=3,p=4"
 * @returns Parsed params object.
 */
function deserializeParams(str: string): Params {
  const result: Params = {};
  str.split(",").forEach((entry) => {
    const [key, ...rest] = entry.split("=");
    if (!key || rest.length === 0) {
      throw new TypeError(
        `params must be in the format name=value`,
      );
    }
    if (!VALUE_REGEX.test(key)) {
      throw new TypeError(`params names must satisfy ${NAME_REGEX}`);
    }
    const value = rest.join("=");
    if (!VALUE_REGEX.test(value)) {
      throw new TypeError(`params values must satisfy ${VALUE_REGEX}`);
    }

    // Attempt numeric conversion if it's a valid number
    const num = Number(value);
    result[key] = isNaN(num) ? value : num;
  });
  return result;
}

/**
 * Serializes a PHC object into a PHC string.
 * @param opts PHC components (id, version, params, salt, hash)
 * @returns PHC string e.g. $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
 */
export function serialize(opts: PhcOptions): string {
  if (typeof opts !== "object" || opts === null) {
    throw new TypeError("opts must be an object");
  }

  if (Object.keys(opts).length === 0) {
    throw new TypeError("opts is empty");
  }

  if (typeof opts.id !== "string") {
    throw new TypeError("id must be a string");
  }

  if (!ID_REGEX.test(opts.id)) {
    throw new TypeError(`id must satisfy ${ID_REGEX}`);
  }

  const parts = [`$${opts.id}`];

  if ("version" in opts) {
    if (
      typeof opts.version !== "number" ||
      opts.version < 0 ||
      !Number.isInteger(opts.version)
    ) {
      throw new TypeError("version must be a positive integer number");
    }

    parts.push(`$v=${opts.version}`);
  }

  if ("params" in opts) {
    parts.push(`$${serializeParams(opts.params)}`);
  }

  if ("salt" in opts && opts.salt) {
    // Salt Validation
    if (
      !(opts.salt instanceof ArrayBuffer || opts.salt instanceof Uint8Array)
    ) {
      throw new TypeError("salt must be a ArrayBuffer or Uint8Array");
    }
    // PHC format doesn't expect `=` in base64
    parts.push(`$${encodeBase64(opts.salt).split("=")[0]}`);

    if ("hash" in opts && opts.hash) {
      // Hash Validation
      if (
        !(opts.hash instanceof ArrayBuffer || opts.hash instanceof Uint8Array)
      ) {
        throw new TypeError("hash must be a ArrayBuffer or Uint8Array");
      }
      // PHC format doesn't expect `=` in base64
      parts.push(`$${encodeBase64(opts.hash).split("=")[0]}`);
    }
  }

  return parts.join("");
}

/**
 * Parses a PHC string into an object.
 *   ```
 *    $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
 *    ```
 * @param phcStr PHC-formatted string.
 * @returns Parsed PHC components as object.
 */
export function deserialize(phcStr: string): PhcOptions {
  if (phcStr === null || phcStr === "" || typeof phcStr !== "string") {
    throw new TypeError("PHC string must be a non-empty string");
  }
  if (phcStr[0] !== "$") {
    throw new TypeError("PHC string must start with '$'");
  }

  // Remove first empty $ with slice
  const parts = phcStr.split("$").slice(1);
  const numFields = parts.length;

  if (numFields < 1) {
    throw new TypeError("PHC string must contain at least an id");
  }

  // Parse Fields
  let maxf = 5;
  if (!VERSION_REGEX.test(parts[1])) maxf--;
  if (parts.length > maxf) {
    throw new TypeError(
      `PHC string contains too many fields: ${parts.length}/${maxf}`,
    );
  }

  if (numFields > 5) {
    throw new TypeError(`PHC string contains too many fields: ${numFields}/5`);
  }

  const [id, ...fields] = parts;

  if (!ID_REGEX.test(id)) {
    throw new TypeError(`id must satisfy ${ID_REGEX}`);
  }

  const result: PhcOptions = { id };

  // Optional version
  if (VERSION_REGEX.test(fields[0])) {
    const [, versionStr] = fields.shift()?.match(VERSION_REGEX)!;
    result.version = parseInt(versionStr, 10);
  }

  // Decode Salt before param
  if (BASE64_REGEX.test(fields[fields.length - 1])) {
    if (fields.length > 1 && BASE64_REGEX.test(fields[fields.length - 2])) {
      // Parse Hash
      result.hash = decodeBase64(fields.pop() as string);
      // Parse Salt
      result.salt = decodeBase64(fields.pop() as string);
    } else {
      // Parse Salt
      result.salt = decodeBase64(fields.pop() as string);
    }
  }
  // Parse Parameters
  if (fields.length > 0) {
    result.params = deserializeParams(fields.pop() as string);
  }

  if (fields.length > 0) {
    throw new TypeError(`PHC string contains unrecognized fields: ${fields}`);
  }

  return result;
}
