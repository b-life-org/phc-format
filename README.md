# phc-format

Fork from https://github.com/simonepri/phc-format/", "author": "Simone Primarosa
(https://simoneprimarosa.com)",

## Motivation

The [PHC String Format][specs:phc] is an attempt to specify a common hash string
format that's a restricted & well defined subset of the Modular Crypt Format.
New hashes are strongly encouraged to adhere to the PHC specification, rather
than the much looser [Modular Crypt Format][specs:mcf].

## Install

### Deno

```bash
deno add @b-life-org/phc-format
```

### Node

```bash
npx jsr add @b-life-org/phc-format
yarn dlx jsr add @b-life-org/phc-format
pnpm dlx jsr add @b-life-org/phc-format
```

### Bun

```bash
bunx jsr add @b-life-org/phc-format
```

## Usage

```ts
import { deserialize, serialize } from "@b-life-org/phc-format";
export { decodeBase64, encodeBase64 } from "jsr:@std/encoding@^1.0.7/base64";


const phcobj = {
    id: "argon2id",
    // version parameter is optional
    version: 19,
    params: {
      m: 4096,
      t: 3,
      p: 1,
    },
    salt: decodeBase64(
      "is3l4odzaPZ9wfe4FjMJ1vQSHMspqMJQETyy3bwgfLqHZPo6aoUxqw==",
    ),
    hash: decodeBase64(
      "IwTKxtAEG7E1xyMfhhBC11q6HDG6zM1QmXzBSUU861k=",
    ),
  };

const phcstr =
  "$argon2id$v=19$m=4096,t=3,p=1$is3l4odzaPZ9wfe4FjMJ1vQSHMspqMJQETyy3bwgfLqHZPo6aoUxqw==$IwTKxtAEG7E1xyMfhhBC11q6HDG6zM1QmXzBSUU861k=",

serialize(phcobj);
// => phcstr

deserialize(phcstr);
// => phcobj
```

## API

#### TOC

<dl>
<dt><a href="#serialize">serialize(opts)</a> ⇒ <code>string</code></dt>
<dd><p>Generates a PHC string using the data provided.</p>
</dd>
<dt><a href="#deserialize">deserialize(phcstr)</a> ⇒ <code>Object</code></dt>
<dd><p>Parses data from a PHC string.</p>
</dd>
</dl>

<a name="serialize"></a>

### serialize(opts) ⇒ <code>string</code>

Generates a PHC string using the data provided.

**Kind**: global function\
**Returns**: <code>string</code> - The hash string adhering to the PHC format.

| Param          | Type                    | Description                                                   |
| -------------- | ----------------------- | ------------------------------------------------------------- |
| opts           | <code>Object</code>     | Object that holds the data needed to generate the PHC string. |
| opts.id        | <code>string</code>     | Symbolic name for the function.                               |
| [opts.version] | <code>Number</code>     | The version of the function.                                  |
| [opts.params]  | <code>Object</code>     | Parameters of the function.                                   |
| [opts.salt]    | <code>Uint8Array</code> | The salt as a Uint8Array.                                     |
| [opts.hash]    | <code>Uint8Array</code> | The hash as a Uint8Array.                                     |

<a name="deserialize"></a>

### deserialize(phcstr) ⇒ <code>Object</code>

Parses data from a PHC string.

**Kind**: global function\
**Returns**: <code>Object</code> - The object containing the data parsed from
the PHC string.

| Param  | Type                | Description            |
| ------ | ------------------- | ---------------------- |
| phcstr | <code>string</code> | A PHC string to parse. |

## Contributing

## Authors

Original

- **Simone Primarosa** - _Github_ ([@simonepri][github:simonepri])

## License

This project is licensed under the MIT License - see the [LICENSE][LICENSE] file
for details.

<!-- Links -->

[specs:mcf]: https://github.com/ademarre/binary-mcf
[specs:phc]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
