# vectorpin (TypeScript)

TypeScript / JavaScript reference implementation of VectorPin, byte-for-byte compatible with the Python and Rust ports.

```bash
npm install vectorpin
```

```ts
import { Signer, Verifier, pinToJSON } from 'vectorpin';

// At ingestion time
const signer = Signer.generate('prod-2026-05');
const embedding = new Float32Array(/* ... 3072 floats from your model ... */);
const pin = await signer.pin({
  source: 'The quick brown fox.',
  model: 'text-embedding-3-large',
  vector: embedding,
});
// Store JSON.stringify-able pin alongside the embedding in your vector DB metadata.
const json = pinToJSON(pin);

// At read/audit time
const verifier = new Verifier({ [signer.keyId]: await signer.publicKeyBytes() });
const result = await verifier.verify(pin, {
  source: 'The quick brown fox.',
  vector: embedding,
});
if (!result.ok) {
  throw new Error(`integrity failure: ${result.error} - ${result.detail}`);
}
```

## Compatibility

This is **protocol v2**. The TypeScript port consumes the same `testvectors/v2.json` and `testvectors/negative_v2.json` fixtures the Python and Rust ports use in CI. A pin produced by any of the three implementations verifies on the other two; canonical bytes and signatures are identical byte-for-byte. v1 pins do not verify under the default verifier; use `LegacyV1Verifier` if you need to validate pre-v2 pins during a migration.

## Runtime support

- Node.js 20+ (requires `globalThis.crypto.getRandomValues`; the test suite uses `node:test`).
- The library has no dependency on Node's `Buffer` or any other Node-only API: base64url and UTF-8 length are implemented in plain JavaScript, and the crypto path is pure JavaScript via [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), so it also works in Deno, Bun, browsers, and Cloudflare Workers.

Vectors: pass a `Float32Array` when your store persists single precision. A `Float64Array` and a plain `number[]` are 64-bit representations; the signer pins them as `f64` by default (pass `vecDtype: 'f32'` to commit to the single-precision rounding), and the verifier refuses them against an `f32` pin rather than narrowing.

## Build & test

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # node:test via tsx
npm run build       # emit dist/
```

## License

Apache 2.0. See `../LICENSE`.
