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

The TypeScript port consumes the same `testvectors/v1.json` and `testvectors/negative_v1.json` fixtures the Python and Rust ports use in CI. A pin produced by any of the three implementations verifies on the other two; canonical bytes and signatures are identical byte-for-byte.

## Runtime support

- Node.js 20+ (uses `Buffer.from(s, 'base64url')` and `globalThis.crypto.getRandomValues`).
- The crypto path is pure JavaScript via [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), so it also works in Deno, Bun, and Cloudflare Workers. Replace the `Buffer.from('base64url')` calls if you target a runtime without `Buffer`.

## Build & test

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # node:test via tsx
npm run build       # emit dist/
```

## License

Apache 2.0. See `../LICENSE`.
