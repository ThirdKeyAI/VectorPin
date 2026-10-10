// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Regression tests for the security-review fixes. Each block names the
// finding it pins down and fails on the pre-fix code:
//   VP-1  precision widening (f64 low-bit channel)
//   VP-5  trustedTime binds the revocation window
//   VP-6  lone surrogates rejected; verify() never throws
//   VP-9  calendar validation of ts
//   VP-10 expectedModelHash
//   VP-12 strict canonical base64url
//   VP-13 integer literals for v / vec_dim; extra: null rejected
//   VP-14 kid / model byte caps on the dict path
//   VP-18 Buffer-free base64url codec
// plus VectorSmuggle-style perturbations and fast-check properties.

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import fc from 'fast-check';

import {
  b64UrlDecodeNoPad,
  b64UrlEncodeNoPad,
  isValidCalendarTs,
  MAX_KID_BYTES,
  MAX_MODEL_BYTES,
  pinFromDict,
  pinFromJSON,
  pinToJSON,
  utf8ByteLength,
  type Pin,
} from '../src/attestation.js';
import { canonicalVectorBytes, hashText } from '../src/hash.js';
import { Signer } from '../src/signer.js';
import { Verifier, VerifyErrorCode } from '../src/verifier.js';

async function world() {
  const signer = Signer.fromPrivateBytes(new Uint8Array(32).fill(9), 'k');
  const verifier = new Verifier({ k: await signer.publicKeyBytes() });
  return { signer, verifier };
}

function f64Vector(dim: number, seed = 1): Float64Array {
  // Deterministic xorshift-derived values in (-1, 1).
  let x = BigInt(0x9e3779b9) + BigInt(seed);
  const out = new Float64Array(dim);
  for (let i = 0; i < dim; i++) {
    x ^= (x << 13n) & 0xffffffffffffffffn;
    x ^= x >> 7n;
    x ^= (x << 17n) & 0xffffffffffffffffn;
    out[i] = (Number((x >> 11n) & 0x1fffffffffffffn) / 2 ** 53) * 2 - 1;
  }
  return out;
}

/** Rewrite bits 0..27 of every element; the f32 rounding is unchanged. */
function hidePayloadInLowBits(v: Float64Array): Float64Array {
  const out = new Float64Array(v);
  const bits = new BigUint64Array(out.buffer);
  let seed = 42n;
  for (let i = 0; i < bits.length; i++) {
    seed = (seed * 6364136223846793005n + 1n) & 0xffffffffffffffffn;
    let payload = (seed >> 36n) & ((1n << 28n) - 1n);
    if (payload === 0n) payload = 1n;
    bits[i] = (bits[i]! & ~((1n << 28n) - 1n)) | payload;
  }
  for (let i = 0; i < v.length; i++) {
    assert.equal(Math.fround(out[i]!), Math.fround(v[i]!), 'f32 rounding preserved');
  }
  assert.notDeepEqual(Array.from(out), Array.from(v));
  return out;
}

function withField(json: string, field: string, value: unknown): Record<string, unknown> {
  const d = JSON.parse(json) as Record<string, unknown>;
  d[field] = value;
  return d;
}

// ---- VP-1 -------------------------------------------------------------------

describe('VP-1: precision widening is rejected', () => {
  it('f64 low-bit channel against an f32 pin is rejected', async () => {
    const { signer, verifier } = await world();
    const v64 = f64Vector(3072);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v64, vecDtype: 'f32' });
    assert.equal(pin.header.vec_dtype, 'f32');
    const smuggled = hidePayloadInLowBits(v64);
    const r = await verifier.verify(pin, { vector: smuggled });
    assert.equal(r.ok, false);
    assert.equal(r.error, VerifyErrorCode.SHAPE_MISMATCH);
    assert.match(r.detail, /64-bit/);
    // The untouched f64 input is refused too; the f32 the store persists passes.
    assert.equal((await verifier.verify(pin, { vector: v64 })).error, VerifyErrorCode.SHAPE_MISMATCH);
    assert.equal((await verifier.verify(pin, { vector: new Float32Array(v64) })).ok, true);
  });

  it('number[] is a 64-bit representation and is refused against an f32 pin', async () => {
    const { signer, verifier } = await world();
    const v32 = new Float32Array([0.1, 0.2, 0.3]);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v32 });
    const r = await verifier.verify(pin, { vector: Array.from(v32) });
    assert.equal(r.error, VerifyErrorCode.SHAPE_MISMATCH);
    assert.equal((await verifier.verify(pin, { vector: v32 })).ok, true);
  });

  it('an f64 pin catches the low-bit modification as VECTOR_TAMPERED', async () => {
    const { signer, verifier } = await world();
    const v64 = f64Vector(256);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v64 });
    assert.equal(pin.header.vec_dtype, 'f64');
    const r = await verifier.verify(pin, { vector: hidePayloadInLowBits(v64) });
    assert.equal(r.error, VerifyErrorCode.VECTOR_TAMPERED);
    assert.equal((await verifier.verify(pin, { vector: v64 })).ok, true);
  });

  it('signer defaults to the native dtype', async () => {
    const { signer } = await world();
    assert.equal(
      (await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) })).header.vec_dtype,
      'f32',
    );
    assert.equal(
      (await signer.pin({ source: 's', model: 'm', vector: new Float64Array([1]) })).header.vec_dtype,
      'f64',
    );
    assert.equal((await signer.pin({ source: 's', model: 'm', vector: [1] })).header.vec_dtype, 'f64');
  });

  it('narrower than pinned is allowed', async () => {
    const { signer, verifier } = await world();
    const v32 = new Float32Array([0.1, 0.2]);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v32, vecDtype: 'f64' });
    assert.equal((await verifier.verify(pin, { vector: v32 })).ok, true);
  });

  it('VECTOR_TAMPERED detail hints at a dtype mismatch', async () => {
    const { signer, verifier } = await world();
    const v64 = f64Vector(8);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v64 });
    const r = await verifier.verify(pin, { vector: new Float32Array(v64) });
    assert.equal(r.error, VerifyErrorCode.VECTOR_TAMPERED);
    assert.match(r.detail, /vecDtype: 'f32'/);
  });
});

// ---- VP-5 -------------------------------------------------------------------

describe('VP-5: trustedTime binds the revocation window', () => {
  it('backdated forgery is rejected when the ingestion time is trusted', async () => {
    const signer = Signer.generate('k');
    const verifier = new Verifier({
      k: { publicKey: await signer.publicKeyBytes(), validUntil: new Date('2026-06-01T00:00:00Z') },
    });
    const forged = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([1]),
      timestamp: '2026-05-01T00:00:00Z',
    });
    assert.equal((await verifier.verify(forged)).ok, true, 'the documented limitation');
    const r = await verifier.verify(forged, { trustedTime: new Date('2026-07-01T00:00:00Z') });
    assert.equal(r.error, VerifyErrorCode.KEY_EXPIRED);
    const r2 = await verifier.verify(forged, { trustedTime: new Date('2026-04-01T00:00:00Z') });
    assert.equal(r2.error, VerifyErrorCode.KEY_EXPIRED);
    assert.match(r2.detail, /postdates/);
    assert.equal(
      (await verifier.verify(forged, { trustedTime: new Date('2026-05-02T00:00:00Z') })).ok,
      true,
    );
  });
});

// ---- VP-6 -------------------------------------------------------------------

describe('VP-6: lone surrogates', () => {
  it('are rejected by the parser on every string field', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    for (const field of ['model', 'kid']) {
      assert.throws(() => pinFromDict(withField(json, field, 'x\ud800')), /surrogate/);
    }
    assert.throws(() => pinFromDict(withField(json, 'extra', { k: '\udfff' })), /surrogate/);
    assert.throws(() => pinFromJSON(json.replace('"model":"m"', '"model":"\\ud800"')), /surrogate/);
  });

  it('are rejected by the signer', async () => {
    const { signer } = await world();
    const vector = new Float32Array([1]);
    await assert.rejects(signer.pin({ source: 's', model: 'm\ud800', vector }), /surrogate/);
    await assert.rejects(signer.pin({ source: 's\ud800', model: 'm', vector }), /surrogate/);
    await assert.rejects(
      signer.pin({ source: 's', model: 'm', vector, extra: { k: '\ud800' } }),
      /surrogate/,
    );
  });

  it('hashText refuses them instead of substituting U+FFFD', () => {
    assert.throws(() => hashText('a\ud800b'), /surrogate/);
    assert.notEqual(hashText('a�b'), undefined);
  });

  it('verify() never throws on a hostile header', async () => {
    const { verifier, signer } = await world();
    const good = await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) });
    const hostile: Pin = { header: { ...good.header, model: '\ud800' }, sig: good.sig };
    const r = await verifier.verify(hostile);
    assert.equal(r.ok, false);
    assert.equal(r.error, VerifyErrorCode.PARSE_ERROR);
    const r2 = await verifier.verify(good, { source: 's\ud800' });
    assert.equal(r2.error, VerifyErrorCode.PARSE_ERROR);
    // A vector that is not a vector at all.
    const r3 = await verifier.verify(good, { vector: 'nope' as unknown as number[] });
    assert.equal(r3.error, VerifyErrorCode.SHAPE_MISMATCH);
  });
});

// ---- VP-9 -------------------------------------------------------------------

describe('VP-9: calendar validation', () => {
  const bad = [
    '2026-03-00T00:00:00Z',
    '2026-13-01T00:00:00Z',
    '2026-00-10T00:00:00Z',
    '2026-02-30T00:00:00Z',
    '2025-02-29T00:00:00Z',
    '2026-04-31T00:00:00Z',
    '2026-05-05T24:00:00Z',
    '2026-05-05T12:60:00Z',
    '2026-05-05T12:00:60Z',
  ];
  it('rejects impossible dates at parse time', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    for (const ts of bad) {
      assert.equal(isValidCalendarTs(ts), false, ts);
      assert.throws(() => pinFromDict(withField(json, 'ts', ts)), /calendar/, ts);
    }
    assert.equal(isValidCalendarTs('2024-02-29T23:59:59Z'), true);
  });

  it('rejects a rolled-over date in the validity-window path too', async () => {
    const signer = Signer.generate('k');
    const verifier = new Verifier({
      k: { publicKey: await signer.publicKeyBytes(), validFrom: new Date(0) },
    });
    const good = await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) });
    const rolled: Pin = { header: { ...good.header, ts: '2026-02-30T00:00:00Z' }, sig: good.sig };
    const r = await verifier.verify(rolled);
    assert.equal(r.error, VerifyErrorCode.KEY_EXPIRED);
  });
});

// ---- VP-10 ------------------------------------------------------------------

describe('VP-10: expectedModelHash', () => {
  it('is enforced', async () => {
    const { signer, verifier } = await world();
    const good = 'sha256:' + 'a'.repeat(64);
    const bad = 'sha256:' + 'b'.repeat(64);
    const vector = new Float32Array([1, 2]);
    const pin = await signer.pin({ source: 's', model: 'm', vector, modelHash: good });
    assert.equal((await verifier.verify(pin, { expectedModelHash: good })).ok, true);
    assert.equal(
      (await verifier.verify(pin, { expectedModelHash: bad })).error,
      VerifyErrorCode.MODEL_MISMATCH,
    );
    const noHash = await signer.pin({ source: 's', model: 'm', vector });
    assert.equal(
      (await verifier.verify(noHash, { expectedModelHash: good })).error,
      VerifyErrorCode.MODEL_MISMATCH,
    );
  });
});

// ---- VP-12 / VP-18 ----------------------------------------------------------

describe('VP-12 / VP-18: strict Buffer-free base64url', () => {
  it('round-trips and matches the canonical encoding', () => {
    for (const len of [0, 1, 2, 3, 4, 31, 32, 33, 63, 64, 65]) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
      const enc = b64UrlEncodeNoPad(bytes);
      assert.doesNotMatch(enc, /[=+/]/);
      assert.deepEqual(Array.from(b64UrlDecodeNoPad(enc)), Array.from(bytes), `len ${len}`);
    }
    // Known vector: 0xfb 0xff -> "-_8" in the URL-safe alphabet.
    assert.equal(b64UrlEncodeNoPad(new Uint8Array([0xfb, 0xff])), '-_8');
  });

  it('rejects padding, standard alphabet, bad length, and trailing bits', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    const sig = (JSON.parse(json) as { sig: string }).sig;
    assert.throws(() => pinFromDict(withField(json, 'sig', sig + '==')), /base64url/);
    assert.throws(() => pinFromDict(withField(json, 'sig', sig.slice(0, -1) + '+')), /base64url/);
    assert.throws(() => b64UrlDecodeNoPad('AAAAA'), /length/);
    // 64 zero bytes encode to 85 'A's + 'A'; 'B' sets a trailing bit.
    assert.throws(() => pinFromDict(withField(json, 'sig', 'A'.repeat(85) + 'B')), /trailing/);
    assert.equal(b64UrlDecodeNoPad('A'.repeat(86)).length, 64);
  });

  it('does not reference Node Buffer anywhere in the library', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const url = await import('node:url');
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    for (const f of ['attestation.ts', 'hash.ts', 'signer.ts', 'verifier.ts', 'index.ts']) {
      const src = fs.readFileSync(path.join(here, '..', 'src', f), 'utf8');
      // Usage, not mentions: `Buffer.from(...)`, `Buffer.byteLength(...)`.
      assert.doesNotMatch(src, /\bBuffer\s*[.(]/, f);
    }
  });
});

// ---- VP-13 ------------------------------------------------------------------

describe('VP-13: integer parsing parity', () => {
  it('rejects non-integer literals for v and vec_dim in JSON text', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    assert.throws(() => pinFromJSON(json.replace('"v":2', '"v":2.0')), /minimal integer/);
    assert.throws(() => pinFromJSON(json.replace('"v":2', '"v":2e0')), /minimal integer/);
    assert.throws(() => pinFromJSON(json.replace('"vec_dim":1', '"vec_dim":1.0')), /minimal integer/);
    // An extra *value* "2.0" (a string) is fine; only number literals are refused.
    const withExtra = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([1]),
      extra: { v: '2.0' },
    });
    assert.ok(pinFromJSON(pinToJSON(withExtra)));
  });

  it('rejects extra: null', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    assert.throws(() => pinFromDict(withField(json, 'extra', null)), /pin.extra/);
  });
});

// ---- VP-14 ------------------------------------------------------------------

describe('VP-14: byte caps on the dict path', () => {
  it('rejects oversize model and kid before normalization', async () => {
    const { signer } = await world();
    const json = pinToJSON(await signer.pin({ source: 's', model: 'm', vector: new Float32Array([1]) }));
    assert.throws(
      () => pinFromDict(withField(json, 'model', 'x'.repeat(MAX_MODEL_BYTES + 1))),
      /model exceeds/,
    );
    assert.throws(() => pinFromDict(withField(json, 'kid', 'k'.repeat(MAX_KID_BYTES + 1))), /kid exceeds/);
    // Bytes, not code units: 600 x U+00E9 is 1200 bytes.
    assert.throws(() => pinFromDict(withField(json, 'model', 'é'.repeat(600))), /model exceeds/);
    assert.equal(utf8ByteLength('é'), 2);
  });
});

// ---- VectorSmuggle-style perturbations -------------------------------------

describe('adversarial perturbations are detected', () => {
  it('noise, scaling, offset, LSB flips, and element swaps all fail', async () => {
    const { signer, verifier } = await world();
    const base = new Float32Array(f64Vector(256));
    const pin = await signer.pin({ source: 's', model: 'm', vector: base });
    const flipLsb = (v: Float32Array, all: boolean) => {
      const out = new Float32Array(v);
      const u = new Uint32Array(out.buffer);
      for (let i = 0; i < (all ? u.length : 1); i++) u[i] = u[i]! ^ 1;
      return out;
    };
    const cases: Record<string, Float32Array> = {
      'noise_1e-3': base.map((x) => x + 1e-3),
      'noise_1e-5': base.map((x) => x + 1e-5),
      scaling: base.map((x) => x * 1.0001),
      offset: base.map((x) => x + 1e-4),
      lsb_one: flipLsb(base, false),
      lsb_all: flipLsb(base, true),
      swap: (() => {
        const v = new Float32Array(base);
        [v[0], v[1]] = [v[1]!, v[0]!];
        return v;
      })(),
    };
    for (const [name, perturbed] of Object.entries(cases)) {
      assert.notDeepEqual(Array.from(perturbed), Array.from(base), name);
      const r = await verifier.verify(pin, { vector: perturbed });
      assert.equal(r.error, VerifyErrorCode.VECTOR_TAMPERED, name);
    }
    assert.equal((await verifier.verify(pin, { vector: base })).ok, true);
  });
});

// ---- property tests ---------------------------------------------------------

describe('canonical bytes properties (fast-check)', () => {
  it('f32 bytes are the little-endian concatenation of each element', () => {
    fc.assert(
      fc.property(fc.array(fc.float({ noNaN: true, noDefaultInfinity: true }), { minLength: 1, maxLength: 64 }), (xs) => {
        const v = new Float32Array(xs);
        const expected = new Uint8Array(v.length * 4);
        const dv = new DataView(expected.buffer);
        for (let i = 0; i < v.length; i++) dv.setFloat32(i * 4, v[i]!, true);
        assert.deepEqual(Array.from(canonicalVectorBytes(v, 'f32')), Array.from(expected));
      }),
    );
  });

  it('f64 -> f32 cast is Math.fround (round-to-nearest-even)', () => {
    fc.assert(
      fc.property(
        fc.array(fc.double({ noNaN: true, noDefaultInfinity: true, min: -1e30, max: 1e30 }), {
          minLength: 1,
          maxLength: 64,
        }),
        (xs) => {
          const v = new Float64Array(xs);
          const expected = new Uint8Array(v.length * 4);
          const dv = new DataView(expected.buffer);
          for (let i = 0; i < v.length; i++) dv.setFloat32(i * 4, Math.fround(v[i]!), true);
          assert.deepEqual(Array.from(canonicalVectorBytes(v, 'f32')), Array.from(expected));
        },
      ),
    );
  });

  it('base64url round-trips arbitrary bytes canonically', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 128 }), (bytes) => {
        const enc = b64UrlEncodeNoPad(bytes);
        assert.deepEqual(Array.from(b64UrlDecodeNoPad(enc)), Array.from(bytes));
      }),
    );
  });

  it('pins round-trip through JSON and verify', async () => {
    const { signer, verifier } = await world();
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-zA-Z0-9 _.-]{1,32}$/),
        fc.string({ maxLength: 64 }),
        fc.array(fc.float({ noNaN: true, noDefaultInfinity: true }), { minLength: 1, maxLength: 16 }),
        async (model, source, xs) => {
          const vector = new Float32Array(xs);
          const pin = await signer.pin({ source, model, vector, extra: { 'vectorpin.record_id': 'r' } });
          const back = pinFromJSON(pinToJSON(pin));
          assert.equal(pinToJSON(back), pinToJSON(pin));
          const r = await verifier.verify(back, { source, vector, expectedRecordId: 'r' });
          assert.equal(r.ok, true, r.detail);
        },
      ),
      { numRuns: 40 },
    );
  });
});
