// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v2-specific canonicalization behavior.
//
// These tests are independent of the cross-language fixtures —
// they exercise the wire-format rules in isolation so a regression
// in (e.g.) the NFC check is caught even if the v2.json fixtures
// happen to not stress that code path.

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  canonicalizeHeader,
  DOMAIN_TAG,
  MAX_EXTRA_ENTRIES,
  MAX_PIN_JSON_BYTES,
  MAX_VEC_DIM,
  pinFromJSON,
  PROTOCOL_VERSION,
  type PinHeader,
} from '../src/attestation.js';
import { Signer } from '../src/signer.js';

function baseHeader(): PinHeader {
  return {
    v: PROTOCOL_VERSION,
    kid: 'k1',
    model: 'm',
    source_hash: 'sha256:' + 'a'.repeat(64),
    vec_hash: 'sha256:' + 'b'.repeat(64),
    vec_dtype: 'f32',
    vec_dim: 3,
    ts: '2026-05-13T12:00:00Z',
  };
}

describe('DOMAIN_TAG', () => {
  it('is exactly 13 bytes', () => {
    assert.equal(DOMAIN_TAG.length, 13);
  });

  it('spells "vectorpin/v2\\x00"', () => {
    const expected = [
      118, 101, 99, 116, 111, 114, 112, 105, 110, 47, 118, 50, 0,
    ];
    assert.deepEqual(Array.from(DOMAIN_TAG), expected);
  });
});

describe('canonicalizeHeader (v2)', () => {
  it('prepends DOMAIN_TAG to the canonical JSON', () => {
    const bytes = canonicalizeHeader(baseHeader());
    assert.deepEqual(Array.from(bytes.slice(0, 13)), Array.from(DOMAIN_TAG));
  });

  it('includes kid in the signed JSON body', () => {
    const bytes = canonicalizeHeader(baseHeader());
    const json = new TextDecoder().decode(bytes.slice(13));
    const parsed = JSON.parse(json) as Record<string, unknown>;
    assert.equal(parsed['kid'], 'k1');
    assert.equal(parsed['v'], 2);
  });

  it('rejects non-NFC strings at canonicalize time', () => {
    // "café" with combining acute (NFD form).
    const nfd = 'café';
    assert.throws(() =>
      canonicalizeHeader({ ...baseHeader(), model: nfd }),
    );
  });

  it('sorts extra keys after NFC normalization', () => {
    const header: PinHeader = {
      ...baseHeader(),
      extra: { z: '1', a: '2', m: '3' },
    };
    const bytes = canonicalizeHeader(header);
    const json = new TextDecoder().decode(bytes.slice(13));
    // Keys appear in lexicographic order in the JSON output.
    const aIdx = json.indexOf('"a"');
    const mIdx = json.indexOf('"m"');
    const zIdx = json.indexOf('"z"');
    assert.ok(aIdx >= 0 && aIdx < mIdx && mIdx < zIdx);
  });
});

describe('pinFromJSON rejects v2 wire-format violations', () => {
  function pinWith(overrides: Record<string, unknown>): string {
    const obj: Record<string, unknown> = {
      v: 2,
      kid: 'k1',
      model: 'm',
      source_hash: 'sha256:' + 'a'.repeat(64),
      vec_hash: 'sha256:' + 'b'.repeat(64),
      vec_dtype: 'f32',
      vec_dim: 3,
      ts: '2026-05-13T12:00:00Z',
      sig: 'A'.repeat(86), // 64 bytes -> 86 base64url chars
      ...overrides,
    };
    return JSON.stringify(obj);
  }

  it('rejects unknown top-level field', () => {
    assert.throws(() => pinFromJSON(pinWith({ stowaway: 'x' })));
  });

  it('rejects __proto__ as a top-level key', () => {
    // We can't add __proto__ via spread on object literals reliably;
    // construct a raw JSON string.
    const raw =
      '{"__proto__":"x","v":2,"kid":"k1","model":"m","source_hash":"sha256:' +
      'a'.repeat(64) +
      '","vec_hash":"sha256:' +
      'b'.repeat(64) +
      '","vec_dtype":"f32","vec_dim":3,"ts":"2026-05-13T12:00:00Z","sig":"' +
      'A'.repeat(86) +
      '"}';
    assert.throws(() => pinFromJSON(raw));
  });

  it('rejects non-string extra value', () => {
    assert.throws(() => pinFromJSON(pinWith({ extra: { region: 5 } })));
  });

  it('rejects NFD model string', () => {
    assert.throws(() => pinFromJSON(pinWith({ model: 'café' })));
  });

  it('rejects ts with fractional seconds', () => {
    assert.throws(() => pinFromJSON(pinWith({ ts: '2026-05-13T12:00:00.000Z' })));
  });

  it('rejects ts with an offset instead of trailing Z', () => {
    assert.throws(() => pinFromJSON(pinWith({ ts: '2026-05-13T12:00:00+00:00' })));
  });

  it('rejects lowercase t/z in ts', () => {
    assert.throws(() => pinFromJSON(pinWith({ ts: '2026-05-13t12:00:00z' })));
  });

  it('rejects sig that decodes to non-64 bytes', () => {
    // 32 bytes -> 43 base64url chars
    assert.throws(() => pinFromJSON(pinWith({ sig: 'A'.repeat(43) })));
  });

  it('rejects standard-base64 alphabet in sig', () => {
    // Inject a `+` which is not in the URL-safe alphabet.
    assert.throws(() => pinFromJSON(pinWith({ sig: '+' + 'A'.repeat(85) })));
  });

  it('rejects pin JSON exceeding the size cap', () => {
    const huge = 'x'.repeat(MAX_PIN_JSON_BYTES + 1);
    assert.throws(() => pinFromJSON(huge));
  });

  it('rejects vec_dim above MAX_VEC_DIM', () => {
    assert.throws(() => pinFromJSON(pinWith({ vec_dim: MAX_VEC_DIM + 1 })));
  });

  it('rejects extra with too many entries', () => {
    const extra: Record<string, string> = {};
    for (let i = 0; i <= MAX_EXTRA_ENTRIES; i++) {
      extra[`k${i}`] = 'v';
    }
    assert.throws(() => pinFromJSON(pinWith({ extra })));
  });

  it('rejects v != 2 in strict mode', () => {
    assert.throws(() => pinFromJSON(pinWith({ v: 1 })));
    assert.throws(() => pinFromJSON(pinWith({ v: 99 })));
  });

  it('rejects control character in kid', () => {
    assert.throws(() => pinFromJSON(pinWith({ kid: 'k\x01' })));
  });

  it('rejects bidi-override in model', () => {
    assert.throws(() => pinFromJSON(pinWith({ model: 'm‮' })));
  });
});

describe('Signer.pin rejects unsafe input', () => {
  it('rejects NaN in the vector', async () => {
    const signer = Signer.generate('k1');
    const v = new Float32Array([0.1, NaN, 0.3]);
    await assert.rejects(signer.pin({ source: 's', model: 'm', vector: v }));
  });

  it('rejects +Infinity in the vector', async () => {
    const signer = Signer.generate('k1');
    const v = new Float32Array([0.1, Infinity, 0.3]);
    await assert.rejects(signer.pin({ source: 's', model: 'm', vector: v }));
  });

  it('rejects -Infinity in the vector', async () => {
    const signer = Signer.generate('k1');
    const v = new Float32Array([0.1, -Infinity, 0.3]);
    await assert.rejects(signer.pin({ source: 's', model: 'm', vector: v }));
  });

  it('rejects control character in model', async () => {
    const signer = Signer.generate('k1');
    const v = new Float32Array([0.1, 0.2, 0.3]);
    await assert.rejects(signer.pin({ source: 's', model: 'm\x01', vector: v }));
  });

  it('+0.0 and -0.0 produce different vec_hashes', async () => {
    const signer = Signer.generate('k1');
    const pos = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([0.0, 0.0, 0.0]),
    });
    const neg = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([-0.0, -0.0, -0.0]),
    });
    assert.notEqual(pos.header.vec_hash, neg.header.vec_hash);
  });

  it('emits v=2 timestamp format', async () => {
    const signer = Signer.generate('k1');
    const pin = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([0.1, 0.2, 0.3]),
    });
    assert.match(pin.header.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it('strips fractional seconds when given an RFC 3339 timestamp', async () => {
    const signer = Signer.generate('k1');
    const pin = await signer.pin({
      source: 's',
      model: 'm',
      vector: new Float32Array([0.1, 0.2, 0.3]),
      timestamp: '2026-05-13T12:00:00.123Z',
    });
    assert.equal(pin.header.ts, '2026-05-13T12:00:00Z');
  });
});
