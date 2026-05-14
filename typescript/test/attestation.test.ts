// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Strict-validation tests for pinFromJSON / pinFromDict. These cover
// the prototype-pollution, size-cap, type, alphabet, and structural
// checks added in the P2 hardening pass. The positive round-trip is
// covered in signer-verifier.test.ts and cross-lang.test.ts.

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  MAX_EXTRA_ENTRIES,
  MAX_PIN_JSON_BYTES,
  pinFromDict,
  pinFromJSON,
  pinToJSON,
} from '../src/attestation.js';
import { Signer } from '../src/signer.js';

async function validPinJson(): Promise<string> {
  const signer = Signer.fromPrivateBytes(new Uint8Array(32).fill(7), 'k1');
  const pin = await signer.pin({
    source: 'hello',
    model: 'm',
    vector: new Float32Array([0.1, 0.2, 0.3]),
    timestamp: '2026-05-01T00:00:00Z',
  });
  return pinToJSON(pin);
}

function parseObj(json: string): Record<string, unknown> {
  return JSON.parse(json) as Record<string, unknown>;
}

describe('pinFromJSON size cap', () => {
  it('rejects JSON larger than MAX_PIN_JSON_BYTES', () => {
    const oversize = '{"x":"' + 'a'.repeat(MAX_PIN_JSON_BYTES) + '"}';
    assert.throws(() => pinFromJSON(oversize), /maximum size/);
  });

  it('rejects non-object JSON roots', () => {
    assert.throws(() => pinFromJSON('123'), /pin JSON root/);
    assert.throws(() => pinFromJSON('"hi"'), /pin JSON root/);
    assert.throws(() => pinFromJSON('null'), /pin JSON root/);
    assert.throws(() => pinFromJSON('[1,2,3]'), /pin JSON root/);
  });
});

describe('pinFromDict prototype-pollution guards', () => {
  it('rejects __proto__ as an own property', async () => {
    const base = parseObj(await validPinJson());
    const polluted = JSON.parse(
      JSON.stringify(base).replace(/^\{/, '{"__proto__":{"polluted":1},'),
    ) as Record<string, unknown>;
    assert.ok(Object.prototype.hasOwnProperty.call(polluted, '__proto__'));
    assert.throws(() => pinFromDict(polluted), /forbidden key/);
  });

  it('rejects constructor as an own property', async () => {
    const base = parseObj(await validPinJson());
    const polluted = { constructor: 'evil', ...base } as Record<string, unknown>;
    assert.throws(() => pinFromDict(polluted), /forbidden key/);
  });

  it('rejects prototype as an own property', async () => {
    const base = parseObj(await validPinJson());
    const polluted = { prototype: 'evil', ...base } as Record<string, unknown>;
    assert.throws(() => pinFromDict(polluted), /forbidden key/);
  });

  it('rejects __proto__ inside extra', async () => {
    const base = parseObj(await validPinJson());
    base['extra'] = JSON.parse('{"__proto__":"x"}');
    assert.throws(() => pinFromDict(base), /forbidden key in pin.extra|unknown pin field/);
  });
});

describe('pinFromDict unknown top-level keys', () => {
  it('rejects unknown keys', async () => {
    const base = parseObj(await validPinJson());
    base['surprise'] = 'gotcha';
    assert.throws(() => pinFromDict(base), /unknown pin field/);
  });
});

describe('pinFromDict type checks', () => {
  it('rejects wrong v', async () => {
    const base = parseObj(await validPinJson());
    base['v'] = 2;
    assert.throws(() => pinFromDict(base), /unsupported pin version/);
  });

  it('rejects v as a string', async () => {
    const base = parseObj(await validPinJson());
    base['v'] = '1';
    assert.throws(() => pinFromDict(base), /unsupported pin version/);
  });

  it('rejects empty model', async () => {
    const base = parseObj(await validPinJson());
    base['model'] = '';
    assert.throws(() => pinFromDict(base), /pin.model/);
  });

  it('rejects non-string kid', async () => {
    const base = parseObj(await validPinJson());
    base['kid'] = 42;
    assert.throws(() => pinFromDict(base), /pin.kid/);
  });

  it('rejects non-string ts', async () => {
    const base = parseObj(await validPinJson());
    base['ts'] = 123456;
    assert.throws(() => pinFromDict(base), /pin.ts/);
  });

  it('rejects unknown vec_dtype', async () => {
    const base = parseObj(await validPinJson());
    base['vec_dtype'] = 'f16';
    assert.throws(() => pinFromDict(base), /unsupported vec_dtype/);
  });

  it('rejects non-integer vec_dim', async () => {
    const base = parseObj(await validPinJson());
    base['vec_dim'] = 3.5;
    assert.throws(() => pinFromDict(base), /vec_dim/);
  });

  it('rejects zero vec_dim', async () => {
    const base = parseObj(await validPinJson());
    base['vec_dim'] = 0;
    assert.throws(() => pinFromDict(base), /vec_dim/);
  });

  it('rejects vec_dim above the cap', async () => {
    const base = parseObj(await validPinJson());
    base['vec_dim'] = 2_000_000;
    assert.throws(() => pinFromDict(base), /vec_dim/);
  });
});

describe('pinFromDict hash format checks', () => {
  it('rejects malformed source_hash', async () => {
    const base = parseObj(await validPinJson());
    base['source_hash'] = 'sha256:ZZZ';
    assert.throws(() => pinFromDict(base), /source_hash/);
  });

  it('rejects malformed vec_hash', async () => {
    const base = parseObj(await validPinJson());
    base['vec_hash'] = 'not-a-hash';
    assert.throws(() => pinFromDict(base), /vec_hash/);
  });

  it('rejects malformed model_hash when present', async () => {
    const base = parseObj(await validPinJson());
    base['model_hash'] = 'sha256:short';
    assert.throws(() => pinFromDict(base), /model_hash/);
  });

  it('accepts a well-formed optional model_hash', async () => {
    const base = parseObj(await validPinJson());
    base['model_hash'] = 'sha256:' + '0'.repeat(64);
    // Will still fail on signature length-or-mismatch — but parsing
    // the pin shape should succeed up to that. We assert the error is
    // about the signature, not the model_hash.
    try {
      pinFromDict(base);
    } catch (e) {
      assert.doesNotMatch(String((e as Error).message), /model_hash/);
    }
  });
});

describe('pinFromDict signature checks', () => {
  it('rejects sig of wrong byte length', async () => {
    const base = parseObj(await validPinJson());
    // 8 zero bytes -> 11 base64url chars (no pad).
    base['sig'] = 'AAAAAAAAAAA';
    assert.throws(() => pinFromDict(base), /pin.sig must decode to 64 bytes/);
  });

  it('rejects sig with standard-base64 + or / characters', async () => {
    const base = parseObj(await validPinJson());
    // Construct a 64-byte payload that, in standard base64, contains
    // a '+' or '/'. 0xfb 0xff produces '+/' near the front. We just
    // splice one in to ensure rejection.
    base['sig'] = '+'.repeat(86);
    assert.throws(() => pinFromDict(base), /base64url input/);
  });

  it('rejects sig with whitespace', async () => {
    const base = parseObj(await validPinJson());
    base['sig'] = 'AAAA AAAA';
    assert.throws(() => pinFromDict(base), /base64url input/);
  });

  it('rejects missing sig', async () => {
    const base = parseObj(await validPinJson());
    delete base['sig'];
    assert.throws(() => pinFromDict(base), /pin.sig/);
  });
});

describe('pinFromDict extra map', () => {
  it('rejects non-string values', async () => {
    const base = parseObj(await validPinJson());
    base['extra'] = { foo: 123 };
    assert.throws(() => pinFromDict(base), /pin.extra/);
  });

  it('rejects extra arrays', async () => {
    const base = parseObj(await validPinJson());
    base['extra'] = ['a', 'b'];
    assert.throws(() => pinFromDict(base), /pin.extra/);
  });

  it('rejects oversize extra', async () => {
    const base = parseObj(await validPinJson());
    const big: Record<string, string> = {};
    for (let i = 0; i < MAX_EXTRA_ENTRIES + 1; i++) big[`k${i}`] = 'v';
    base['extra'] = big;
    assert.throws(() => pinFromDict(base), /maximum is/);
  });
});
