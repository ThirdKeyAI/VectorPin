// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Legacy v1 verifier tests.
//
// The strict v2 verifier rejects v1 pins. `LegacyV1Verifier` keeps
// historical artifacts verifiable during a migration window. Per
// spec §5 step 1, legacy mode is opt-in.

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { b64UrlDecodeNoPad } from '../src/attestation.js';
import { LegacyV1Verifier, VerifyErrorCode } from '../src/verifier.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTVECTORS_DIR = join(HERE, '..', '..', 'testvectors');

interface V1Bundle {
  public_key_b64: string;
  key_id: string;
  fixtures: V1Fixture[];
}

interface V1Fixture {
  name: string;
  input: { source: string };
  expected: { pin_json: string };
}

interface V1NegativeFixture {
  pin_json: string;
  tampered_vector_b64: string;
  expected_error: string;
}

function loadV1(): V1Bundle {
  return JSON.parse(readFileSync(join(TESTVECTORS_DIR, 'v1.json'), 'utf8')) as V1Bundle;
}

function loadV1Negative(): V1NegativeFixture {
  return JSON.parse(
    readFileSync(join(TESTVECTORS_DIR, 'negative_v1.json'), 'utf8'),
  ) as V1NegativeFixture;
}

describe('LegacyV1Verifier accepts v1 fixtures', () => {
  const bundle = loadV1();
  const pubKey = b64UrlDecodeNoPad(bundle.public_key_b64);

  for (const fx of bundle.fixtures) {
    it(`verifies v1 fixture ${fx.name}`, async () => {
      const pin = LegacyV1Verifier.parsePin(fx.expected.pin_json);
      assert.equal(pin.header.v, 1, 'pin is v1');
      const verifier = new LegacyV1Verifier({ [bundle.key_id]: pubKey });
      const r = await verifier.verify(pin, { source: fx.input.source });
      assert.equal(r.ok, true, `v1 verify: ${r.error} ${r.detail}`);
    });
  }
});

describe('LegacyV1Verifier still detects v1 tampering', () => {
  it('returns VECTOR_TAMPERED on the v1 tampered fixture', async () => {
    const bundle = loadV1();
    const neg = loadV1Negative();
    const pin = LegacyV1Verifier.parsePin(neg.pin_json);

    const bytes = b64UrlDecodeNoPad(neg.tampered_vector_b64);
    const dim = pin.header.vec_dim;
    const tampered = new Float32Array(dim);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < dim; i++) {
      tampered[i] = view.getFloat32(i * 4, /* littleEndian */ true);
    }

    const verifier = new LegacyV1Verifier({
      [bundle.key_id]: b64UrlDecodeNoPad(bundle.public_key_b64),
    });
    const r = await verifier.verify(pin, { vector: tampered });
    assert.equal(r.ok, false);
    assert.equal(r.error, VerifyErrorCode.VECTOR_TAMPERED);
  });
});
