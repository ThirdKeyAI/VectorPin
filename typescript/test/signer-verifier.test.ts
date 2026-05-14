// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { pinFromJSON, pinToJSON, PROTOCOL_VERSION } from '../src/attestation.js';
import { Signer } from '../src/signer.js';
import { Verifier, VerifyErrorCode } from '../src/verifier.js';

describe('Signer.pin + Verifier.verify', () => {
  async function fixture(keyId = 'k1') {
    const signer = Signer.generate(keyId);
    const verifier = new Verifier({ [signer.keyId]: await signer.publicKeyBytes() });
    const vector = new Float32Array(Array.from({ length: 16 }, (_, i) => i * 0.1));
    return { signer, verifier, vector };
  }

  it('honest verify succeeds', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    assert.equal(pin.header.v, PROTOCOL_VERSION);
    assert.equal(pin.header.kid, signer.keyId);
    const result = await verifier.verify(pin, { source: 'hello', vector });
    assert.equal(result.ok, true, `unexpected error: ${result.error} - ${result.detail}`);
  });

  it('signature-only verify succeeds when no source/vector supplied', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    assert.equal((await verifier.verify(pin)).ok, true);
  });

  it('vector tamper is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const tampered = new Float32Array(vector);
    tampered[0] = vector[0]! + 1e-5;
    const result = await verifier.verify(pin, { vector: tampered });
    assert.equal(result.ok, false);
    assert.equal(result.error, VerifyErrorCode.VECTOR_TAMPERED);
  });

  it('source mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const result = await verifier.verify(pin, { source: 'HELLO' });
    assert.equal(result.ok, false);
    assert.equal(result.error, VerifyErrorCode.SOURCE_MISMATCH);
  });

  it('shape mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const truncated = new Float32Array(vector.slice(0, 8));
    const result = await verifier.verify(pin, { vector: truncated });
    assert.equal(result.ok, false);
    assert.equal(result.error, VerifyErrorCode.SHAPE_MISMATCH);
  });

  it('unknown key is caught', async () => {
    const rogue = Signer.generate('rogue');
    const prod = Signer.generate('prod');
    const verifier = new Verifier({ [prod.keyId]: await prod.publicKeyBytes() });
    const v = new Float32Array([1, 2, 3]);
    const pin = await rogue.pin({ source: 'x', model: 'm', vector: v });
    const result = await verifier.verify(pin);
    assert.equal(result.ok, false);
    assert.equal(result.error, VerifyErrorCode.UNKNOWN_KEY);
  });

  it('model mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'x', model: 'model-A', vector });
    const result = await verifier.verify(pin, { expectedModel: 'model-B' });
    assert.equal(result.ok, false);
    assert.equal(result.error, VerifyErrorCode.MODEL_MISMATCH);
  });

  it('rotation: multiple keys can verify', async () => {
    const oldSigner = Signer.generate('2026-04');
    const newSigner = Signer.generate('2026-05');
    const verifier = new Verifier({
      [oldSigner.keyId]: await oldSigner.publicKeyBytes(),
      [newSigner.keyId]: await newSigner.publicKeyBytes(),
    });
    const v = new Float32Array([1, 2, 3]);
    assert.equal(
      (await verifier.verify(await oldSigner.pin({ source: 'x', model: 'm', vector: v }))).ok,
      true,
    );
    assert.equal(
      (await verifier.verify(await newSigner.pin({ source: 'x', model: 'm', vector: v }))).ok,
      true,
    );
  });

  it('JSON round-trip preserves the pin', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const json = pinToJSON(pin);
    const back = pinFromJSON(json);
    assert.equal((await verifier.verify(back, { source: 'hello', vector })).ok, true);
    // Compact form, no whitespace.
    assert.ok(!json.includes('\n'));
    assert.ok(!json.includes(': '));
  });

  it('record-id replay protection: match passes, mismatch fails', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({
      source: 'x',
      model: 'm',
      vector,
      extra: { 'vectorpin.record_id': 'rec-1' },
    });
    const ok = await verifier.verify(pin, { expectedRecordId: 'rec-1' });
    assert.equal(ok.ok, true);
    const bad = await verifier.verify(pin, { expectedRecordId: 'rec-2' });
    assert.equal(bad.ok, false);
    assert.equal(bad.error, VerifyErrorCode.RECORD_MISMATCH);
  });

  it('empty keyId is rejected', () => {
    assert.throws(() => Signer.generate(''));
  });

  it('publicKeyBytes returns 32 bytes', async () => {
    const signer = Signer.generate('k');
    assert.equal((await signer.publicKeyBytes()).length, 32);
  });
});
