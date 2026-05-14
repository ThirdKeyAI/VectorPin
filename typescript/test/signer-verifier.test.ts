// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { pinFromJSON, pinToJSON } from '../src/attestation.js';
import { Signer } from '../src/signer.js';
import { Verifier } from '../src/verifier.js';

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
    assert.equal(result.error, 'vector_tampered');
  });

  it('source mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const result = await verifier.verify(pin, { source: 'HELLO' });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'source_mismatch');
  });

  it('shape mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'hello', model: 'm', vector });
    const truncated = new Float32Array(vector.slice(0, 8));
    const result = await verifier.verify(pin, { vector: truncated });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'shape_mismatch');
  });

  it('unknown key is caught', async () => {
    const rogue = Signer.generate('rogue');
    const prod = Signer.generate('prod');
    const verifier = new Verifier({ [prod.keyId]: await prod.publicKeyBytes() });
    const v = new Float32Array([1, 2, 3]);
    const pin = await rogue.pin({ source: 'x', model: 'm', vector: v });
    const result = await verifier.verify(pin);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'unknown_key');
  });

  it('model mismatch is caught', async () => {
    const { signer, verifier, vector } = await fixture();
    const pin = await signer.pin({ source: 'x', model: 'model-A', vector });
    const result = await verifier.verify(pin, { expectedModel: 'model-B' });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'model_mismatch');
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

  it('empty keyId is rejected', () => {
    assert.throws(() => Signer.generate(''));
  });

  it('publicKeyBytes returns 32 bytes', async () => {
    const signer = Signer.generate('k');
    assert.equal((await signer.publicKeyBytes()).length, 32);
  });
});

describe('Signer key-material handling', () => {
  it('fromPrivateBytes does not retain the caller buffer', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i + 1;
    const signer = Signer.fromPrivateBytes(seed, 'k');
    const pubBefore = await signer.publicKeyBytes();

    // Mutate the caller buffer; a non-defensive implementation would
    // change the public key and thereby invalidate signatures.
    seed.fill(0);

    const pubAfter = await signer.publicKeyBytes();
    assert.deepEqual(Array.from(pubBefore), Array.from(pubAfter));

    const v = new Float32Array([0.5, 0.25]);
    const pin = await signer.pin({ source: 's', model: 'm', vector: v });
    const verifier = new Verifier({ k: pubAfter });
    assert.equal((await verifier.verify(pin, { source: 's', vector: v })).ok, true);
  });

  it('privateKeyBytes returns a defensive copy', () => {
    const signer = Signer.generate('k');
    const copy = signer.privateKeyBytes();
    copy.fill(0);
    const copy2 = signer.privateKeyBytes();
    assert.notDeepEqual(Array.from(copy), Array.from(copy2));
  });

  it('wipe() makes the signer throw on subsequent use', async () => {
    const signer = Signer.generate('k');
    const v = new Float32Array([1, 2, 3]);
    // Sanity: a fresh signer can sign.
    await signer.pin({ source: 's', model: 'm', vector: v });

    signer.wipe();
    assert.equal(signer.isWiped, true);

    await assert.rejects(
      async () => signer.pin({ source: 's', model: 'm', vector: v }),
      /wiped/,
    );
    assert.throws(() => signer.privateKeyBytes(), /wiped/);
    await assert.rejects(async () => signer.publicKeyBytes(), /wiped/);
  });
});
