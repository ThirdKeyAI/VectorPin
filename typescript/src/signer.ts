// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin signing.
//
// Wraps an Ed25519 signing key plus a `kid` so verifiers can route
// signatures during key rotation. Use Signer.generate() for tests
// and demos; load production keys from a managed secret store.

import * as ed25519 from '@noble/ed25519';
import { randomBytes } from '@noble/hashes/utils';

import {
  canonicalizeHeader,
  PROTOCOL_VERSION,
  type Pin,
  type PinHeader,
} from './attestation.js';
import { hashText, hashVector, type VecDtype, type VectorInput } from './hash.js';

// Hard requirement: a Web-Crypto-compatible CSPRNG must be available
// at module load. Every supported runtime (Node >=20, Deno, Bun,
// modern browsers, Cloudflare Workers) provides this. If it's missing
// we refuse to load rather than silently fall back to a weaker source.
if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
  throw new Error('CSPRNG not available; VectorPin requires a runtime with Web Crypto API');
}

export interface SignerPinOptions {
  /** Source text the embedding was produced from. */
  source: string;
  /** Embedding model identifier, e.g. 'text-embedding-3-large'. */
  model: string;
  /** 1-D embedding. */
  vector: VectorInput;
  /** Canonical dtype to hash under. Defaults to 'f32'. */
  vecDtype?: VecDtype;
  /** Optional content hash of the model weights. */
  modelHash?: string;
  /** Optional explicit timestamp in `YYYY-MM-DDTHH:MM:SSZ` form; defaults to now (UTC). */
  timestamp?: string;
  /** Optional string-to-string metadata committed under the signature. */
  extra?: Record<string, string>;
}

/**
 * Produces signed Pin attestations.
 *
 * A Signer holds one Ed25519 private key. The corresponding public
 * key is published with `keyId` so verifiers can route signatures
 * to the right key during rotation.
 */
export class Signer {
  #privateKey: Uint8Array;
  readonly #keyId: string;
  #wiped = false;

  private constructor(privateKey: Uint8Array, keyId: string) {
    if (!keyId) throw new Error('keyId must be non-empty');
    if (privateKey.length !== 32) {
      throw new Error(`private key must be 32 bytes, got ${privateKey.length}`);
    }
    // Defensive copy so the caller cannot mutate or zero our key
    // after construction.
    this.#privateKey = new Uint8Array(privateKey);
    this.#keyId = keyId;
  }

  /** Generate a fresh Ed25519 signer. Tests and demos only. */
  static generate(keyId: string): Signer {
    return new Signer(randomBytes(32), keyId);
  }

  /** Load a signer from a 32-byte raw Ed25519 private seed. */
  static fromPrivateBytes(raw: Uint8Array, keyId: string): Signer {
    return new Signer(raw, keyId);
  }

  get keyId(): string {
    return this.#keyId;
  }

  /** True after `wipe()` has been called; the signer is unusable. */
  get isWiped(): boolean {
    return this.#wiped;
  }

  /**
   * Zero out the private key material and mark the signer unusable.
   * Subsequent calls to `pin()` or key accessors will throw.
   */
  wipe(): void {
    this.#privateKey.fill(0);
    this.#wiped = true;
  }

  /** 32-byte raw Ed25519 public key — what verifiers register. */
  async publicKeyBytes(): Promise<Uint8Array> {
    this.#assertUsable();
    return ed25519.getPublicKeyAsync(this.#privateKey);
  }

  /** 32-byte raw Ed25519 private seed. Treat as a secret. */
  privateKeyBytes(): Uint8Array {
    this.#assertUsable();
    // Defensive copy so the caller cannot mutate our internal state.
    return new Uint8Array(this.#privateKey);
  }

  /** Create a signed Pin for a (source, model, vector) triple. */
  async pin(opts: SignerPinOptions): Promise<Pin> {
    this.#assertUsable();
    if (opts.vector.length === 0) {
      throw new Error('cannot pin an empty vector');
    }
    const dtype: VecDtype = opts.vecDtype ?? 'f32';
    const ts = opts.timestamp ?? formatUtcIsoSecond(new Date());
    const header: PinHeader = {
      v: PROTOCOL_VERSION,
      model: opts.model,
      source_hash: hashText(opts.source),
      vec_hash: hashVector(opts.vector, dtype),
      vec_dtype: dtype,
      vec_dim: opts.vector.length,
      ts,
      model_hash: opts.modelHash,
      extra: opts.extra,
    };
    const canonical = canonicalizeHeader(header);
    const sig = await ed25519.signAsync(canonical, this.#privateKey);
    return { header, kid: this.#keyId, sig };
  }

  #assertUsable(): void {
    if (this.#wiped) {
      throw new Error('signer has been wiped and is no longer usable');
    }
  }
}

/**
 * Format `Date` to `YYYY-MM-DDTHH:MM:SSZ` UTC (second-precision).
 *
 * We avoid `toISOString()` because it includes milliseconds and the
 * Python/Rust ports emit second-precision timestamps. Matching that
 * format keeps cross-language hashes identical for fixtures that
 * supply their own timestamp string.
 */
export function formatUtcIsoSecond(d: Date): string {
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  return (
    pad(d.getUTCFullYear(), 4) +
    '-' +
    pad(d.getUTCMonth() + 1) +
    '-' +
    pad(d.getUTCDate()) +
    'T' +
    pad(d.getUTCHours()) +
    ':' +
    pad(d.getUTCMinutes()) +
    ':' +
    pad(d.getUTCSeconds()) +
    'Z'
  );
}
