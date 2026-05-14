// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin verification.
//
// Mirrors the Python and Rust verifiers: same failure-mode enum,
// same matching semantics, same support for partial verification
// (signature-only, signature + vector, etc).

import * as ed25519 from '@noble/ed25519';

import { canonicalizeHeader, PROTOCOL_VERSION, type Pin } from './attestation.js';
import { hashText, hashVector, type VectorInput } from './hash.js';

/**
 * Distinct verification failure modes. Callers route on this so a
 * signature-invalid result (potential forgery) can be handled
 * differently from a vector-tampered result (potential steganography
 * kill shot).
 *
 * Wire-form values match the Python reference (`VerifyError.OK.value`
 * etc.), so a result serialized over a service boundary round-trips.
 */
export const VerifyErrorCode = {
  OK: 'ok',
  UNKNOWN_KEY: 'unknown_key',
  UNSUPPORTED_VERSION: 'unsupported_version',
  SIGNATURE_INVALID: 'signature_invalid',
  VECTOR_TAMPERED: 'vector_tampered',
  SOURCE_MISMATCH: 'source_mismatch',
  MODEL_MISMATCH: 'model_mismatch',
  SHAPE_MISMATCH: 'shape_mismatch',
} as const;

export type VerifyErrorCode = (typeof VerifyErrorCode)[keyof typeof VerifyErrorCode];

/** Structured result; truthy via `result.ok` iff verification succeeded. */
export interface VerificationResult {
  readonly ok: boolean;
  readonly error: VerifyErrorCode;
  readonly detail: string;
}

export interface VerifyOptions {
  /** If provided, the source text is rehashed and compared to `source_hash`. */
  source?: string;
  /** If provided, the vector is rehashed under `vec_dtype` and compared to `vec_hash`. */
  vector?: VectorInput;
  /** If provided, the pin's `model` field must equal this string. */
  expectedModel?: string;
}

/** Maximum length of an attacker-controlled substring in `detail`. */
const MAX_DETAIL_FIELD = 64;

/**
 * Strip control characters and newlines from any attacker-controllable
 * field before embedding it in a `detail` string. Keeps the message
 * legible without giving an attacker a vector to inject log entries
 * or terminal escape sequences.
 */
function sanitizeDetail(s: string): string {
  // Replace ASCII control chars and DEL with '?'.
  const cleaned = s.replace(/[\x00-\x1f\x7f]/g, '?');
  if (cleaned.length <= MAX_DETAIL_FIELD) return cleaned;
  return cleaned.slice(0, MAX_DETAIL_FIELD) + '...';
}

/**
 * Verifies Pin attestations against a key registry.
 *
 * The registry maps key id -> 32-byte raw Ed25519 public key.
 * Verifiers MUST be willing to hold multiple keys at once to support
 * rotation: when a new signing key is introduced, both the old and
 * new public keys live in the registry until the rotation window
 * closes.
 */
export class Verifier {
  readonly #keys = new Map<string, Uint8Array>();

  constructor(publicKeys: Record<string, Uint8Array> = {}) {
    for (const [kid, key] of Object.entries(publicKeys)) {
      this.addKey(kid, key);
    }
  }

  /** Register an additional public key — used during rotation. */
  addKey(kid: string, publicKey: Uint8Array): void {
    if (publicKey.length !== 32) {
      throw new Error(`public key for ${kid} must be 32 bytes, got ${publicKey.length}`);
    }
    // Defensive copy so callers can't mutate registered keys.
    this.#keys.set(kid, new Uint8Array(publicKey));
  }

  get keyCount(): number {
    return this.#keys.size;
  }

  /**
   * Verify a Pin. Pass `source`/`vector`/`expectedModel` only when
   * you have the corresponding ground truth on hand — the signature
   * check always runs; the others are gated on what you supply.
   */
  async verify(pin: Pin, opts: VerifyOptions = {}): Promise<VerificationResult> {
    if (pin.header.v !== PROTOCOL_VERSION) {
      return result(false, 'unsupported_version', `pin version ${pin.header.v} not supported`);
    }

    const publicKey = this.#keys.get(pin.kid);
    if (!publicKey) {
      return result(
        false,
        'unknown_key',
        `no registered public key for kid=${sanitizeDetail(pin.kid)}`,
      );
    }

    const canonical = canonicalizeHeader(pin.header);
    let sigValid: boolean;
    try {
      sigValid = await ed25519.verifyAsync(pin.sig, canonical, publicKey);
    } catch {
      sigValid = false;
    }
    if (!sigValid) {
      return result(false, 'signature_invalid', 'ed25519 signature did not verify');
    }

    if (opts.vector !== undefined) {
      if (opts.vector.length !== pin.header.vec_dim) {
        return result(
          false,
          'shape_mismatch',
          `vector length ${opts.vector.length} != pin dim ${pin.header.vec_dim}`,
        );
      }
      if (hashVector(opts.vector, pin.header.vec_dtype) !== pin.header.vec_hash) {
        return result(
          false,
          'vector_tampered',
          'vector hash mismatch — embedding has been modified after pinning',
        );
      }
    }

    if (opts.source !== undefined && hashText(opts.source) !== pin.header.source_hash) {
      return result(
        false,
        'source_mismatch',
        'source hash mismatch — pinned source differs from supplied source',
      );
    }

    if (opts.expectedModel !== undefined && pin.header.model !== opts.expectedModel) {
      return result(
        false,
        'model_mismatch',
        `pin model ${sanitizeDetail(pin.header.model)} != expected ${sanitizeDetail(
          opts.expectedModel,
        )}`,
      );
    }

    return result(true, 'ok', '');
  }
}

function result(ok: boolean, error: VerifyErrorCode, detail: string): VerificationResult {
  return { ok, error, detail };
}
