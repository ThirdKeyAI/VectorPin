// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin verification.
//
// Mirrors the Python and Rust verifiers: same failure-mode enum,
// same matching semantics, same support for partial verification
// (signature-only, signature + vector, etc).
//
// The default `Verifier` accepts only protocol v2 pins. A
// `LegacyV1Verifier` is provided for migration scenarios where
// pre-v2 pins still need to validate; legacy mode is opt-in per
// spec §5 step 1.

import * as ed25519 from '@noble/ed25519';

import {
  canonicalizeHeader,
  canonicalizeHeaderV1,
  pinFromDict,
  pinFromJSON,
  PROTOCOL_VERSION,
  SIG_LEN,
  type Pin,
} from './attestation.js';
import { hashText, hashVector, type VectorInput } from './hash.js';

/**
 * Distinct verification failure modes. Callers route on this so a
 * signature-invalid result (potential forgery) can be handled
 * differently from a vector-tampered result (potential steganography
 * kill shot).
 *
 * Wire-form values match the Python reference, so a result
 * serialized over a service boundary round-trips.
 */
export const VerifyErrorCode = {
  OK: 'ok',
  UNKNOWN_KEY: 'unknown_key',
  UNSUPPORTED_VERSION: 'unsupported_version',
  KEY_EXPIRED: 'key_expired',
  PARSE_ERROR: 'parse_error',
  SIGNATURE_INVALID: 'signature_invalid',
  VECTOR_TAMPERED: 'vector_tampered',
  SOURCE_MISMATCH: 'source_mismatch',
  MODEL_MISMATCH: 'model_mismatch',
  SHAPE_MISMATCH: 'shape_mismatch',
  RECORD_MISMATCH: 'record_mismatch',
  COLLECTION_MISMATCH: 'collection_mismatch',
  TENANT_MISMATCH: 'tenant_mismatch',
} as const;

export type VerifyErrorCode = (typeof VerifyErrorCode)[keyof typeof VerifyErrorCode];

/** Structured result; truthy via `result.ok` iff verification succeeded. */
export interface VerificationResult {
  readonly ok: boolean;
  readonly error: VerifyErrorCode;
  readonly detail: string;
}

/**
 * A registered public key, with an optional validity window per
 * spec §7. `validFrom` is inclusive; `validUntil` is exclusive.
 */
export interface KeyEntry {
  readonly publicKey: Uint8Array;
  readonly validFrom?: Date | undefined;
  readonly validUntil?: Date | undefined;
}

export type KeyRegistration = Uint8Array | KeyEntry;

export interface VerifyOptions {
  /** If provided, the source text is rehashed and compared to `source_hash`. */
  source?: string;
  /** If provided, the vector is rehashed under `vec_dtype` and compared to `vec_hash`. */
  vector?: VectorInput;
  /** If provided, the pin's `model` field must equal this string. */
  expectedModel?: string;
  /**
   * Replay-protection identifiers (spec §5 step 8). If supplied, the
   * verifier checks the corresponding `vectorpin.*` value in the
   * pin's `extra` map and rejects on mismatch.
   */
  expectedRecordId?: string;
  expectedCollectionId?: string;
  expectedTenantId?: string;
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
  // eslint-disable-next-line no-control-regex
  const cleaned = s.replace(/[\x00-\x1f\x7f]/g, '?');
  if (cleaned.length <= MAX_DETAIL_FIELD) return cleaned;
  return cleaned.slice(0, MAX_DETAIL_FIELD) + '...';
}

/**
 * Parse a v2-style `ts` string into a UTC `Date`. Returns null if
 * the string is unparseable so the caller can fail safely.
 */
function parseTs(ts: string): Date | null {
  // Strict v2 form is "YYYY-MM-DDTHH:MM:SSZ"; we also accept the
  // less-strict RFC 3339 form because this helper is shared with the
  // legacy v1 verifier.
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return null;
  return new Date(t);
}

/**
 * Verifies Pin attestations against a key registry.
 *
 * The registry maps key id -> 32-byte raw Ed25519 public key (or a
 * `KeyEntry` with optional validity window). Verifiers MUST be
 * willing to hold multiple keys at once to support rotation: when a
 * new signing key is introduced, both the old and new public keys
 * live in the registry until the rotation window closes.
 *
 * The default constructor accepts only protocol v2 pins. To accept
 * legacy v1 pins, use `LegacyV1Verifier` instead.
 */
export class Verifier {
  readonly #keys = new Map<string, KeyEntry>();
  readonly #acceptV1Legacy: boolean;

  constructor(
    publicKeys: Record<string, KeyRegistration> = {},
    opts: { acceptV1Legacy?: boolean } = {},
  ) {
    this.#acceptV1Legacy = opts.acceptV1Legacy === true;
    for (const [kid, key] of Object.entries(publicKeys)) {
      this.addKey(kid, key);
    }
  }

  /** Register an additional public key — used during rotation. */
  addKey(kid: string, key: KeyRegistration): void {
    const entry = coerceEntry(key, kid);
    this.#keys.set(kid, entry);
  }

  get keyCount(): number {
    return this.#keys.size;
  }

  /** Internal hook used by `LegacyV1Verifier`. */
  protected get acceptV1Legacy(): boolean {
    return this.#acceptV1Legacy;
  }

  /**
   * Verify a Pin. The signature check always runs; the others are
   * gated on which ground-truth values you supply.
   */
  async verify(pin: Pin, opts: VerifyOptions = {}): Promise<VerificationResult> {
    // Step 1: version dispatch.
    const accepted = this.#acceptV1Legacy
      ? [PROTOCOL_VERSION, 1]
      : [PROTOCOL_VERSION];
    if (!accepted.includes(pin.header.v)) {
      return result(
        false,
        VerifyErrorCode.UNSUPPORTED_VERSION,
        `pin version ${pin.header.v} not supported`,
      );
    }

    // Pre-check signature shape so a malformed pin returns a
    // structured PARSE_ERROR rather than blowing up downstream.
    if (!(pin.sig instanceof Uint8Array) || pin.sig.length !== SIG_LEN) {
      return result(
        false,
        VerifyErrorCode.PARSE_ERROR,
        `signature must be exactly ${SIG_LEN} bytes`,
      );
    }

    // Step 2: kid lookup + validity window.
    const entry = this.#keys.get(pin.header.kid);
    if (!entry) {
      return result(
        false,
        VerifyErrorCode.UNKNOWN_KEY,
        `no registered public key for kid=${sanitizeDetail(pin.header.kid)}`,
      );
    }
    if (entry.validFrom !== undefined || entry.validUntil !== undefined) {
      const pinTs = parseTs(pin.header.ts);
      if (pinTs === null) {
        return result(
          false,
          VerifyErrorCode.KEY_EXPIRED,
          'pin ts unparseable; cannot evaluate key validity window',
        );
      }
      if (entry.validFrom !== undefined && pinTs < entry.validFrom) {
        return result(
          false,
          VerifyErrorCode.KEY_EXPIRED,
          `pin ts ${sanitizeDetail(pin.header.ts)} predates key validFrom`,
        );
      }
      if (entry.validUntil !== undefined && pinTs >= entry.validUntil) {
        return result(
          false,
          VerifyErrorCode.KEY_EXPIRED,
          `pin ts ${sanitizeDetail(pin.header.ts)} is at or past key validUntil`,
        );
      }
    }

    // Step 4: signature.
    const canonical = canonicalFor(pin);
    let sigValid = false;
    try {
      sigValid = await ed25519.verifyAsync(pin.sig, canonical, entry.publicKey);
    } catch {
      sigValid = false;
    }
    if (!sigValid) {
      return result(
        false,
        VerifyErrorCode.SIGNATURE_INVALID,
        'ed25519 signature did not verify',
      );
    }

    // Step 6: vector check. Vector NaN/Inf at verify time is a parse
    // error per spec §5 step 6 — reject before hashing.
    if (opts.vector !== undefined) {
      if (opts.vector.length !== pin.header.vec_dim) {
        return result(
          false,
          VerifyErrorCode.SHAPE_MISMATCH,
          `vector length ${opts.vector.length} != pin dim ${pin.header.vec_dim}`,
        );
      }
      for (let i = 0; i < opts.vector.length; i++) {
        const x = opts.vector[i] as number;
        if (!Number.isFinite(x)) {
          return result(
            false,
            VerifyErrorCode.PARSE_ERROR,
            'supplied vector contains NaN or infinity',
          );
        }
      }
      if (hashVector(opts.vector, pin.header.vec_dtype) !== pin.header.vec_hash) {
        return result(
          false,
          VerifyErrorCode.VECTOR_TAMPERED,
          'vector hash mismatch — embedding has been modified after pinning',
        );
      }
    }

    // Step 5: source check.
    if (opts.source !== undefined && hashText(opts.source) !== pin.header.source_hash) {
      return result(
        false,
        VerifyErrorCode.SOURCE_MISMATCH,
        'source hash mismatch — pinned source differs from supplied source',
      );
    }

    // Step 7: model check.
    if (opts.expectedModel !== undefined && pin.header.model !== opts.expectedModel) {
      return result(
        false,
        VerifyErrorCode.MODEL_MISMATCH,
        `pin model ${sanitizeDetail(pin.header.model)} != expected ${sanitizeDetail(
          opts.expectedModel,
        )}`,
      );
    }

    // Step 8: replay-protection identifier checks. The `vectorpin.*`
    // reserved keys are tamper-evident because every `extra` entry
    // is signed.
    const replayChecks: Array<[string, string | undefined, VerifyErrorCode]> = [
      ['vectorpin.record_id', opts.expectedRecordId, VerifyErrorCode.RECORD_MISMATCH],
      ['vectorpin.collection_id', opts.expectedCollectionId, VerifyErrorCode.COLLECTION_MISMATCH],
      ['vectorpin.tenant_id', opts.expectedTenantId, VerifyErrorCode.TENANT_MISMATCH],
    ];
    for (const [key, expected, errCode] of replayChecks) {
      if (expected === undefined) continue;
      const actual = pin.header.extra?.[key];
      if (actual !== expected) {
        return result(
          false,
          errCode,
          `pin extra[${key}]=${sanitizeDetail(String(actual))} != expected ${sanitizeDetail(expected)}`,
        );
      }
    }

    return result(true, VerifyErrorCode.OK, '');
  }
}

/**
 * Migration-mode verifier that accepts protocol v1 pins in addition
 * to v2. v1 pins are dispatched to v1 canonicalization so legacy
 * artifacts continue to verify byte-for-byte against their original
 * signatures.
 *
 * Per spec §5 step 1: legacy mode MUST be opt-in and SHOULD be
 * disabled by default. Use this class explicitly; do not turn it on
 * in shared infrastructure paths.
 *
 * To parse a v1 pin JSON, use the static helpers on this class —
 * the default `pinFromJSON` rejects v1 pins.
 */
export class LegacyV1Verifier extends Verifier {
  constructor(publicKeys: Record<string, KeyRegistration> = {}) {
    super(publicKeys, { acceptV1Legacy: true });
  }

  /** Parse a pin from a JSON string, accepting v1 or v2. */
  static parsePin(s: string): Pin {
    return pinFromJSON(s, { acceptV1Legacy: true });
  }

  /** Parse a pin from a plain object, accepting v1 or v2. */
  static parsePinDict(d: Record<string, unknown>): Pin {
    return pinFromDict(d, { acceptV1Legacy: true });
  }
}

/**
 * Reconstruct the canonical bytes a signer would have signed.
 *
 * Dispatches on the pin's `v` field so the legacy verifier shares
 * most of this code path. v2 emits `DOMAIN_TAG || json`; v1 emits
 * just the (kid-less) JSON.
 */
function canonicalFor(pin: Pin): Uint8Array {
  if (pin.header.v === 1) {
    return canonicalizeHeaderV1(pin.header);
  }
  return canonicalizeHeader(pin.header);
}

function coerceEntry(key: KeyRegistration, kid: string): KeyEntry {
  if (key instanceof Uint8Array) {
    if (key.length !== 32) {
      throw new Error(`public key for ${kid} must be 32 bytes, got ${key.length}`);
    }
    return { publicKey: new Uint8Array(key) };
  }
  if (key && typeof key === 'object' && 'publicKey' in key) {
    const pk = key.publicKey;
    if (!(pk instanceof Uint8Array) || pk.length !== 32) {
      throw new Error(`public key for ${kid} must be a 32-byte Uint8Array`);
    }
    return {
      publicKey: new Uint8Array(pk),
      validFrom: key.validFrom,
      validUntil: key.validUntil,
    };
  }
  throw new Error(`public key for ${kid} must be Uint8Array or KeyEntry`);
}

function result(ok: boolean, error: VerifyErrorCode, detail: string): VerificationResult {
  return { ok, error, detail };
}
