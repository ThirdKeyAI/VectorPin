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
  isValidCalendarTs,
  pinFromDict,
  pinFromJSON,
  PROTOCOL_VERSION,
  SIG_LEN,
  type Pin,
} from './attestation.js';
import {
  hashText,
  hashVector,
  nativeDtype,
  vectorElementWidth,
  type VectorInput,
} from './hash.js';

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
 *
 * The window is evaluated against the pin's signer-chosen `ts` unless
 * the caller supplies `VerifyOptions.trustedTime`; on its own it
 * therefore only bounds honest signers — a holder of a compromised
 * key can backdate `ts` into the window.
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
  /**
   * If provided, the vector is rehashed under `vec_dtype` and compared
   * to `vec_hash`. A `Float64Array` or plain `number[]` (both 64-bit
   * representations) is refused against an `f32` pin as
   * `SHAPE_MISMATCH` rather than narrowed: the bits a cast discards
   * would otherwise go unverified (spec §3.2).
   */
  vector?: VectorInput;
  /** If provided, the pin's `model` field must equal this string. */
  expectedModel?: string;
  /**
   * If provided, the pin's `model_hash` must equal this `sha256:<hex>`
   * value; a pin without one fails `MODEL_MISMATCH`.
   */
  expectedModelHash?: string;
  /**
   * An instant from a clock the signing-key holder cannot write (for
   * example the store's own ingestion timestamp). When supplied, the key
   * validity window is evaluated against it instead of the pin's `ts`,
   * and a pin whose `ts` postdates it is rejected as `KEY_EXPIRED`.
   */
  trustedTime?: Date;
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
 * Parse a pin `ts` into a UTC `Date`. Returns null if the string is
 * unparseable so the caller can fail safely.
 *
 * v2 pins must satisfy the strict shape AND calendar validity (V8's
 * `Date.parse` would roll `2026-02-30` forward to March 2, which no
 * other port does). v1 pins keep the lenient RFC 3339 parse because
 * the legacy verifier has to accept historical artifacts.
 */
function parseTs(ts: string, version: number): Date | null {
  if (version === PROTOCOL_VERSION) {
    if (!isValidCalendarTs(ts)) return null;
    const t = Date.parse(ts);
    return Number.isNaN(t) ? null : new Date(t);
  }
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
   *
   * Never rejects (throws) on account of pin content or ground truth:
   * anything unexpected is reported as a `PARSE_ERROR` result so a
   * hostile record cannot turn a read path into an exception path.
   */
  async verify(pin: Pin, opts: VerifyOptions = {}): Promise<VerificationResult> {
    try {
      return await this.#verifyInner(pin, opts);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return result(
        false,
        VerifyErrorCode.PARSE_ERROR,
        `verification aborted on malformed input: ${sanitizeDetail(msg)}`,
      );
    }
  }

  async #verifyInner(pin: Pin, opts: VerifyOptions): Promise<VerificationResult> {
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
    if (
      entry.validFrom !== undefined ||
      entry.validUntil !== undefined ||
      opts.trustedTime !== undefined
    ) {
      const pinTs = parseTs(pin.header.ts, pin.header.v);
      if (pinTs === null) {
        return result(
          false,
          VerifyErrorCode.KEY_EXPIRED,
          'pin ts unparseable; cannot evaluate key validity window',
        );
      }
      // `ts` is chosen by whoever holds the signing key; a trusted time
      // from the store binds the window to a clock the key holder
      // cannot write.
      let windowTs = pinTs;
      if (opts.trustedTime !== undefined) {
        if (!(opts.trustedTime instanceof Date) || Number.isNaN(opts.trustedTime.getTime())) {
          return result(false, VerifyErrorCode.PARSE_ERROR, 'trustedTime must be a valid Date');
        }
        if (pinTs > opts.trustedTime) {
          return result(
            false,
            VerifyErrorCode.KEY_EXPIRED,
            `pin ts ${sanitizeDetail(pin.header.ts)} postdates the trusted time`,
          );
        }
        windowTs = opts.trustedTime;
      }
      if (entry.validFrom !== undefined && windowTs < entry.validFrom) {
        return result(
          false,
          VerifyErrorCode.KEY_EXPIRED,
          `pin ts ${sanitizeDetail(pin.header.ts)} predates key validFrom`,
        );
      }
      if (entry.validUntil !== undefined && windowTs >= entry.validUntil) {
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

    // Step 5: source check.
    if (opts.source !== undefined) {
      let sourceHash: string;
      try {
        sourceHash = hashText(opts.source);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return result(
          false,
          VerifyErrorCode.PARSE_ERROR,
          `supplied source cannot be hashed: ${sanitizeDetail(msg)}`,
        );
      }
      if (sourceHash !== pin.header.source_hash) {
        return result(
          false,
          VerifyErrorCode.SOURCE_MISMATCH,
          'source hash mismatch — pinned source differs from supplied source',
        );
      }
    }

    // Step 6: vector check. Vector NaN/Inf at verify time is a parse
    // error per spec §5 step 6 — reject before hashing.
    if (opts.vector !== undefined) {
      const vec = opts.vector;
      if (
        !(vec instanceof Float32Array) &&
        !(vec instanceof Float64Array) &&
        !Array.isArray(vec)
      ) {
        return result(
          false,
          VerifyErrorCode.SHAPE_MISMATCH,
          'vector must be a Float32Array, Float64Array, or number[]',
        );
      }
      if (vec.length !== pin.header.vec_dim) {
        return result(
          false,
          VerifyErrorCode.SHAPE_MISMATCH,
          `vector length ${vec.length} != pin dim ${pin.header.vec_dim}`,
        );
      }
      // Precision check (§3.2): never narrow a wider vector before
      // hashing — the discarded bits would be a covert channel.
      const pinnedWidth = pin.header.vec_dtype === 'f32' ? 4 : 8;
      if (vectorElementWidth(vec) > pinnedWidth) {
        return result(
          false,
          VerifyErrorCode.SHAPE_MISMATCH,
          `supplied vector is a 64-bit representation (${
            vec instanceof Float64Array ? 'Float64Array' : 'number[]'
          }) but the pin's vec_dtype is f32; low-order bits would be unverified. ` +
            'Pass a Float32Array holding what the store persists.',
        );
      }
      for (let i = 0; i < vec.length; i++) {
        const x = vec[i] as number;
        if (typeof x !== 'number' || !Number.isFinite(x)) {
          return result(
            false,
            VerifyErrorCode.PARSE_ERROR,
            'supplied vector contains NaN, infinity, or a non-number',
          );
        }
      }
      if (hashVector(vec, pin.header.vec_dtype) !== pin.header.vec_hash) {
        let detail = 'vector hash mismatch — embedding has been modified after pinning';
        const supplied = nativeDtype(vec);
        if (supplied !== pin.header.vec_dtype) {
          detail += ` (supplied vector is ${supplied} but the pin was signed as ${
            pin.header.vec_dtype
          }; if your store persists ${supplied}, pin with vecDtype: '${supplied}')`;
        }
        return result(false, VerifyErrorCode.VECTOR_TAMPERED, detail);
      }
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
    if (
      opts.expectedModelHash !== undefined &&
      pin.header.model_hash !== opts.expectedModelHash
    ) {
      return result(
        false,
        VerifyErrorCode.MODEL_MISMATCH,
        `pin model_hash ${sanitizeDetail(String(pin.header.model_hash))} != expected ${sanitizeDetail(
          opts.expectedModelHash,
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
