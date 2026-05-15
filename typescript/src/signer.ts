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
  /**
   * Optional explicit timestamp in `YYYY-MM-DDTHH:MM:SSZ` form, or a
   * `Date` instance that will be formatted to that form. Defaults to
   * now (UTC). v2 enforces the exact strftime pattern; fractional
   * seconds or non-`Z` offsets are rejected.
   */
  timestamp?: string | Date;
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
    // NFC + safety check on key_id at construction so every emitted
    // pin has a header a strict verifier accepts.
    const normalizedKid = normalizeStringStrict(keyId, 'keyId');
    // Defensive copy so the caller cannot mutate or zero our key
    // after construction.
    this.#privateKey = new Uint8Array(privateKey);
    this.#keyId = normalizedKid;
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
    return new Uint8Array(this.#privateKey);
  }

  /**
   * Create a signed Pin for a (source, model, vector) triple.
   *
   * Per spec §3.2, vectors containing NaN, +inf, or -inf are rejected
   * at sign time. Per spec §3.1, every string-typed input is
   * NFC-normalized and checked for control characters and bidi
   * overrides; non-NFC input is silently re-normalized but other
   * unsafe characters reject.
   */
  async pin(opts: SignerPinOptions): Promise<Pin> {
    this.#assertUsable();
    if (opts.vector.length === 0) {
      throw new Error('cannot pin an empty vector');
    }

    // Reject NaN / Inf BEFORE we compute hashes so a signer never
    // commits to a vector with ambiguous semantics.
    for (let i = 0; i < opts.vector.length; i++) {
      const x = opts.vector[i] as number;
      if (!Number.isFinite(x)) {
        throw new Error('vector contains NaN or Inf; refusing to sign');
      }
    }

    const dtype: VecDtype = opts.vecDtype ?? 'f32';

    // NFC + safety for every string-typed input.
    const modelN = normalizeStringStrict(opts.model, 'model');
    // Source is hashed; NFC happens inside hashText already, but we
    // still want a stable representation here.
    const sourceN = opts.source.normalize('NFC');

    const extraN: Record<string, string> | undefined = (() => {
      if (!opts.extra) return undefined;
      const out: Record<string, string> = {};
      for (const k of Object.keys(opts.extra)) {
        if (typeof k !== 'string' || typeof opts.extra[k] !== 'string') {
          throw new Error('extra must be a map of string -> string');
        }
        const kn = normalizeStringStrict(k, `extra key ${JSON.stringify(k)}`);
        const vn = normalizeStringStrict(opts.extra[k]!, `extra[${JSON.stringify(k)}]`);
        out[kn] = vn;
      }
      return out;
    })();

    const ts = formatTimestamp(opts.timestamp);

    const header: PinHeader = {
      v: PROTOCOL_VERSION,
      kid: this.#keyId,
      model: modelN,
      source_hash: hashText(sourceN),
      vec_hash: hashVector(opts.vector, dtype),
      vec_dtype: dtype,
      vec_dim: opts.vector.length,
      ts,
      model_hash: opts.modelHash,
      extra: extraN,
    };
    const canonical = canonicalizeHeader(header);
    const sig = await ed25519.signAsync(canonical, this.#privateKey);
    return { header, sig };
  }

  #assertUsable(): void {
    if (this.#wiped) {
      throw new Error('signer has been wiped and is no longer usable');
    }
  }
}

/**
 * NFC-normalize a string and reject control characters or bidi
 * overrides. Used on every signer input so the produced pin always
 * parses under the strict v2 verifier.
 */
function normalizeStringStrict(value: string, fieldName: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a string`);
  }
  const nfc = value.normalize('NFC');
  for (let i = 0; i < nfc.length; i++) {
    const cp = nfc.charCodeAt(i);
    if (cp < 0x20) {
      throw new Error(
        `${fieldName} contains control character U+${cp.toString(16).padStart(4, '0').toUpperCase()}`,
      );
    }
    if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
      throw new Error(
        `${fieldName} contains bidi-override character U+${cp.toString(16).padStart(4, '0').toUpperCase()}`,
      );
    }
  }
  return nfc;
}

/**
 * Coerce a `string | Date | undefined` into the exact v2 timestamp
 * pattern `YYYY-MM-DDTHH:MM:SSZ`. Accepts:
 *   - A string already matching the pattern (passed through).
 *   - A string in a related RFC 3339 form with fractional seconds or
 *     a numeric offset — these are normalized to the strict form.
 *   - A `Date` (formatted via UTC accessors).
 *   - undefined (uses `new Date()`).
 *
 * The resulting string is then validated by the strict v2 regex. If
 * a caller passes a non-coercible string we throw rather than
 * emitting a pin that would later fail to parse.
 */
function formatTimestamp(input: string | Date | undefined): string {
  if (input === undefined) {
    return formatUtcIsoSecond(new Date());
  }
  if (input instanceof Date) {
    return formatUtcIsoSecond(input);
  }
  if (typeof input !== 'string') {
    throw new Error('timestamp must be a string or Date');
  }
  // Fast-path: already in canonical form.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(input)) {
    return input;
  }
  // Try to coerce any RFC 3339 string into canonical form. Fractional
  // seconds and offsets are dropped here so callers don't have to
  // hand-format.
  const parsed = Date.parse(input);
  if (Number.isNaN(parsed)) {
    throw new Error(`timestamp must match 'YYYY-MM-DDTHH:MM:SSZ'; got ${JSON.stringify(input)}`);
  }
  return formatUtcIsoSecond(new Date(parsed));
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
