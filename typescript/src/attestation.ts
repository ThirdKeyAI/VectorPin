// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin attestation format and canonicalization.
//
// A Pin is the attestation that travels alongside an embedding in
// vector store metadata. It commits to:
//
//   - the source text (by hash)
//   - the model that produced the embedding (identifier + optional hash)
//   - the embedding itself (by hash)
//   - the producer (by signing key id)
//   - the time of pinning
//
// The wire form is a compact JSON object. The signature is over a
// canonical byte sequence built by `canonicalize()`, NOT over the
// JSON encoding — this is so that downstream re-serialization
// (whitespace, key order) cannot invalidate signatures.
//
// Protocol version: PROTOCOL_VERSION (currently 1). Older readers
// MUST reject unknown versions.

import type { VecDtype } from './hash.js';

export const PROTOCOL_VERSION = 1 as const;

/** Maximum accepted size of a serialized pin JSON (bytes). */
export const MAX_PIN_JSON_BYTES = 65536;

/** Maximum number of entries permitted in the `extra` map. */
export const MAX_EXTRA_ENTRIES = 32;

/** Maximum permitted embedding dimension (1 << 20). */
export const MAX_VEC_DIM = 1048576;

/** Top-level keys permitted in a pin JSON object. */
const ALLOWED_PIN_KEYS: ReadonlySet<string> = new Set([
  'v',
  'kid',
  'model',
  'model_hash',
  'source_hash',
  'vec_hash',
  'vec_dtype',
  'vec_dim',
  'ts',
  'extra',
  'sig',
]);

/** Keys that are forbidden as own properties — blocks prototype pollution. */
const FORBIDDEN_KEYS: ReadonlySet<string> = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

/**
 * The signed portion of a Pin.
 *
 * Everything except `sig` and `kid` lives here. Two Pins are
 * equivalent iff their headers canonicalize to identical bytes.
 */
export interface PinHeader {
  readonly v: number;
  readonly model: string;
  readonly source_hash: string;
  readonly vec_hash: string;
  readonly vec_dtype: VecDtype;
  readonly vec_dim: number;
  readonly ts: string;
  readonly model_hash?: string | undefined;
  readonly extra?: Readonly<Record<string, string>> | undefined;
}

/**
 * Build the dict form of a header for JSON serialization. Keys are
 * sorted alphabetically inside `canonicalize`; this function only
 * decides which fields are present.
 *
 * The returned object has a null prototype so that no accidental
 * inheritance from `Object.prototype` can sneak in.
 */
export function headerToDict(h: PinHeader): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  out['v'] = h.v;
  out['model'] = h.model;
  out['source_hash'] = h.source_hash;
  out['vec_hash'] = h.vec_hash;
  out['vec_dtype'] = h.vec_dtype;
  out['vec_dim'] = h.vec_dim;
  out['ts'] = h.ts;
  if (h.model_hash !== undefined && h.model_hash !== null) {
    out['model_hash'] = h.model_hash;
  }
  if (h.extra && Object.keys(h.extra).length > 0) {
    // Sort extra by key to match the Python reference output.
    const sortedExtra: Record<string, string> = Object.create(null);
    for (const k of Object.keys(h.extra).sort()) {
      sortedExtra[k] = h.extra[k]!;
    }
    out['extra'] = sortedExtra;
  }
  return out;
}

/**
 * Stable byte representation for signing/verifying.
 *
 * Uses JSON with sorted keys, no whitespace, raw UTF-8 (non-ASCII
 * passes through unescaped). This is the canonicalization form
 * with the best library support across languages while still being
 * deterministic.
 */
export function canonicalizeHeader(h: PinHeader): Uint8Array {
  return new TextEncoder().encode(canonicalJsonStringify(headerToDict(h)));
}

/** A signed pin attestation. */
export interface Pin {
  readonly header: PinHeader;
  readonly kid: string;
  /** Raw signature bytes (Ed25519 = 64 bytes). */
  readonly sig: Uint8Array;
}

/** Compact JSON encoding suitable for vector DB metadata fields. */
export function pinToJSON(pin: Pin): string {
  return canonicalJsonStringify(pinToDict(pin));
}

/** Plain-object representation; mirrors `Pin.to_dict` in Python. */
export function pinToDict(pin: Pin): Record<string, unknown> {
  const d = headerToDict(pin.header);
  d['kid'] = pin.kid;
  d['sig'] = b64UrlEncodeNoPad(pin.sig);
  return d;
}

export function pinFromJSON(s: string): Pin {
  if (typeof s !== 'string') {
    throw new Error('pin JSON must be a string');
  }
  if (Buffer.byteLength(s, 'utf8') > MAX_PIN_JSON_BYTES) {
    throw new Error(
      `pin JSON exceeds maximum size of ${MAX_PIN_JSON_BYTES} bytes`,
    );
  }
  const parsed: unknown = JSON.parse(s);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('pin JSON root must be an object');
  }
  return pinFromDict(parsed as Record<string, unknown>);
}

export function pinFromDict(d: Record<string, unknown>): Pin {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) {
    throw new Error('pin dict must be a plain object');
  }

  // Reject prototype-pollution payloads. Only own properties count;
  // `JSON.parse` produces objects with `Object.prototype` as their
  // prototype, so we must look at the literal keys present.
  const ownKeys = Object.keys(d);
  for (const k of ownKeys) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new Error(`forbidden key in pin: ${JSON.stringify(k)}`);
    }
    if (!ALLOWED_PIN_KEYS.has(k)) {
      throw new Error(`unknown pin field: ${JSON.stringify(k)}`);
    }
  }

  // Required scalars.
  if (typeof d['v'] !== 'number' || d['v'] !== PROTOCOL_VERSION) {
    throw new Error(
      `unsupported pin version ${JSON.stringify(d['v'])}; expected ${PROTOCOL_VERSION}`,
    );
  }
  if (typeof d['model'] !== 'string' || d['model'].length === 0) {
    throw new Error('pin.model must be a non-empty string');
  }
  if (typeof d['kid'] !== 'string') {
    throw new Error('pin.kid must be a string');
  }
  if (typeof d['ts'] !== 'string') {
    throw new Error('pin.ts must be a string');
  }
  if (typeof d['sig'] !== 'string') {
    throw new Error('pin.sig must be a string');
  }

  const dtype = d['vec_dtype'];
  if (typeof dtype !== 'string' || (dtype !== 'f32' && dtype !== 'f64')) {
    throw new Error(`unsupported vec_dtype ${JSON.stringify(dtype)}`);
  }

  const vecDim = d['vec_dim'];
  if (
    typeof vecDim !== 'number' ||
    !Number.isInteger(vecDim) ||
    vecDim <= 0 ||
    vecDim > MAX_VEC_DIM
  ) {
    throw new Error(
      `pin.vec_dim must be an integer in (0, ${MAX_VEC_DIM}]; got ${JSON.stringify(vecDim)}`,
    );
  }

  // Hash fields must look like sha256:<64-hex>.
  if (typeof d['source_hash'] !== 'string' || !SHA256_RE.test(d['source_hash'])) {
    throw new Error('pin.source_hash must match /^sha256:[0-9a-f]{64}$/');
  }
  if (typeof d['vec_hash'] !== 'string' || !SHA256_RE.test(d['vec_hash'])) {
    throw new Error('pin.vec_hash must match /^sha256:[0-9a-f]{64}$/');
  }

  // Optional model_hash.
  let modelHash: string | undefined;
  if ('model_hash' in d && d['model_hash'] !== undefined && d['model_hash'] !== null) {
    if (typeof d['model_hash'] !== 'string' || !SHA256_RE.test(d['model_hash'])) {
      throw new Error('pin.model_hash must match /^sha256:[0-9a-f]{64}$/');
    }
    modelHash = d['model_hash'];
  }

  // Optional extra map: string -> string, capped in size, no
  // forbidden keys.
  let extra: Record<string, string> | undefined;
  if ('extra' in d && d['extra'] !== undefined && d['extra'] !== null) {
    const extraRaw = d['extra'];
    if (typeof extraRaw !== 'object' || Array.isArray(extraRaw)) {
      throw new Error('pin.extra must be an object of string values');
    }
    const extraKeys = Object.keys(extraRaw as Record<string, unknown>);
    if (extraKeys.length > MAX_EXTRA_ENTRIES) {
      throw new Error(
        `pin.extra has ${extraKeys.length} entries; maximum is ${MAX_EXTRA_ENTRIES}`,
      );
    }
    const sanitized: Record<string, string> = Object.create(null);
    for (const k of extraKeys) {
      if (FORBIDDEN_KEYS.has(k)) {
        throw new Error(`forbidden key in pin.extra: ${JSON.stringify(k)}`);
      }
      const v = (extraRaw as Record<string, unknown>)[k];
      if (typeof v !== 'string') {
        throw new Error(
          `pin.extra[${JSON.stringify(k)}] must be a string; got ${typeof v}`,
        );
      }
      sanitized[k] = v;
    }
    extra = sanitized;
  }

  const header: PinHeader = {
    v: d['v'],
    model: d['model'],
    source_hash: d['source_hash'],
    vec_hash: d['vec_hash'],
    vec_dtype: dtype,
    vec_dim: vecDim,
    ts: d['ts'],
    model_hash: modelHash,
    extra,
  };

  // Validate base64url BEFORE decoding so we can be strict about
  // alphabet and reject standard-base64 (`+`/`/`) input.
  const sig = b64UrlDecodeStrict(d['sig']);
  if (sig.length !== 64) {
    throw new Error(`pin.sig must decode to 64 bytes (got ${sig.length})`);
  }

  return {
    header,
    kid: d['kid'],
    sig,
  };
}

// ---- canonical JSON ----

/**
 * Deterministic JSON encoder matching Python's
 * `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
 * and Rust's `serde_json` with sorted keys (see attestation::canonicalize).
 *
 * Sorts object keys at every depth, omits whitespace, and emits raw
 * UTF-8 (non-ASCII is not escaped to \uXXXX). We do not need full
 * canonical-JSON [RFC 8785] semantics — the protocol values are
 * scalars and shallow string maps, so a small recursive walk suffices.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('cannot canonicalize non-finite number');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJsonStringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

// ---- URL-safe base64 without padding ----

/**
 * URL-safe base64, no padding — matches Python's
 * `base64.urlsafe_b64encode(data).rstrip(b"=")` and Rust's
 * `URL_SAFE_NO_PAD`.
 */
export function b64UrlEncodeNoPad(data: Uint8Array): string {
  // Buffer is available in Node 20+ (the package's minimum); base64url
  // is the standard URL-safe alphabet without padding.
  return Buffer.from(data).toString('base64url');
}

export function b64UrlDecodeNoPad(s: string): Uint8Array {
  return b64UrlDecodeStrict(s);
}

/**
 * Strict base64url decoder. Rejects standard-base64 (`+`, `/`) and
 * any character outside the URL-safe alphabet. Padding is tolerated
 * on input (we emit without padding) but anything else is rejected
 * up front so we never feed garbage to `Buffer.from`.
 */
function b64UrlDecodeStrict(s: string): Uint8Array {
  if (typeof s !== 'string') {
    throw new Error('base64url input must be a string');
  }
  if (!B64URL_RE.test(s)) {
    throw new Error('base64url input contains invalid characters');
  }
  // Buffer.from with 'base64url' tolerates missing padding.
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
