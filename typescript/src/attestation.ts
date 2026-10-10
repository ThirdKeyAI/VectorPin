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
// canonical byte sequence — DOMAIN_TAG || canonical_json(header) —
// NOT over the JSON encoding, so downstream re-serialization
// (whitespace, key order) cannot invalidate signatures.
//
// Protocol version: PROTOCOL_VERSION (currently 2). v2 prepends a
// 13-byte domain separator (`DOMAIN_TAG`) to the canonical JSON
// before signing, and binds BOTH `v` and `kid` into the signed
// payload to prevent downgrade and key-swap attacks. See
// docs/spec.md §4.2 and §12 for the full rationale.
//
// v2 is a wire-format break with v1; v1 pins do not verify under the
// default v2 verifier. A `LegacyV1Verifier` is provided for migration.

import { assertNoLoneSurrogates, type VecDtype } from './hash.js';

export const PROTOCOL_VERSION = 2 as const;

/**
 * 13-byte domain separator: literally `"vectorpin/v2\x00"`. Prepended
 * to canonical JSON before Ed25519 signing so a VectorPin v2
 * signature cannot collide with any other "signed canonical JSON"
 * message.
 *
 * The byte string IS the contract; cross-language ports MUST match
 * these bytes.
 */
export const DOMAIN_TAG: Uint8Array = new Uint8Array([
  // v   e    c    t    o    r    p    i    n    /    v    2    \0
  118, 101, 99, 116, 111, 114, 112, 105, 110, 47, 118, 50, 0,
]);
if (DOMAIN_TAG.length !== 13) {
  // Defensive: if anyone edits the literal above and miscounts, fail
  // at module load rather than silently emitting invalid pins.
  throw new Error(`DOMAIN_TAG must be exactly 13 bytes; got ${DOMAIN_TAG.length}`);
}

/** Maximum accepted size of a serialized pin JSON (bytes). */
export const MAX_PIN_JSON_BYTES = 65536;

/** Maximum number of entries permitted in the `extra` map. */
export const MAX_EXTRA_ENTRIES = 32;

/** Maximum UTF-8 byte length of any `extra` key. */
export const MAX_EXTRA_KEY_BYTES = 128;

/** Maximum UTF-8 byte length of any `extra` value. */
export const MAX_EXTRA_VALUE_BYTES = 1024;

/** Maximum permitted embedding dimension (1 << 20). */
export const MAX_VEC_DIM = 1048576;

/** Ed25519 raw signature length, in bytes. */
export const SIG_LEN = 64;

/**
 * Maximum UTF-8 byte length of `kid` (§4.3). Checked before NFC and the
 * control-character scan so a hostile object handed to `pinFromDict`
 * (which has no pre-parse byte cap) cannot push a huge string through.
 */
export const MAX_KID_BYTES = 256;

/** Maximum UTF-8 byte length of `model` (§4.3). */
export const MAX_MODEL_BYTES = 1024;

/** Top-level keys permitted in a v2 pin JSON object (§4.1). */
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
/** URL-safe alphabet, no padding — matches Python/Rust strict decoders. */
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/** Strict v2 timestamp: `YYYY-MM-DDTHH:MM:SSZ`, exactly. */
const TS_RE_V2 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * Number literals for `v` / `vec_dim` that are not minimal integers.
 * `JSON.parse` collapses `2.0` and `2` to the same number, so the only
 * place the lexical form can be checked is the raw JSON text. A `"v"`
 * key can only appear unescaped at the top level or as an `extra` key
 * (whose value must be a string, so a number there is rejected anyway).
 */
const NON_INTEGER_LITERAL_RE = /"(?:v|vec_dim)"\s*:\s*-?(?:\d+\.|\d*\.\d+|\d+(?:\.\d+)?[eE])/;

const UTF8_ENCODER = new TextEncoder();

/** UTF-8 byte length of a string without depending on Node's `Buffer`. */
export function utf8ByteLength(s: string): number {
  return UTF8_ENCODER.encode(s).byteLength;
}

/**
 * The signed portion of a Pin (everything except `sig`).
 *
 * Two Pins are equivalent iff their headers canonicalize to identical
 * bytes. In v2, the header includes `v` and `kid` so both are bound
 * by the signature.
 */
export interface PinHeader {
  readonly v: number;
  readonly kid: string;
  readonly model: string;
  readonly source_hash: string;
  readonly vec_hash: string;
  readonly vec_dtype: VecDtype;
  readonly vec_dim: number;
  readonly ts: string;
  readonly model_hash?: string | undefined;
  readonly extra?: Readonly<Record<string, string>> | undefined;
}

/** A signed pin attestation. */
export interface Pin {
  readonly header: PinHeader;
  /** Raw signature bytes (Ed25519 = 64 bytes). */
  readonly sig: Uint8Array;
}

/**
 * Convenience accessor — `kid` is part of the header in v2.
 *
 * Provided so callers that previously read `pin.kid` (v1 era) keep
 * working. New code should reach into `pin.header.kid` directly.
 */
export function pinKid(pin: Pin): string {
  return pin.header.kid;
}

/**
 * Build the dict form of a header for JSON serialization. Keys are
 * sorted lexicographically inside `canonicalJsonStringify`; this
 * function only decides which fields are present.
 *
 * The returned object has a null prototype so that no accidental
 * inheritance from `Object.prototype` can sneak in.
 */
export function headerToDict(h: PinHeader): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  out['v'] = h.v;
  out['kid'] = h.kid;
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
    const sortedExtra: Record<string, string> = Object.create(null);
    for (const k of Object.keys(h.extra).sort()) {
      sortedExtra[k] = h.extra[k]!;
    }
    out['extra'] = sortedExtra;
  }
  return out;
}

/**
 * Stable byte representation for signing/verifying a v2 pin.
 *
 * Returns `DOMAIN_TAG || canonical_json(header)`. All string-typed
 * fields are NFC-normalized at canonicalization time; non-NFC input
 * is rejected so signers cannot silently emit pins a strict verifier
 * would later refuse.
 */
export function canonicalizeHeader(h: PinHeader): Uint8Array {
  // NFC-normalize string fields in place, then re-sort `extra` since
  // NFC composition can change Unicode code-point order.
  const d = headerToDict(h);
  d['kid'] = nfcOrThrow(d['kid'] as string, 'kid');
  d['model'] = nfcOrThrow(d['model'] as string, 'model');
  d['ts'] = nfcOrThrow(d['ts'] as string, 'ts');
  if ('model_hash' in d && typeof d['model_hash'] === 'string') {
    d['model_hash'] = nfcOrThrow(d['model_hash'], 'model_hash');
  }
  if ('extra' in d && d['extra'] && typeof d['extra'] === 'object') {
    const e = d['extra'] as Record<string, string>;
    const normalized: Record<string, string> = Object.create(null);
    for (const k of Object.keys(e)) {
      const kn = nfcOrThrow(k, `extra key ${JSON.stringify(k)}`);
      const vn = nfcOrThrow(e[k]!, `extra[${JSON.stringify(k)}]`);
      normalized[kn] = vn;
    }
    const sorted: Record<string, string> = Object.create(null);
    for (const k of Object.keys(normalized).sort()) {
      sorted[k] = normalized[k]!;
    }
    d['extra'] = sorted;
  }
  const body = UTF8_ENCODER.encode(canonicalJsonStringify(d));
  const out = new Uint8Array(DOMAIN_TAG.length + body.length);
  out.set(DOMAIN_TAG, 0);
  out.set(body, DOMAIN_TAG.length);
  return out;
}

/**
 * Legacy v1 canonicalization, kept for `LegacyV1Verifier` only.
 *
 * v1 differed from v2 in three ways:
 *   - No domain-tag prefix.
 *   - `kid` was NOT included in the signed payload.
 *   - No NFC / control-char / bidi enforcement on string fields.
 *
 * The output here is byte-for-byte identical to what the v1 reference
 * implementation produced, so historical pins continue to verify.
 */
export function canonicalizeHeaderV1(h: PinHeader): Uint8Array {
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
    const sortedExtra: Record<string, string> = Object.create(null);
    for (const k of Object.keys(h.extra).sort()) {
      sortedExtra[k] = h.extra[k]!;
    }
    out['extra'] = sortedExtra;
  }
  return UTF8_ENCODER.encode(canonicalJsonStringify(out));
}

/** Compact JSON encoding suitable for vector DB metadata fields. */
export function pinToJSON(pin: Pin): string {
  return canonicalJsonStringify(pinToDict(pin));
}

/** Plain-object representation; mirrors `Pin.to_dict` in Python. */
export function pinToDict(pin: Pin): Record<string, unknown> {
  const d = headerToDict(pin.header);
  d['sig'] = b64UrlEncodeNoPad(pin.sig);
  return d;
}

/** Options for the parser; legacy mode is for `LegacyV1Verifier` only. */
export interface PinParseOptions {
  /** If true, accept v1 pins with the looser v1 validation rules. */
  acceptV1Legacy?: boolean;
}

export function pinFromJSON(s: string, opts: PinParseOptions = {}): Pin {
  if (typeof s !== 'string') {
    throw new Error('pin JSON must be a string');
  }
  // Measure the raw UTF-8 byte size before JSON.parse runs so we cap
  // parser memory use, not just the resulting object. Code units are a
  // cheap lower bound, so an enormous string is refused before encoding.
  if (s.length > MAX_PIN_JSON_BYTES || utf8ByteLength(s) > MAX_PIN_JSON_BYTES) {
    throw new Error(`pin JSON exceeds maximum size of ${MAX_PIN_JSON_BYTES} bytes`);
  }
  if (NON_INTEGER_LITERAL_RE.test(s)) {
    throw new Error('pin.v / pin.vec_dim must be minimal integer literals');
  }
  const parsed: unknown = JSON.parse(s);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('pin JSON root must be an object');
  }
  return pinFromDict(parsed as Record<string, unknown>, opts);
}

export function pinFromDict(d: Record<string, unknown>, opts: PinParseOptions = {}): Pin {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) {
    throw new Error('pin dict must be a plain object');
  }
  const acceptV1 = opts.acceptV1Legacy === true;

  // Reject prototype-pollution payloads + unknown top-level keys.
  const ownKeys = Object.keys(d);
  for (const k of ownKeys) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new Error(`forbidden key in pin: ${JSON.stringify(k)}`);
    }
    if (!ALLOWED_PIN_KEYS.has(k)) {
      throw new Error(`unknown pin field: ${JSON.stringify(k)}`);
    }
  }

  // Version.
  const v = d['v'];
  if (typeof v !== 'number' || !Number.isInteger(v)) {
    throw new Error(`pin.v must be an integer; got ${JSON.stringify(v)}`);
  }
  const isV2 = v === PROTOCOL_VERSION;
  if (!isV2 && !(acceptV1 && v === 1)) {
    throw new Error(
      `unsupported pin version ${JSON.stringify(v)}; expected ${PROTOCOL_VERSION}`,
    );
  }

  // Required string scalars.
  if (typeof d['model'] !== 'string' || d['model'].length === 0) {
    throw new Error('pin.model must be a non-empty string');
  }
  if (typeof d['kid'] !== 'string' || d['kid'].length === 0) {
    throw new Error('pin.kid must be a non-empty string');
  }
  if (typeof d['ts'] !== 'string' || d['ts'].length === 0) {
    throw new Error('pin.ts must be a non-empty string');
  }
  if (typeof d['sig'] !== 'string') {
    throw new Error('pin.sig must be a string');
  }

  const model = d['model'];
  const kid = d['kid'];
  const ts = d['ts'];

  // Byte caps first (§4.3) so an oversized string never reaches the
  // normalization passes; lone surrogates are refused on every path
  // because they cannot be canonicalized.
  assertByteCap(model, MAX_MODEL_BYTES, 'model');
  assertByteCap(kid, MAX_KID_BYTES, 'kid');
  assertByteCap(ts, MAX_MODEL_BYTES, 'ts');
  assertNoLoneSurrogates(model, 'pin.model');
  assertNoLoneSurrogates(kid, 'pin.kid');
  assertNoLoneSurrogates(ts, 'pin.ts');

  // v2-strict string validation.
  if (isV2) {
    assertSafeString(model, 'model');
    assertSafeString(kid, 'kid');
    assertSafeString(ts, 'ts');
    assertNfc(model, 'model');
    assertNfc(kid, 'kid');
    assertNfc(ts, 'ts');
    if (!TS_RE_V2.test(ts)) {
      throw new Error("pin.ts must match 'YYYY-MM-DDTHH:MM:SSZ' exactly");
    }
    if (!isValidCalendarTs(ts)) {
      throw new Error('pin.ts is not a valid calendar date-time');
    }
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

  // Hash fields.
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

  // Optional extra map: strictly string -> string, bounded. `null` is
  // not "absent" (§4.1): the field is an object or not present at all.
  let extra: Record<string, string> | undefined;
  if ('extra' in d && d['extra'] !== undefined) {
    const extraRaw = d['extra'];
    if (extraRaw === null || typeof extraRaw !== 'object' || Array.isArray(extraRaw)) {
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
      assertByteCap(k, MAX_EXTRA_KEY_BYTES, 'extra key');
      const val = (extraRaw as Record<string, unknown>)[k];
      if (typeof val !== 'string') {
        throw new Error(
          `pin.extra[${JSON.stringify(k)}] must be a string; got ${typeof val}`,
        );
      }
      assertByteCap(val, MAX_EXTRA_VALUE_BYTES, `extra[${JSON.stringify(k)}]`);
      assertNoLoneSurrogates(k, `extra key ${JSON.stringify(k)}`);
      assertNoLoneSurrogates(val, `extra[${JSON.stringify(k)}]`);
      if (isV2) {
        assertSafeString(k, `extra key ${JSON.stringify(k)}`);
        assertSafeString(val, `extra[${JSON.stringify(k)}]`);
        assertNfc(k, `extra key ${JSON.stringify(k)}`);
        assertNfc(val, `extra[${JSON.stringify(k)}]`);
      }
      sanitized[k] = val;
    }
    extra = sanitized;
  }

  // Validate base64url BEFORE decoding so the alphabet check is
  // strict (rejects standard-base64 `+`/`/` input, padding, and
  // non-canonical trailing bits).
  if (d['sig'].length > 4 * SIG_LEN) {
    throw new Error('pin.sig is too long to be a base64url Ed25519 signature');
  }
  const sig = b64UrlDecodeStrict(d['sig']);
  if (sig.length !== SIG_LEN) {
    throw new Error(`pin.sig must decode to ${SIG_LEN} bytes (got ${sig.length})`);
  }

  const header: PinHeader = {
    v,
    kid,
    model,
    source_hash: d['source_hash'],
    vec_hash: d['vec_hash'],
    vec_dtype: dtype,
    vec_dim: vecDim,
    ts,
    model_hash: modelHash,
    extra,
  };

  return { header, sig };
}

// ---- string-safety helpers ----

/**
 * Reject strings that contain ASCII control characters (U+0000-U+001F),
 * Unicode bidi-override code points (U+202A-U+202E, U+2066-U+2069), or
 * lone surrogates. Required by spec §3.1.
 */
export function assertSafeString(value: string, fieldName: string): void {
  assertNoLoneSurrogates(value, fieldName);
  for (let i = 0; i < value.length; i++) {
    const cp = value.charCodeAt(i);
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
}

/** Reject a string whose UTF-8 encoding exceeds `limit` bytes. */
function assertByteCap(value: string, limit: number, fieldName: string): void {
  // One code unit is at least one byte, so a long string is refused
  // without encoding it.
  if (value.length > limit || utf8ByteLength(value) > limit) {
    throw new Error(`pin.${fieldName} exceeds ${limit} bytes`);
  }
}

/**
 * True iff a `TS_RE_V2`-shaped string denotes a real proleptic-Gregorian
 * UTC instant: month 01-12, day valid for the month (leap years
 * honored), hour 00-23, minute 00-59, second 00-59. `Date.parse` is not
 * used because V8 rolls `2026-02-30` forward to March 2.
 */
export function isValidCalendarTs(ts: string): boolean {
  if (!TS_RE_V2.test(ts)) return false;
  const year = Number(ts.slice(0, 4));
  const month = Number(ts.slice(5, 7));
  const day = Number(ts.slice(8, 10));
  const hour = Number(ts.slice(11, 13));
  const minute = Number(ts.slice(14, 16));
  const second = Number(ts.slice(17, 19));
  if (month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]!;
  if (day > daysInMonth) return false;
  return hour <= 23 && minute <= 59 && second <= 59;
}

/**
 * Return `value` unchanged if it is already in NFC form; otherwise
 * throw. The signer's input path normalizes before reaching here so
 * this only catches a header that was constructed with non-NFC
 * strings directly.
 */
function nfcOrThrow(value: string, fieldName: string): string {
  assertNoLoneSurrogates(value, fieldName);
  if (value !== value.normalize('NFC')) {
    throw new Error(`${fieldName} is not NFC-normalized`);
  }
  return value;
}

/** Throw if `value` is not already in NFC form. */
function assertNfc(value: string, fieldName: string): void {
  if (value !== value.normalize('NFC')) {
    throw new Error(`${fieldName} is not NFC-normalized`);
  }
}

// ---- canonical JSON ----

/**
 * Deterministic JSON encoder matching Python's
 * `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
 * and Rust's `serde_json` with sorted keys (see attestation::canonicalize).
 *
 * Sorts object keys at every depth, omits whitespace, and emits raw
 * UTF-8 (non-ASCII is not escaped to \uXXXX). The protocol values
 * are scalars and shallow string maps, so a small recursive walk
 * suffices.
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
//
// Implemented in plain JavaScript (no Node `Buffer`) so the package runs
// unchanged in Deno, Bun, browsers, and edge runtimes.

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_LOOKUP: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) {
    table[B64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/**
 * URL-safe base64, no padding — matches Python's
 * `base64.urlsafe_b64encode(data).rstrip(b"=")` and Rust's
 * `URL_SAFE_NO_PAD`.
 */
export function b64UrlEncodeNoPad(data: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < data.length; i += 3) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8) | data[i + 2]!;
    out +=
      B64URL_ALPHABET[(n >>> 18) & 63]! +
      B64URL_ALPHABET[(n >>> 12) & 63]! +
      B64URL_ALPHABET[(n >>> 6) & 63]! +
      B64URL_ALPHABET[n & 63]!;
  }
  const rest = data.length - i;
  if (rest === 1) {
    const n = data[i]! << 16;
    out += B64URL_ALPHABET[(n >>> 18) & 63]! + B64URL_ALPHABET[(n >>> 12) & 63]!;
  } else if (rest === 2) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8);
    out +=
      B64URL_ALPHABET[(n >>> 18) & 63]! +
      B64URL_ALPHABET[(n >>> 12) & 63]! +
      B64URL_ALPHABET[(n >>> 6) & 63]!;
  }
  return out;
}

export function b64UrlDecodeNoPad(s: string): Uint8Array {
  return b64UrlDecodeStrict(s);
}

/**
 * Strict base64url decoder. Accepts only the URL-safe alphabet with no
 * padding, a length the encoder could have produced, and zero trailing
 * bits — i.e. exactly the canonical encoding of the decoded bytes. This
 * matches the Rust port's `URL_SAFE_NO_PAD` decoder and the Python
 * port's canonical check, so no port accepts a `sig` another rejects.
 */
function b64UrlDecodeStrict(s: string): Uint8Array {
  if (typeof s !== 'string') {
    throw new Error('base64url input must be a string');
  }
  if (!B64URL_RE.test(s)) {
    throw new Error('base64url input contains invalid characters');
  }
  const rem = s.length % 4;
  if (rem === 1) {
    throw new Error('base64url input has an invalid length');
  }
  const outLen = Math.floor((s.length * 6) / 8);
  const out = new Uint8Array(outLen);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64URL_LOOKUP[s.charCodeAt(i)]!;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // Any leftover bits must be zero, otherwise the input is not the
  // canonical encoding of `out` (non-canonical "last symbol").
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new Error('base64url input has non-zero trailing bits');
  }
  return out;
}
