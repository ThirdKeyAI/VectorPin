// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Canonical hashing for source text and embedding vectors.
//
// These three operations are the only places in the protocol where
// semantic content gets turned into bytes. The Python and Rust ports
// agree on the byte semantics here, so this implementation pins down
// the same contract:
//
//   * Vectors: little-endian, 1-D, packed `f32` or `f64` bytes.
//   * Text: UTF-8 of the NFC-normalized string.
//   * Output digests: prefixed with `"sha256:"` and lowercase hex.

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

/** Canonical scalar dtype identifier carried in the wire format. */
export type VecDtype = 'f32' | 'f64';

/**
 * A 1-D vector view accepted by the canonicalization helpers. Plain
 * `number[]`, `Float32Array`, and `Float64Array` are all supported
 * — the dtype the caller passes determines how the bytes are packed.
 *
 * A `Float32Array` is a 32-bit representation; a `Float64Array` and a
 * plain `number[]` (JavaScript numbers are doubles) are 64-bit ones.
 * The verifier refuses a 64-bit input against an `f32` pin, so pass a
 * `Float32Array` when your store persists single precision.
 */
export type VectorInput = readonly number[] | Float32Array | Float64Array;

/**
 * Reproducible byte form of an embedding vector.
 *
 * Always little-endian, always packed, always under the dtype the
 * caller specifies. Two implementations must agree on these bytes
 * byte-for-byte for cross-language verification to work.
 */
export function canonicalVectorBytes(vector: VectorInput, dtype: VecDtype): Uint8Array {
  if (vector.length === 0) {
    throw new Error('cannot canonicalize empty vector');
  }
  const bytesPerElem = dtype === 'f32' ? 4 : 8;
  const out = new Uint8Array(vector.length * bytesPerElem);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  if (dtype === 'f32') {
    for (let i = 0; i < vector.length; i++) {
      // `vector[i]!` is safe — we just bounded i to vector.length.
      view.setFloat32(i * 4, vector[i]!, /* littleEndian */ true);
    }
  } else {
    for (let i = 0; i < vector.length; i++) {
      view.setFloat64(i * 8, vector[i]!, /* littleEndian */ true);
    }
  }
  return out;
}

/** SHA-256 of a vector's canonical bytes, formatted as `"sha256:<hex>"`. */
export function hashVector(vector: VectorInput, dtype: VecDtype = 'f32'): string {
  return sha256Prefixed(canonicalVectorBytes(vector, dtype));
}

/**
 * Throw if `value` contains a lone surrogate code unit. A JavaScript
 * string can hold one, but it has no UTF-8 encoding: `TextEncoder`
 * would silently substitute U+FFFD, producing bytes that no other
 * implementation can reproduce. Equivalent to `!value.isWellFormed()`
 * without requiring the ES2024 lib.
 */
export function assertNoLoneSurrogates(value: string, fieldName: string): void {
  for (let i = 0; i < value.length; i++) {
    const cu = value.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      throw new Error(`${fieldName} contains a lone surrogate code unit`);
    }
    if (cu >= 0xdc00 && cu <= 0xdfff) {
      throw new Error(`${fieldName} contains a lone surrogate code unit`);
    }
  }
}

/** Native canonical dtype of a vector input (see `VectorInput`). */
export function nativeDtype(vector: VectorInput): VecDtype {
  return vector instanceof Float32Array ? 'f32' : 'f64';
}

/** Byte width of one element of `vector` as the verifier sees it. */
export function vectorElementWidth(vector: VectorInput): number {
  // JavaScript numbers are IEEE-754 doubles, so a plain `number[]` is a
  // 64-bit representation whatever values it happens to hold.
  return vector instanceof Float32Array ? 4 : 8;
}

/**
 * SHA-256 of a string after Unicode NFC normalization and UTF-8 encoding.
 * Throws if the string contains a lone surrogate (it cannot be encoded).
 */
export function hashText(text: string): string {
  assertNoLoneSurrogates(text, 'text');
  const nfc = text.normalize('NFC');
  return sha256Prefixed(new TextEncoder().encode(nfc));
}

/** SHA-256 over arbitrary bytes, formatted as `"sha256:<hex>"`. */
export function hashBytes(data: Uint8Array): string {
  return sha256Prefixed(data);
}

function sha256Prefixed(data: Uint8Array): string {
  return `sha256:${bytesToHex(sha256(data))}`;
}
