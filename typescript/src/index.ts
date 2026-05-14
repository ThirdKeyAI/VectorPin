// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// VectorPin — verifiable integrity for AI embedding stores.
//
// This package is the TypeScript reference implementation of
// VectorPin protocol version 2. It is byte-for-byte compatible with
// the Python and Rust ports: identical canonical bytes, identical
// signatures. Compatibility is enforced by shared test vectors at
// `testvectors/v2.json` consumed by all three ports.
//
// Quick start:
//
//     import { Signer, Verifier } from 'vectorpin';
//
//     const signer = Signer.generate('demo-2026-05');
//     const vector = new Float32Array([0.1, 0.2, 0.3]);
//     const pin = await signer.pin({
//       source: 'hello',
//       model: 'text-embedding-3-large',
//       vector,
//     });
//
//     const verifier = new Verifier({
//       [signer.keyId]: await signer.publicKeyBytes(),
//     });
//     const result = await verifier.verify(pin, { source: 'hello', vector });
//     if (!result.ok) throw new Error(`verify failed: ${result.error}`);

export {
  b64UrlDecodeNoPad,
  b64UrlEncodeNoPad,
  canonicalizeHeader,
  canonicalizeHeaderV1,
  canonicalJsonStringify,
  DOMAIN_TAG,
  MAX_EXTRA_ENTRIES,
  MAX_EXTRA_KEY_BYTES,
  MAX_EXTRA_VALUE_BYTES,
  MAX_PIN_JSON_BYTES,
  MAX_VEC_DIM,
  pinFromDict,
  pinFromJSON,
  pinKid,
  pinToDict,
  pinToJSON,
  PROTOCOL_VERSION,
  SIG_LEN,
  type Pin,
  type PinHeader,
  type PinParseOptions,
} from './attestation.js';

export {
  canonicalVectorBytes,
  hashBytes,
  hashText,
  hashVector,
  type VecDtype,
  type VectorInput,
} from './hash.js';

export { formatUtcIsoSecond, Signer, type SignerPinOptions } from './signer.js';

export {
  LegacyV1Verifier,
  Verifier,
  VerifyErrorCode,
  type KeyEntry,
  type KeyRegistration,
  type VerificationResult,
  type VerifyOptions,
} from './verifier.js';
