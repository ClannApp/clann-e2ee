/**
 * Builds the sample files for verify/inspector.html from sample-photo.jpg.
 * Everything is fixed, so anyone can regenerate them and get the same bytes.
 * The key is public and protects nothing.
 *
 * Run from clann-e2ee/:
 *   node --import ./test/hooks.mjs verify/samples/make-samples.ts
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { CLN1_MEDIA_JPEG, encryptWithHeader, makeHeader } from '../../src/cln1.ts';

export const SAMPLE_KEY = new Uint8Array(
  createHash('sha256').update('clann-e2ee public sample key, protects nothing').digest(),
);
const SMALL_CHUNK = 8 * 1024;
const TAG_SIZE = 16;

const fixedRandom = (seed: string) =>
  new Uint8Array(createHash('sha256').update(seed).digest().subarray(0, 16));

export function buildSamples(photo: Uint8Array): Record<string, Uint8Array> {
  const whole = encryptWithHeader(
    SAMPLE_KEY,
    makeHeader(CLN1_MEDIA_JPEG, 1, fixedRandom('sample-photo')),
    photo,
  );
  const chunked = encryptWithHeader(
    SAMPLE_KEY,
    makeHeader(CLN1_MEDIA_JPEG, 1, fixedRandom('sample-chunked'), SMALL_CHUNK),
    photo,
  );

  const tampered = chunked.slice();
  tampered[tampered.length - TAG_SIZE - 1] ^= 0x01;

  // Cut exactly at a chunk boundary: every remaining chunk is intact, so only
  // the last-chunk flag in the nonce can catch it.
  const lastChunkSize = (photo.length % SMALL_CHUNK || SMALL_CHUNK) + TAG_SIZE;
  const truncated = chunked.slice(0, chunked.length - lastChunkSize);

  return {
    'sample-photo.cln1': whole,
    'sample-chunked.cln1': chunked,
    'sample-tampered.cln1': tampered,
    'sample-truncated.cln1': truncated,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = new URL('./', import.meta.url);
  const samples = buildSamples(new Uint8Array(readFileSync(new URL('sample-photo.jpg', dir))));
  for (const [name, bytes] of Object.entries(samples)) {
    writeFileSync(new URL(name, dir), bytes);
    console.log(name, bytes.length);
  }
}
