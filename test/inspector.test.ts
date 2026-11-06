/**
 * Runs the script inside verify/inspector.html, not a copy of it. It shares no
 * code with src/, so checking it against the Go-generated vectors means two
 * independent implementations have to agree on the format.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { bytesToHex } from '../src/bytes';
import { hexToBytes } from './helpers';
import vectors from './vectors.json' with { type: 'json' };
import { SAMPLE_KEY, buildSamples } from '../verify/samples/make-samples.ts';

const html = readFileSync(new URL('../verify/inspector.html', import.meta.url), 'utf8');
const coreSource = html.match(/<script id="cln1-core">([\s\S]*?)<\/script>/)![1];
const CLN1 = new Function(`${coreSource}; return CLN1;`)();

const samplesDir = new URL('../verify/samples/', import.meta.url);
const sample = (name: string) => new Uint8Array(readFileSync(new URL(name, samplesDir)));
const photo = sample('sample-photo.jpg');

test('the page recovers the plaintext of every published vector', async () => {
  assert.ok(vectors.length > 0);
  for (const v of vectors as Array<{ name: string; key_hex: string; plain_hex: string; file_hex: string }>) {
    const { plain } = await CLN1.open(hexToBytes(v.file_hex), hexToBytes(v.key_hex));
    assert.equal(bytesToHex(plain), v.plain_hex, v.name);
  }
});

test('the sample files on disk are exactly what the generator builds', () => {
  for (const [name, bytes] of Object.entries(buildSamples(photo))) {
    assert.deepEqual(sample(name), bytes, name);
  }
});

test('the sample key shown on the page opens the samples', async () => {
  const shown = html.match(/<code>([0-9a-f]{64})<\/code>/)![1];
  assert.equal(shown, bytesToHex(SAMPLE_KEY));

  for (const name of ['sample-photo.cln1', 'sample-chunked.cln1']) {
    const { plain } = await CLN1.open(sample(name), CLN1.parseKey(shown));
    assert.deepEqual(plain, photo, name);
    assert.equal(CLN1.sniff(plain), 'JPEG');
  }
});

test('the chunked sample really has several chunks', async () => {
  const { chunks } = await CLN1.open(sample('sample-chunked.cln1'), SAMPLE_KEY);
  assert.ok(chunks > 1, `expected several chunks, got ${chunks}`);
});

test('one changed byte fails in the chunk it is in', async () => {
  const file = sample('sample-tampered.cln1');
  const { chunkSize } = CLN1.parseHeader(file);
  const last = CLN1.chunkCount(file.length, chunkSize) - 1;
  await assert.rejects(CLN1.open(file, SAMPLE_KEY), (e: { chunk: number }) => e.chunk === last);
});

test('a file cut at a chunk boundary fails on its new last chunk', async () => {
  const file = sample('sample-truncated.cln1');
  const { chunkSize } = CLN1.parseHeader(file);
  const last = CLN1.chunkCount(file.length, chunkSize) - 1;
  assert.ok(last > 0);
  await assert.rejects(CLN1.open(file, SAMPLE_KEY), (e: { chunk: number }) => e.chunk === last);
});

test('the wrong key fails on the first chunk', async () => {
  const wrong = SAMPLE_KEY.slice();
  wrong[0] ^= 0x01;
  await assert.rejects(CLN1.open(sample('sample-photo.cln1'), wrong), (e: { chunk: number }) => e.chunk === 0);
});

test('an edited header fails, because every chunk authenticates it', async () => {
  const file = sample('sample-photo.cln1');
  file[15] ^= 0x02; // key epoch
  await assert.rejects(CLN1.open(file, SAMPLE_KEY), (e: { chunk: number }) => e.chunk === 0);
});

test('a plain photo is reported as a plain photo, not as a CLN1 file', () => {
  assert.throws(() => CLN1.parseHeader(photo), /CLN1/);
  assert.equal(CLN1.sniff(photo), 'JPEG');
});

test('key parsing takes spaces and capitals, and nothing that is not a key', () => {
  const hex = bytesToHex(SAMPLE_KEY);
  assert.deepEqual(CLN1.parseKey(` ${hex.slice(0, 32).toUpperCase()} ${hex.slice(32)}\n`), SAMPLE_KEY);
  assert.throws(() => CLN1.parseKey(hex.slice(2)));
  assert.throws(() => CLN1.parseKey(`zz${hex.slice(2)}`));
  assert.throws(() => CLN1.parseKey(''));
});

test('the page has no way to reach the network', () => {
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)![1];
  assert.match(csp, /default-src 'none'/);
  assert.doesNotMatch(csp, /https?:|\*|connect-src/);

  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 2);
  for (const [, attrs, source] of scripts) {
    assert.doesNotMatch(attrs, /\bsrc=/);
    assert.doesNotMatch(source, /\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage|sessionStorage|indexedDB)\b/);
    // The policy can't stop a page navigating away, so the scripts must never try.
    assert.doesNotMatch(source, /\blocation\b|window\.open|\.submit\(/);
  }
  assert.doesNotMatch(html, /<link\b|<iframe\b|<form\b|https?:\/\//);
});
