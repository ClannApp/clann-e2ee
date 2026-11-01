import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  PROFILE_KEY_SIZE,
  generateProfileKey,
  unwrapAvatarDek,
  unwrapProfileKey,
  wrapAvatarDek,
  wrapProfileKey,
  type ProfileSubject,
} from '../src/profileKey';
import { generateDek, isWellFormedEncMeta } from '../src/keyWrap';
import { decrypt, encryptWithHeader, makeHeader, CLN1_MEDIA_JPEG } from '../src/cln1';
import { seededRandom } from './helpers';

const groupKey = new Uint8Array(32).fill(0x11);
const otherGroupKey = new Uint8Array(32).fill(0x12);
const aoife: ProfileSubject = { type: 'child', id: 'child-aoife' };
const cian: ProfileSubject = { type: 'child', id: 'child-cian' };

test('a profile key round-trips through a group wrap', () => {
  const rnd = seededRandom();
  const pk = generateProfileKey(rnd);
  assert.equal(pk.length, PROFILE_KEY_SIZE);
  const wrap = wrapProfileKey(groupKey, 3, pk, aoife, 1, 'group-a', rnd);
  assert.equal(wrap.key_epoch, 3);
  assert.deepEqual(unwrapProfileKey(groupKey, wrap, aoife, 1, 'group-a'), pk);
});

test('a profile key wrap only opens for the person, version and group it was written for', () => {
  const rnd = seededRandom(7);
  const pk = generateProfileKey(rnd);
  const wrap = wrapProfileKey(groupKey, 1, pk, aoife, 1, 'group-a', rnd);

  // The substitution a server would attempt: Aoife's wrap presented as Cian's.
  assert.throws(() => unwrapProfileKey(groupKey, wrap, cian, 1, 'group-a'));
  assert.throws(() => unwrapProfileKey(groupKey, wrap, { type: 'user', id: 'child-aoife' }, 1, 'group-a'));
  assert.throws(() => unwrapProfileKey(groupKey, wrap, aoife, 2, 'group-a'));
  assert.throws(() => unwrapProfileKey(groupKey, wrap, aoife, 1, 'group-b'));
  assert.throws(() => unwrapProfileKey(otherGroupKey, wrap, aoife, 1, 'group-a'));
});

test('an avatar opens end to end: group key → profile key → DEK → CLN1', () => {
  const rnd = seededRandom(3);
  const pk = generateProfileKey(rnd);
  const dek = generateDek(rnd);
  const image = new TextEncoder().encode('\xff\xd8\xff pretend jpeg');

  const encMeta = wrapAvatarDek(pk, 1, dek, aoife, rnd);
  assert.equal(isWellFormedEncMeta(encMeta), true, 'hosts shape-check it like a photo enc_meta');
  assert.equal(encMeta.key_epoch, 1, 'key_epoch carries the profile key version');
  const file = encryptWithHeader(dek, makeHeader(CLN1_MEDIA_JPEG, 1, rnd(16)), image);

  const groupWrap = wrapProfileKey(groupKey, 1, pk, aoife, 1, 'group-a', rnd);
  const openedPk = unwrapProfileKey(groupKey, groupWrap, aoife, 1, 'group-a');
  const openedDek = unwrapAvatarDek(openedPk, encMeta, aoife);
  assert.deepEqual(decrypt(openedDek, file), image);
});

test("an avatar DEK does not open as someone else's", () => {
  const rnd = seededRandom(9);
  const pk = generateProfileKey(rnd);
  const encMeta = wrapAvatarDek(pk, 1, generateDek(rnd), aoife, rnd);
  assert.throws(() => unwrapAvatarDek(pk, encMeta, cian));
  assert.throws(() => unwrapAvatarDek(pk, { ...encMeta, key_epoch: 2 }, aoife));
});

test('rejects ids that would make the AAD ambiguous', () => {
  const rnd = seededRandom();
  const pk = generateProfileKey(rnd);
  assert.throws(() => wrapProfileKey(groupKey, 1, pk, { type: 'child', id: 'a|b' }, 1, 'group-a', rnd));
  assert.throws(() => wrapProfileKey(groupKey, 1, pk, aoife, 1, 'group|a', rnd));
  assert.throws(() => wrapProfileKey(groupKey, 1, pk, aoife, 0, 'group-a', rnd));
});
