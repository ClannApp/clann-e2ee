/**
 * Randomness is injected, never imported.
 *
 * This library runs in three places with three different CSPRNGs: React Native
 * (expo-crypto — Hermes has no `crypto.getRandomValues`), Node, and browsers.
 * Rather than sniff the environment, every function that needs entropy takes a
 * {@link RandomSource}. That also makes each one deterministically testable:
 * pass a fixed generator and the output is a reproducible vector.
 *
 * Callers on-device pass `expo-crypto`'s `getRandomBytes`; Node and browser
 * callers can pass {@link webCryptoRandom}.
 */

/** Returns exactly `n` cryptographically secure random bytes. */
export type RandomSource = (n: number) => Uint8Array;

/**
 * A {@link RandomSource} backed by the Web Crypto API. Available in Node 19+
 * and every browser; NOT available under Hermes, which is why this is a
 * convenience rather than the default.
 */
export const webCryptoRandom: RandomSource = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
};

/**
 * Draw `n` bytes and check the source honoured the length.
 *
 * A `RandomSource` that silently returns short — or, worse, all-zero — output
 * would produce keys that look fine and are catastrophically weak, so every
 * internal draw goes through here rather than calling the source directly.
 */
export function draw(random: RandomSource, n: number): Uint8Array {
  const bytes = random(n);
  if (!(bytes instanceof Uint8Array) || bytes.length !== n) {
    throw new Error(`random source returned ${(bytes as Uint8Array)?.length} bytes, expected ${n}`);
  }
  return bytes;
}
