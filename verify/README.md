# Clann E2EE Inspector

`inspector.html` opens a Clann encrypted file (the CLN1 format, [PROTOCOL.md](../PROTOCOL.md) section 4) on your own computer. It is one file with no libraries or build step, and its content security policy blocks network requests. Read it, disconnect from the network if you like, and open it in a browser.

It shares no code with `src/`. `test/inspector.test.ts` runs its script against the vectors in `test/vectors.json`, which a separate Go implementation generates.

## What you need

- **An encrypted file.** It's stronger evidence if you get this yourself, by [capturing the upload](CAPTURE.md), rather than from the app.
- **The media key,** for that photo or video. In the app, open it, tap the **⋯** menu, then **What Clann sees**, then **Get this memory's key**. The app asks for Face ID, a fingerprint or the phone's passcode first.

The media key is a secret. Anyone with the key and the file can open that memory in every stored size, and the key never changes. Don't put it in a bug report, a URL or a chat. Use a test photo: the page's **Make a test photo** button makes one with a random ID, so you never need a real family photo.

## What a pass means

> Photo encryption check passed: this file is authenticated CLN1 ciphertext and decrypts locally with the supplied media key.

It does not show where the file came from, who else holds the key, or that every app version, device or network path behaves the same way.

## Checking a real upload

[CAPTURE.md](CAPTURE.md) watches the app upload a test photo through mitmproxy, then authenticates what left the phone. `capture/` holds the tools. Its result is worded differently from the Inspector's:

> Observed upload check passed: in the captured and successfully inspected traffic, the photo upload contained authenticated ciphertext. No plaintext media or secret keys were detected in the inspected upload traffic.

## Samples

`samples/` has files you can try without the app, using a public key that protects nothing:

```
7557e96eb4cb9265d07f285b0f850957cec7c9ed238ae4a402ff004074232608
```

| File | Expected result |
| --- | --- |
| `sample-photo.cln1` | Passes |
| `sample-chunked.cln1` | Passes, over several chunks |
| `sample-tampered.cln1` | Fails: one byte changed |
| `sample-truncated.cln1` | Fails: last chunk removed |
| `sample-photo.jpg` | Reported as a plain JPEG, not encrypted |

To rebuild them, from this repository's root:

```
node --import ./test/hooks.mjs verify/samples/make-samples.ts
```
