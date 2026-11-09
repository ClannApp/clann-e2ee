# Checking what the app uploads

This guide watches the Clann app upload a photo and checks the bytes that leave the phone. You need no access to Clann's servers or to the app's source code. It takes about an hour.

The result covers one run: this app version, this phone and this network path. It's still stronger evidence than the app's own word, because the tools read the bytes themselves.

## What you need

- [mitmproxy](https://mitmproxy.org). The tools run inside it, so there's nothing else to install.
- An iPhone with Clann from the App Store. Android release builds don't trust certificates you install yourself, so without a rooted device the app's HTTPS connections are refused and the run can't say anything.
- A Mac with Xcode for the optional packet capture. It's the only part that can show traffic going around the proxy.
- A test account and a new family. Don't use a real family. The capture holds your login token, and the report lists things like file names and hashes.
- A Wi-Fi network you trust, because mitmproxy listens on it while it runs.

Close other apps on the phone. Their traffic goes through the proxy too.

## 1. Make a test photo

Open [`inspector.html`](inspector.html) on your computer and use **Make a test photo**. It makes a JPEG with a random ID printed on it. Save it to the phone. Later, seeing that ID in a decrypted file ties the file to your own upload.

## 2. Start the proxy

From `verify/capture`:

```sh
RUN=~/clann-capture/run-1
mkdir -p $RUN
FAMILY=CanaryFam$(openssl rand -hex 3)
CHILD=CanaryKid$(openssl rand -hex 3)
CAPTION=CanaryCap$(openssl rand -hex 3)
COMMENT=CanaryCom$(openssl rand -hex 3)
export CANARIES=$FAMILY,$CHILD,$CAPTION,$COMMENT
echo "$CANARIES"

CAPTURE_OUT=$RUN mitmweb -s capture_report.py -w $RUN/run.flows
```

Keep the four words handy, because you'll type them into the app. They're how the report tells you where your text ended up.

## 3. Point the phone at it

1. Go to Settings > Wi-Fi > your network's (i) > HTTP Proxy > Configure Proxy > Manual. Enter your computer's IP address and port 8080.
2. In Safari, open `mitm.it` and download the iOS certificate.
3. Go to Settings > General > VPN & Device Management and install the profile.
4. Go to Settings > General > About > Certificate Trust Settings and turn on mitmproxy.
5. Open any HTTPS site in Safari. It should appear in the mitmweb page at `http://127.0.0.1:8081`.

## 4. Optional: capture packets too

This shows anything that went around the proxy. Connect the phone by USB, then in a second terminal:

```sh
xcrun xctrace list devices          # the phone's ID is in the last brackets
rvictl -s <device-id>
sudo tcpdump -i rvi0 -w ~/clann-capture/run-1/trace.pcap
```

Without it, the report says this wasn't checked.

## 5. Use the app

1. Force-quit Clann, reopen it and wait 30 seconds.
2. Create a family named with your `CanaryFam` word and a child named with your `CanaryKid` word. Don't add a photo of anyone, because profile photos aren't part of this test.
3. In the family's settings, open **End-to-end encryption** and turn it on if it's off.
4. Upload the test photo, and only that, with your `CanaryCap` word as the caption.
5. Wait for it to finish, open it, and comment with your `CanaryCom` word.

Uploading anything else makes the run inconclusive unless you also supply its key, because the tool can't vouch for a file it can't open.

## 6. Get the memory's key

In the app, open the photo and tap the **⋯** menu, then **What Clann sees**, then **Get this memory's key**. The app asks for Face ID or the passcode first. Press and hold the key to copy it, then put it in the key file on your computer, for example with Universal Clipboard:

```sh
pbpaste > ~/clann-capture/run-1/keys.txt
```

Don't paste it into a chat or anything else that keeps a copy. Anyone with the key and the file can open that memory, and the key never changes.

Optional: the app's **See your keys** screen shows the phone's two private keys. Add them as extra lines in `keys.txt`, and the tool also searches the traffic for them. Each line is hex or base64. Only do this with a test account, because these keys open everything the phone can.

## 7. Read the capture back

Press Ctrl-C in both terminals. If you captured packets, summarise them, using your computer's IP address:

```sh
rvictl -x <device-id>
python3 bypass_check.py $RUN/trace.pcap <computer-ip> $RUN/bypass.json
```

Then run the second pass:

```sh
CAPTURE_OUT=$RUN KEY_FILE=$RUN/keys.txt mitmdump -q -nr $RUN/run.flows -s capture_report.py
```

It writes `report.md` and saves each encrypted upload in `uploads/`.

## 8. Understand the result

| Result | What it means |
| --- | --- |
| **Observed upload check passed** | Every encrypted upload authenticated under your key, no plain media or supplied secret appeared in the inspected traffic, and nothing that matters went unread. |
| **Observed upload check failed** | Plain media or a supplied secret was seen. The report says where. Check first that encryption was on for the family, and that the row isn't another app's traffic or a profile photo. |
| **Inconclusive** | The run can't say either way, and the report lists why. Common reasons are an upload no key opened, a connection the proxy couldn't read, or an upload that's neither media nor CLN1. |

To cross-check with a separate implementation, open a file from `uploads/` in the Inspector and enter the key. The SHA-256 it shows should match the file's name and the report. The original should show your test photo, with its random ID.

Then read the sections a person has to judge:

| Section | Expected | Look into it if |
| --- | --- | --- |
| 3. CLN1 uploads | 3 for a photo, all authenticated | The count is off |
| 4. Connections this run can't speak for | Phone services at most | Anything else appears, or an address received data around the proxy |
| 6. Byte accounting | "Everything else" is small next to the CLN1 total | A host received more than you can explain |
| 7. Canary hits | Family and child names at the API only | A caption or comment word appears anywhere, or any word reaches a third party |
| 8. JSON fields | Matches [PROTOCOL.md](../PROTOCOL.md) section 8. Captions and comments are `sealed` | A field isn't listed there, or text is `PLAINTEXT` |
| 9. App version | A version or update ID | Nothing, so you can't say what you tested |

## What a pass doesn't prove

- That every app version, device or network path behaves the same way. It covers this run.
- Who else holds the key. The media key is sealed to other keys, and a sealed box doesn't reveal its recipient, so the labels in `wrapped_keys` are only what the app wrote.
- That no second copy was sent. A copy encrypted under another key looks like any other random data, which is why section 6 counts bytes, but small amounts could still hide in ordinary requests.
- Anything about downloads, or what the servers do with the file afterwards.

The phone services the report sets aside are listed at the top of `capture_report.py`. If you don't accept that list, treat those connections as unread too.

## Clean up

1. Turn the phone's Wi-Fi proxy off.
2. Remove the mitmproxy profile in VPN & Device Management.
3. Delete the test family in the app.
4. Delete the private files. The capture holds your login token and signed URLs:

```sh
rm ~/clann-capture/run-1/run.flows ~/clann-capture/run-1/trace.pcap ~/clann-capture/run-1/keys.txt
```

`report.md` and `bypass.json` hold no keys, tokens, cookies or query strings, so they're the files to share. If you find a problem, see "Reporting problems" in [PROTOCOL.md](../PROTOCOL.md).

## Testing the tools

From this repository's root:

```sh
mitmdump -ns verify/capture/test_capture_report.py
```

The tests use the public sample files in `samples/`.
