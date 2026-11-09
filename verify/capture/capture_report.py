"""Reads a mitmproxy capture of the Clann app and reports what it shows.

It runs twice. The first pass runs live while you use the app:

    CAPTURE_OUT=run-1 mitmweb -s capture_report.py -w run-1/run.flows

The second reads the capture back with the memory's key, which doesn't exist
until the upload has happened:

    CAPTURE_OUT=run-1 KEY_FILE=keys.txt mitmdump -q -nr run-1/run.flows -s capture_report.py

CAPTURE.md has the whole procedure.

report.md never contains keys, auth headers, cookies or URL query strings, so it
can be shared. run.flows holds your auth token and signed URLs, and keys.txt holds
the keys. Keep both private and delete them when you finish.
"""
import base64
import gzip
import hashlib
import ipaddress
import json
import math
import os
import re
import struct
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mitmproxy import ctx

HEADER_SIZE = 32
TAG_SIZE = 16
LAST_CHUNK = 0x80000000
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MEDIA_NAMES = {1: "JPEG", 2: "MP4"}

# Below this, an upload is too small to hold a photo worth worrying about.
BINARY_MIN_BYTES = 1024
# Text this large could be a second copy of a photo, encoded.
TEXT_MAX_BYTES = 256 * 1024
# Bytes sent around the proxy before they need explaining.
BYPASS_MIN_BYTES = 10_000

# Connections the phone itself makes, which the app can't use to send a file.
# Anything else that can't be read makes the result inconclusive. Hosts that
# accept arbitrary uploads, such as storage.googleapis.com, must not go here.
PHONE_SERVICES = (
    ".apple.com", ".icloud.com", ".mzstatic.com", ".aaplimg.com", ".cdn-apple.com",
    ".apple-dns.net", ".gstatic.com", ".android.com", "mtalk.google.com",
    "play.googleapis.com", "android.googleapis.com", "android.apis.google.com",
)
APPLE_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("17.0.0.0/8", "2620:149::/32", "2a01:b740::/32", "2403:300::/32")
)

# JSON request fields worth comparing against PROTOCOL.md section 8.
WATCHED = {
    "file_hash", "file_hashes", "filename", "taken_at", "caption",
    "caption_by_group", "text", "comment", "comment_text", "events",
    "event_name", "event_date", "latitude", "longitude", "lat", "lng",
    "location", "gps", "exif", "wrapped_keys", "enc_meta", "encrypted",
    "subject_ids", "width", "height", "duration_ms", "size_bytes",
    "ota_update_id", "ota_channel", "ota_runtime_version", "$app_version",
}
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
EMBEDDED_MEDIA = re.compile(rb"(/9j/|iVBORw0KGgo)[A-Za-z0-9+/_-]{1024,}")
HEIF_BRANDS = (b"heic", b"heix", b"hevc", b"mif1", b"msf1")
SCRUBBED = b"[secret removed]"


def sniff(data):
    """What a file is, from its first bytes. None if it's nothing recognisable."""
    if data[:4] == b"CLN1":
        return "CLN1"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[4:8] == b"ftyp":
        return "HEIC" if data[8:12] in HEIF_BRANDS else "MP4"
    if data[4:8] in (b"moov", b"mdat", b"wide", b"free"):
        return "QuickTime"
    if data[:4] == b"GIF8":
        return "GIF"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    return None


def parse_header(data):
    """The checks the Inspector makes. Raises ValueError for a file it would refuse."""
    if len(data) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("no complete chunk after the header")
    version, alg, media = data[4], data[5], data[6]
    chunk_size, epoch = struct.unpack(">II", data[8:16])
    if version != 1:
        raise ValueError(f"unsupported version {version}")
    if alg != 1:
        raise ValueError(f"unsupported algorithm {alg}")
    if media not in MEDIA_NAMES:
        raise ValueError(f"unsupported media type {media}")
    if chunk_size == 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"implausible chunk size {chunk_size}")
    if epoch == 0:
        raise ValueError("key epoch is 0")
    return {"media": media, "chunk_size": chunk_size, "epoch": epoch}


def open_cln1(data, key):
    """Authenticate every chunk. Returns what came out, or None if any chunk fails.

    See PROTOCOL.md section 4. The last-chunk flag in the nonce is what makes a
    file cut at a chunk boundary fail rather than open shorter.
    """
    sealed_size = parse_header(data)["chunk_size"] + TAG_SIZE
    count = math.ceil((len(data) - HEADER_SIZE) / sealed_size)
    aead = AESGCM(key)
    start_of_plain = b""
    size = 0
    for index in range(count):
        last = index == count - 1
        start = HEADER_SIZE + index * sealed_size
        sealed = data[start:] if last else data[start:start + sealed_size]
        nonce = data[16:24] + struct.pack(">I", index | (LAST_CHUNK if last else 0))
        try:
            plain = aead.decrypt(nonce, sealed, data[:HEADER_SIZE])
        except InvalidTag:
            return None
        start_of_plain = start_of_plain or plain[:16]
        size += len(plain)
    return {"chunks": count, "recovered": sniff(start_of_plain) or "unrecognised", "recovered_bytes": size}


def forms_of(raw):
    """The ways these bytes could appear in traffic. Base64 depends on alignment, so try all three."""
    forms = {("raw", raw), ("hex", raw.hex().encode()), ("hex", raw.hex().upper().encode())}
    if quote(raw).encode() != raw:
        forms.add(("url-encoded", quote(raw).encode()))
    for offset in range(3):
        # Only the characters that depend on nothing but these bytes.
        encoded = base64.b64encode(b"\0" * offset + raw)
        first = math.ceil(offset * 8 / 6)
        end = (offset + len(raw)) * 8 // 6
        plain = encoded[first:end]
        forms.add(("base64", plain))
        forms.add(("base64url", plain.replace(b"+", b"-").replace(b"/", b"_")))
    return forms


def decode_secret(text):
    """A secret's bytes from hex or base64. None if it's neither, or too short to search for safely."""
    text = re.sub(r"\s+", "", text)
    try:
        if HEX.fullmatch(text):
            value = bytes.fromhex(text)
        else:
            normal = text.replace("-", "+").replace("_", "/").rstrip("=")
            value = base64.b64decode(normal + "=" * (-len(normal) % 4), validate=True)
    except ValueError:
        return None
    return value if len(value) >= 16 else None


def read_secrets(path):
    """One secret per line, '#' starts a comment. Errors name the line, never its contents."""
    secrets, problems = [], []
    try:
        lines = Path(path).expanduser().read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return [], ["The key file couldn't be read."]
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        value = decode_secret(line)
        if value is None:
            problems.append(f"Line {number} of the key file isn't hex or base64 of at least 16 bytes.")
        else:
            secrets.append(value)
    return secrets, problems


def body_of(message):
    """Decoded body, including gzip the HTTP layer didn't advertise, which analytics SDKs send."""
    try:
        body = message.content or b""
    except ValueError:
        body = message.raw_content or b""
    if body[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(body)
        except OSError:
            pass
    return body


def parts_of(request, body):
    """Each part of a multipart form, or else the one body.

    Split here rather than with mitmproxy's multipart_form, which strips line
    endings out of binary parts and so would corrupt an encrypted file.
    """
    content_type = request.headers.get("content-type", "")
    boundary = re.search(r'boundary="?([^";,\s]+)', content_type)
    if not boundary or "multipart/" not in content_type.lower():
        return [body]
    parts = []
    for section in (b"\r\n" + body).split(b"\r\n--" + boundary[1].encode())[1:]:
        if section.startswith(b"--"):
            break
        _, separator, content = section.partition(b"\r\n\r\n")
        if separator:
            parts.append(content)
    return parts or [body]


def header_text(headers):
    return "\n".join(f"{k}: {v}" for k, v in headers.items(multi=True)).encode("utf-8", "replace")


def walk(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in WATCHED:
                found.append((key, item))
            walk(item, found)
    elif isinstance(value, list):
        for item in value:
            walk(item, found)


def describe(key, value):
    if key == "wrapped_keys" and isinstance(value, list):
        labels = [v.get("device_id", "?")[:8] for v in value if isinstance(v, dict)]
        return f"{len(value)} sealed copies, labelled {labels}"
    if key == "enc_meta" and isinstance(value, dict):
        return f"sealed key record, key epoch {value.get('key_epoch', '?')}"
    if key in ("caption", "text", "comment", "comment_text") and isinstance(value, str):
        if not value:
            return "empty"
        return "sealed (clnf1.)" if value.startswith("clnf1.") else f"PLAINTEXT: {value[:60]}"
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 80 else text[:77] + "..."


def is_phone_service(host):
    return any(host == s.lstrip(".") or host.endswith(s) for s in PHONE_SERVICES)


def needs_explaining(row):
    """Whether traffic that went around the proxy is more than the phone's own background noise."""
    if row["sent"] < BYPASS_MIN_BYTES:
        return False
    address = ipaddress.ip_address(row["address"])
    return address.is_global and not any(
        address.version == n.version and address in n for n in APPLE_NETWORKS
    )


class CaptureReport:
    def __init__(self, out, key_file=None, canaries=(), offline=None):
        self.out = Path(out).expanduser()
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.offline = offline
        self.canaries = list(canaries)
        self.keys_given = key_file is not None
        self.secrets, self.problems = read_secrets(key_file) if key_file else ([], [])
        self.secret_needles = [
            (number, form, needle)
            for number, secret in enumerate(self.secrets, 1)
            for form, needle in forms_of(secret)
        ]
        self.canary_needles = [
            (word, form, needle) for word in self.canaries for form, needle in forms_of(word.encode())
        ]
        self.count = 0
        self.by_host = defaultdict(lambda: [0, 0, 0])
        self.cln1 = []
        self.media = []
        self.binary = []
        self.secret_hits = defaultdict(int)
        self.canary_hits = defaultdict(int)
        self.fields = defaultdict(dict)
        self.versions = defaultdict(set)
        self.unreadable = defaultdict(int)
        self.raw_tcp = defaultdict(int)
        self.unread_bodies = defaultdict(int)
        self.bypass = None

    # Reading traffic

    def response(self, flow):
        self.record(flow)

    def error(self, flow):
        if flow.response is None:
            self.record(flow)

    def tls_failed_client(self, data):
        client = data.context.client
        host = client.sni or (data.context.server.address or ("unknown",))[0]
        self.unreadable[host] += 1
        self.write_connection_log()

    def tcp_start(self, flow):
        address = flow.server_conn.address
        self.raw_tcp[address[0] if address else "unknown"] += 1

    def tcp_end(self, flow):
        address = flow.server_conn.address
        host = address[0] if address else "unknown"
        self.search_messages(host, "(raw TCP)", flow.messages)

    def websocket_end(self, flow):
        host = flow.request.pretty_host
        self.search_messages(host, self.clean_path(flow.request), flow.websocket.messages)

    def search_messages(self, host, path, messages):
        for message in messages:
            self.search(host, path, "sent" if message.from_client else "received", message.content)
            if message.from_client:
                self.by_host[host][1] += len(message.content)
                self.classify_part(message.content, host, path, "socket")

    @staticmethod
    def clean_path(request):
        return UUID.sub("{id}", request.path.split("?", 1)[0])

    def record(self, flow):
        request = flow.request
        host = request.pretty_host
        path = self.clean_path(request)
        body = body_of(request)
        down = body_of(flow.response) if flow.response else b""

        stats = self.by_host[host]
        stats[0] += 1
        stats[1] += len(body)
        stats[2] += len(down)

        if request.raw_content is None and flow.response is not None:
            self.unread_bodies[host] += 1

        self.classify_upload(request, host, path, body, flow)
        self.search(host, path, "sent", b"\n".join((
            request.url.encode("utf-8", "replace"),
            header_text(request.headers),
            body,
            request.raw_content or b"",
        )))
        if flow.response:
            self.search(host, path, "received", b"\n".join((
                header_text(flow.response.headers),
                down,
                flow.response.raw_content or b"",
            )))
        self.collect_fields(host, request.method, path, body)
        for name, value in request.headers.items():
            if name.lower().startswith("expo-") or (
                name.lower() == "user-agent" and "clann" in value.lower()
            ):
                self.versions[name.lower()].add(value)

        self.count += 1
        if not self.is_offline() and self.count % 25 == 0:
            self.write()

    def classify_upload(self, request, host, path, body, flow):
        if request.method not in ("PUT", "POST", "PATCH"):
            return
        status = flow.response.status_code if flow.response else "no response"
        for part in parts_of(request, body):
            self.classify_part(part, host, path, status)

    def classify_part(self, part, host, path, status):
        if len(part) < BINARY_MIN_BYTES:
            return
        entry = {
            "host": host, "path": path, "bytes": len(part),
            "sha256": hashlib.sha256(part).hexdigest(), "status": status,
        }
        kind = sniff(part)
        if kind == "CLN1":
            self.cln1.append({**entry, **self.check_cln1(part)})
            self.keep_upload(part, entry["sha256"])
        elif kind:
            self.media.append({**entry, "kind": kind})
        elif self.looks_like_text(part):
            embedded = EMBEDDED_MEDIA.search(part)
            if embedded:
                name = "JPEG" if embedded[1] == b"/9j/" else "PNG"
                self.media.append({**entry, "kind": f"{name} as base64 text"})
            elif len(part) >= TEXT_MAX_BYTES:
                self.binary.append(entry)
        else:
            self.binary.append(entry)

    @staticmethod
    def looks_like_text(data):
        try:
            data.decode()
        except UnicodeDecodeError:
            return False
        return True

    def check_cln1(self, data):
        try:
            header = parse_header(data)
        except ValueError as problem:
            return {"opened": False, "note": f"not a valid CLN1 file: {problem}"}
        result = {**header, "media": MEDIA_NAMES[header["media"]], "opened": False, "note": "no key given"}
        keys = [s for s in self.secrets if len(s) == 32]
        for key in keys:
            opened = open_cln1(data, key)
            if opened:
                chunks = f"{opened['chunks']} chunk{'' if opened['chunks'] == 1 else 's'}"
                note = f"authenticated, {chunks}, {opened['recovered']}, {opened['recovered_bytes']:,} bytes recovered"
                return {**result, "opened": True, "note": note}
        return {**result, "note": "no supplied key opened it"} if keys else result

    def keep_upload(self, data, sha256):
        """Second pass only: save the file so it can be cross-checked in the Inspector."""
        if self.is_offline():
            folder = self.out / "uploads"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{sha256}.cln1").write_bytes(data)

    def search(self, host, path, direction, data):
        for number, form, needle in self.secret_needles:
            if needle in data:
                self.secret_hits[(number, form, direction, host, path)] += 1
        for word, form, needle in self.canary_needles:
            if needle in data:
                self.canary_hits[(word, form, direction, host, path)] += 1

    def collect_fields(self, host, method, path, body):
        if body.lstrip()[:1] not in (b"{", b"["):
            return
        # Before any field is cut short for display, which would hide a secret from the final scrub.
        for _, _, needle in self.secret_needles:
            body = body.replace(needle, SCRUBBED)
        try:
            parsed = json.loads(body)
        except ValueError:
            return
        found = []
        walk(parsed, found)
        for key, value in found:
            self.fields[(host, method, path)].setdefault(key, describe(key, value))

    # The two passes

    def is_offline(self):
        return bool(ctx.options.rfile) if self.offline is None else self.offline

    def done(self):
        if self.is_offline():
            self.read_connection_log()
            self.read_bypass()
        else:
            self.write_connection_log()
        self.write()
        print(f"{self.verdict()[0]}. Full report: {self.out / 'report.md'}")

    def write_connection_log(self):
        """TLS refusals fire only while live and aren't kept in the flow file, so the second pass needs this."""
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "connections.json").write_text(json.dumps({"refused": self.unreadable}, indent=2))

    def read_connection_log(self):
        try:
            refused = json.loads((self.out / "connections.json").read_text())["refused"]
        except (OSError, ValueError, KeyError):
            self.problems.append(
                "connections.json from the live pass is missing, so refused connections can't be listed."
            )
            return
        for host, count in refused.items():
            self.unreadable[host] += count

    def read_bypass(self):
        try:
            self.bypass = json.loads((self.out / "bypass.json").read_text())
        except (OSError, ValueError):
            self.bypass = None

    def write(self):
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "report.md").write_text(self.scrub(self.render()))

    def scrub(self, text):
        """A secret in a URL, a hostname or a field has to be reported without being repeated."""
        for _, _, needle in self.secret_needles:
            try:
                text = text.replace(needle.decode(), SCRUBBED.decode())
            except UnicodeDecodeError:
                pass
        return text

    # The result

    def blocked_hosts(self):
        hosts = set(self.unreadable) | set(self.raw_tcp) | set(self.unread_bodies)
        return sorted(h for h in hosts if not is_phone_service(h))

    def bypass_rows(self):
        return [r for r in (self.bypass or {}).get("around", []) if needs_explaining(r)]

    def verdict(self):
        failed = []
        if self.media:
            failed.append(f"{len(self.media)} upload(s) were plain media, not encrypted. See section 1.")
        if self.secret_hits:
            failed.append("A key or secret you supplied appeared in the traffic. See section 2.")
        if failed:
            return "Observed upload check failed", failed

        questions = list(self.problems)
        if not self.keys_given:
            questions.append("No key was supplied, so nothing has been authenticated yet. Run the second pass.")
        elif not any(len(s) == 32 for s in self.secrets):
            questions.append("The key file has no 64-character media key.")
        if not self.cln1:
            questions.append("No CLN1 upload was captured.")
        unopened = [u for u in self.cln1 if not u["opened"]]
        if unopened and self.keys_given:
            questions.append(
                f"{len(unopened)} of {len(self.cln1)} CLN1 uploads weren't opened by a supplied key, "
                "so their contents are unknown. See section 3."
            )
        blocked = self.blocked_hosts()
        if blocked:
            questions.append(f"Traffic to {', '.join(blocked)} couldn't be read. See section 4.")
        around = self.bypass_rows()
        if around:
            questions.append(f"{len(around)} address(es) received data that went around the proxy. See section 4.")
        if self.binary:
            questions.append(f"{len(self.binary)} other large upload(s) need explaining. See section 5.")
        if questions:
            return "Inconclusive", questions
        return "Observed upload check passed", []

    def noun(self):
        media = {u["media"] for u in self.cln1 if u.get("media")}
        return "video" if media == {"MP4"} else "photo" if media == {"JPEG"} else "photo and video"

    def render(self):
        outcome, reasons = self.verdict()
        out = ["# Clann capture report", "", f"## Result: {outcome}", ""]
        if outcome == "Observed upload check passed":
            out += [
                f"In the captured and successfully inspected traffic, the {self.noun()} upload "
                "contained authenticated ciphertext. No plaintext media or secret keys were "
                "detected in the inspected upload traffic.",
            ]
        else:
            out += [f"- {reason}" for reason in reasons]
        out += ["", "This result does not independently prove that every app version, device, "
                "or network path is secure, and it doesn't show who else holds the key.", "",
                "### Not checked by this run", ""]
        if self.bypass is None:
            out.append("- Connections that went around the proxy: there's no bypass.json for this run.")
        out += [
            "- Who the keys were sealed to. The `wrapped_keys` labels are written by the app, and "
            "a sealed box doesn't reveal its recipient.",
            "- A second copy encrypted under another key would look like any other random data. "
            "Compare the byte counts in section 6 with what you did in the app.",
            "- Downloads, and anything outside this capture.",
            "",
            f"Started {self.started}. {self.count} requests read. "
            f"{len(self.secrets)} secret(s) searched for. Canaries: {', '.join(self.canaries) or 'none'}.",
            "",
            "## 1. Plaintext media uploads",
            "",
            "A row here fails the run, unless it's a family without encryption turned on or an "
            "unencrypted avatar.",
            "",
        ]
        out += self.rows(self.media, ("kind", "host", "path", "bytes", "status", "sha256")) or ["None."]

        out += ["", "## 2. Supplied secrets found in traffic", "",
                "URLs, headers and bodies, both directions, in raw, hex, URL-encoded, base64 and "
                "base64url forms. The secrets themselves are never written here.", ""]
        hits = [f"- Secret {number} ({form}) {direction} {host}{path}: {n}x"
                for (number, form, direction, host, path), n in sorted(self.secret_hits.items())]
        out += hits or ["None found." if self.secrets else "Not searched: no key file."]

        out += ["", "## 3. CLN1 uploads", "",
                "A photo should show 3 (original, medium, thumbnail), a video 2 (original, poster). "
                "A key opens every size of its memory. Each file is in `uploads/`, named by its "
                "SHA-256, so you can open it in the Inspector and compare the hash.", ""]
        out += self.rows(self.cln1, ("host", "path", "bytes", "media", "epoch", "status", "note", "sha256")) or ["None."]

        out += ["", "## 4. Connections this run can't speak for", ""]
        lines = []
        for host, n in sorted(self.unreadable.items()):
            lines.append(f"- TLS refused: {host} ({n}x){self.service_label(host)}")
        for host, n in sorted(self.raw_tcp.items()):
            lines.append(f"- Raw TCP, not HTTP: {host} ({n}x){self.service_label(host)}")
        for host, n in sorted(self.unread_bodies.items()):
            lines.append(f"- Body not kept by the proxy: {host} ({n}x){self.service_label(host)}")
        out += lines or ["No refused or unreadable connections."]
        out += [""]
        if self.bypass is None:
            out.append("Around the proxy: not checked.")
        else:
            out.append(f"Around the proxy, from the packet capture "
                       f"({self.bypass.get('through_proxy', 0):,} bytes went through it):")
            out.append("")
            out += self.rows(self.bypass.get("around", []), ("address", "name", "sent", "received")) or ["Nothing."]

        out += ["", "## 5. Other large uploads", "",
                "Not media and not CLN1, so each one needs explaining.", ""]
        out += self.rows(self.binary, ("host", "path", "bytes", "status", "sha256")) or ["None."]

        total_up = sum(s[1] for s in self.by_host.values())
        cln1_up = sum(u["bytes"] for u in self.cln1)
        out += ["", "## 6. Byte accounting", "",
                f"Sent in total: {total_up:,} bytes. CLN1 files: {cln1_up:,} bytes. "
                f"Everything else: {total_up - cln1_up:,} bytes.",
                "", "| Host | Requests | Sent | Received |", "|---|---|---|---|"]
        for host, (n, up, down) in sorted(self.by_host.items(), key=lambda i: -i[1][1]):
            out.append(f"| {host} | {n} | {up:,} | {down:,} |")

        out += ["", "## 7. Canary hits", "",
                "A family or child name reaching the API is expected. A caption or comment canary "
                "anywhere, or any canary at a third-party host, is a finding.", ""]
        canaries = [f"- {word} ({form}) {direction} {host}{path}: {n}x"
                    for (word, form, direction, host, path), n in sorted(self.canary_hits.items())]
        out += canaries or ["None."]

        out += ["", "## 8. Fields sent in JSON requests", "", "First value seen. Compare with PROTOCOL.md section 8."]
        for (host, method, path), fields in sorted(self.fields.items()):
            out.append(f"\n**{method} {host}{path}**\n")
            out += [f"- `{key}`: {value}" for key, value in sorted(fields.items())]

        out += ["", "## 9. App version evidence", ""]
        lines = [f"- {name}: {', '.join(sorted(values))}" for name, values in sorted(self.versions.items())]
        out += lines or ["None seen. Relaunch the app with the capture running."]
        return "\n".join(out) + "\n"

    @staticmethod
    def service_label(host):
        return ", the phone's own service" if is_phone_service(host) else ""

    @staticmethod
    def rows(items, columns):
        if not items:
            return []
        lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
        for item in items:
            lines.append("| " + " | ".join(str(item.get(c, "")) for c in columns) + " |")
        return lines


addons = [
    CaptureReport(
        out=os.environ.get("CAPTURE_OUT", "capture-output"),
        key_file=os.environ.get("KEY_FILE"),
        canaries=[c.strip() for c in os.environ.get("CANARIES", "").split(",") if c.strip()],
    )
]
