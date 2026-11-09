"""List traffic in a packet capture that did not go through the proxy.

With the phone's Wi-Fi proxy set, app traffic should only reach the proxy's
address. Everything else went around mitmproxy, so the report can't speak for it.
Writes the result to a file that capture_report.py reads on its second pass.

    python3 bypass_check.py trace.pcap <proxy-ip> run-1/bypass.json
"""
import json
import re
import socket
import subprocess
import sys
from collections import Counter, defaultdict

LINE = re.compile(r"\bIP6?\s+(\S+)\s+>\s+(\S+?):\s.*?(?:tcp|UDP, length)\s+(\d+)")
# Only name the addresses someone will actually need to look at.
NAME_FROM_BYTES = 10_000


def address(endpoint):
    return endpoint.rsplit(".", 1)[0]


def name_of(ip):
    socket.setdefaulttimeout(2)
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def read_packets(pcap):
    dump = subprocess.run(
        ["tcpdump", "-nn", "-q", "-r", pcap],
        capture_output=True, text=True, check=True,
    ).stdout
    packets = []
    for line in dump.splitlines():
        match = LINE.search(line)
        if match:
            packets.append((address(match[1]), address(match[2]), int(match[3])))
    return packets


def phone_addresses(packets, proxy_ip):
    """Which addresses are the phone's. It can have several, such as IPv4 and IPv6.

    Every packet has the phone on one end, so each connected set of addresses has
    two sides, and the phone's side holds the set's busiest address. The proxy is
    known not to be the phone, which matters when it's the only other address.
    """
    neighbours = defaultdict(set)
    seen = Counter()
    for src, dst, _ in packets:
        neighbours[src].add(dst)
        neighbours[dst].add(src)
        seen[src] += 1
        seen[dst] += 1

    is_phone = {}
    starts = [(proxy_ip, False)] + [(ip, True) for ip, _ in seen.most_common()]
    for start, phone_side in starts:
        if start in is_phone or start not in seen:
            continue
        is_phone[start] = phone_side
        frontier = [start]
        while frontier:
            current = frontier.pop()
            for other in neighbours[current]:
                if other not in is_phone:
                    is_phone[other] = not is_phone[current]
                    frontier.append(other)
    return {ip for ip, phone in is_phone.items() if phone}


def summarise(packets, proxy_ip):
    phone = phone_addresses(packets, proxy_ip)
    through_proxy = 0
    around = defaultdict(lambda: [0, 0])
    for src, dst, size in packets:
        sent = src in phone
        remote = dst if sent else src
        if remote == proxy_ip:
            through_proxy += size
        else:
            around[remote][0 if sent else 1] += size
    rows = [
        {"address": ip, "name": name_of(ip) if up >= NAME_FROM_BYTES else "", "sent": up, "received": down}
        for ip, (up, down) in sorted(around.items(), key=lambda i: -i[1][0])
    ]
    return {"through_proxy": through_proxy, "around": rows}


def main(pcap, proxy_ip, out):
    packets = read_packets(pcap)
    if not packets:
        sys.exit("No packets parsed. Check the capture, or the tcpdump output format.")
    result = summarise(packets, proxy_ip)
    with open(out, "w") as file:
        json.dump(result, file, indent=2)

    print(f"Through the proxy: {result['through_proxy']:,} payload bytes")
    print(f"Around the proxy: {sum(r['sent'] for r in result['around']):,} sent, "
          f"{sum(r['received'] for r in result['around']):,} received\n")
    print(f"{'Sent':>12} {'Received':>12}  Address")
    for row in result["around"]:
        print(f"{row['sent']:>12,} {row['received']:>12,}  {row['address']}  {row['name']}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
