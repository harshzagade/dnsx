"""Shared fixtures for DnsX tests.

NOTE: this sandbox blocks outbound UDP (sendto raises PermissionError),
including loopback UDP, so real UDP sockets cannot be used in tests here.
TCP loopback works. UDP queries from DnsClient are therefore tested through
an in-process fake UDP socket (see _FakeUdpSocket / patch_udp_sockets),
which answers from the same routing table as the fake TCP server.
On a normal machine the fake UDP socket behaves identically to the real
thing from DnsClient's point of view (same bytes in, same bytes out).
"""
import socket
import struct
import threading
import pytest
from dnsx.dns import (
    encode_name, decode_name, build_query, TYPE_A, TYPE_NS, TYPE_CNAME,
    TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_AAAA, TYPE_AXFR, TYPE_CAA, TYPE_DS
)

_TYPE_BY_NAME = {
    "A": TYPE_A, "NS": TYPE_NS, "CNAME": TYPE_CNAME, "SOA": TYPE_SOA,
    "MX": TYPE_MX, "TXT": TYPE_TXT, "AAAA": TYPE_AAAA, "AXFR": TYPE_AXFR,
    "CAA": TYPE_CAA, "DS": TYPE_DS,
}


def build_response(qid, qname, qtype, answers, rcode=0, flags=0x8180):
    """Build a valid DNS response message: question echoed + answer RRs."""
    query_part = build_query(qname, qtype, qid)
    header = struct.pack("!HHHHHH", qid, flags | (rcode & 0xF), 1, len(answers), 0, 0)
    body = query_part[12:]  # question section (name + qtype + qclass)

    for atype_str, adata in answers:
        body += encode_name(qname)
        atype = _TYPE_BY_NAME.get(atype_str, 99)

        body += struct.pack("!HHI", atype, 1, 60)

        rdata = b""
        if atype_str == "A":
            rdata = socket.inet_aton(adata)
        elif atype_str == "AAAA":
            rdata = socket.inet_pton(socket.AF_INET6, adata)
        elif atype_str in ("NS", "CNAME"):
            rdata = encode_name(adata)
        elif atype_str == "MX":
            rdata = struct.pack("!H", adata[0]) + encode_name(adata[1])
        elif atype_str == "TXT":
            for s in adata:
                b = s.encode()
                rdata += struct.pack("B", len(b)) + b
        elif atype_str == "SOA":
            rdata = encode_name(adata[0]) + encode_name(adata[1])
            rdata += struct.pack("!IIIII", adata[2], adata[3], adata[4], adata[5], adata[6])
        elif atype_str == "CAA":
            # adata: (flags, tag, value)
            tag = adata[1].encode("ascii")
            rdata = struct.pack("!BB", adata[0], len(tag)) + tag + adata[2].encode()
        elif atype_str == "DS":
            # adata: (key_tag, algorithm, digest_type, digest_hex)
            rdata = struct.pack("!HBB", adata[0], adata[1], adata[2]) + bytes.fromhex(adata[3])

        body += struct.pack("!H", len(rdata)) + rdata
    return header + body


def lookup_answer(table, qname, qtype):
    """Routing-table lookup shared by the fake TCP server and fake UDP socket.

    Returns (answer_specs, rcode). Unknown names are NXDOMAIN (rcode 3),
    unless the table carries a ("__wildcard__", TYPE_A) entry, in which case
    any unknown A query under example.com resolves to that IP.
    """
    key = (qname.lower().rstrip("."), qtype)
    if key in table:
        return table[key], 0
    if qtype == TYPE_A and ("__wildcard__", TYPE_A) in table:
        if qname.lower().rstrip(".").endswith(".example.com"):
            return table[("__wildcard__", TYPE_A)], 0
    return [], 3


# ---------------------------------------------------------------------------
# In-process fake UDP socket (the sandbox blocks real UDP sendto).
# ---------------------------------------------------------------------------

class _FakeUdpSocket:
    """Minimal SOCK_DGRAM stand-in: answers queries from UDP_STATE table."""

    def __init__(self, *args, **kwargs):
        self._timeout = None
        self._pending = None
        self._bound = None

    def settimeout(self, timeout):
        self._timeout = timeout

    def setsockopt(self, *args, **kwargs):
        pass

    def bind(self, address):
        self._bound = address

    def getsockname(self):
        return self._bound or ("127.0.0.1", 0)

    def sendto(self, data, addr):
        if UDP_STATE.get("blackhole"):
            self._pending = None
            return len(data)
        qid = struct.unpack("!H", data[:2])[0]
        qname, offset = decode_name(data, 12)
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        ans, rcode = lookup_answer(UDP_STATE.get("table", {}), qname, qtype)
        resp = build_response(qid, qname, qtype, ans, rcode)
        if (qname.lower().rstrip("."), qtype) in UDP_STATE.get("tc", set()):
            # Set the TC bit; optionally cut the datagram short mid-record
            # (a real truncated reply), to prove the client retries over
            # TCP instead of surfacing a parse error for a partial answer.
            flags = struct.unpack("!H", resp[2:4])[0] | 0x0200
            resp = resp[:2] + struct.pack("!H", flags) + resp[4:]
            if UDP_STATE.get("truncate_tc"):
                resp = resp[:-3]
        self._pending = resp
        return len(data)

    def recvfrom(self, nbytes):
        if self._pending is None:
            raise socket.timeout("timed out")
        data, self._pending = self._pending, None
        return data, ("127.0.0.1", 53)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# Mutable holder the fake UDP socket reads from; tests set it via fixtures.
UDP_STATE = {"table": {}, "blackhole": False, "tc": set(), "truncate_tc": False}

_REAL_SOCKET = socket.socket


def _socket_factory(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
    if type == socket.SOCK_DGRAM:
        return _FakeUdpSocket()
    return _REAL_SOCKET(family, type, proto, *args, **kwargs)


@pytest.fixture(autouse=True)
def patch_udp_sockets(monkeypatch):
    """Route DGRAM sockets through the in-process fake; TCP stays real."""
    UDP_STATE["table"] = {}
    UDP_STATE["blackhole"] = False
    UDP_STATE["tc"] = set()
    UDP_STATE["truncate_tc"] = False
    monkeypatch.setattr(socket, "socket", _socket_factory)
    yield
    UDP_STATE["table"] = {}
    UDP_STATE["blackhole"] = False
    UDP_STATE["tc"] = set()
    UDP_STATE["truncate_tc"] = False


@pytest.fixture
def udp_blackhole(patch_udp_sockets):
    """Fake UDP socket that never answers (drives DnsTimeout)."""
    UDP_STATE["blackhole"] = True
    yield
    UDP_STATE["blackhole"] = False


def _recv_exact(conn, nbytes):
    data = b""
    while len(data) < nbytes:
        chunk = conn.recv(nbytes - len(data))
        if not chunk:
            break
        data += chunk
    return data


class FakeServer:
    """Fake DNS server: real TCP listener; UDP side unused (see note above)."""

    def __init__(self, table):
        self.table = table
        self.udp_sock = _REAL_SOCKET(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(("127.0.0.1", 0))
        self.udp_port = self.udp_sock.getsockname()[1]

        self.tcp_sock = _REAL_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.bind(("127.0.0.1", 0))
        self.tcp_port = self.tcp_sock.getsockname()[1]
        self.tcp_sock.listen(5)

        self.running = True
        self.threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True)
        ]
        for t in self.threads:
            t.start()

    def _lookup(self, qname, qtype):
        return lookup_answer(self.table, qname, qtype)

    def _udp_loop(self):
        # Never receives anything (clients use the in-process fake UDP socket),
        # but keep the socket open so the port stays bound.
        while self.running:
            try:
                self.udp_sock.settimeout(0.1)
                self.udp_sock.recvfrom(1024)
            except (socket.timeout, OSError):
                continue

    def _tcp_loop(self):
        while self.running:
            try:
                self.tcp_sock.settimeout(0.1)
                conn, _ = self.tcp_sock.accept()
                with conn:
                    raw_len = _recv_exact(conn, 2)
                    if len(raw_len) < 2:
                        continue
                    length = struct.unpack("!H", raw_len)[0]
                    data = _recv_exact(conn, length)
                    if len(data) < length:
                        continue
                    qid = struct.unpack("!H", data[:2])[0]
                    qname, offset = decode_name(data, 12)
                    qtype = struct.unpack("!H", data[offset:offset + 2])[0]

                    if qtype == TYPE_AXFR:
                        soa = self.table[("example.com", TYPE_SOA)]
                        a_rec = self.table[("example.com", TYPE_A)]
                        m1 = build_response(qid, qname, qtype, [("SOA", soa[0][1]), ("A", a_rec[0][1])])
                        m2 = build_response(qid, qname, qtype, [("A", a_rec[0][1]), ("SOA", soa[0][1])])
                        for m in [m1, m2]:
                            conn.sendall(struct.pack("!H", len(m)) + m)
                    else:
                        ans, rcode = self._lookup(qname, qtype)
                        resp = build_response(qid, qname, qtype, ans, rcode)
                        conn.sendall(struct.pack("!H", len(resp)) + resp)
            except (socket.timeout, OSError):
                continue

    def shutdown(self):
        self.running = False
        self.udp_sock.close()
        self.tcp_sock.close()
        for t in self.threads:
            t.join(timeout=0.5)


@pytest.fixture
def fake_dns_server():
    server = FakeServer({})

    def _set(table):
        server.table.clear()
        server.table.update(table)
        UDP_STATE["table"] = dict(table)

    yield {
        "udp_port": server.udp_port,
        "tcp_port": server.tcp_port,
        "table": server.table,
        "set": _set,
    }
    server.shutdown()


def example_table():
    soa_data = ("ns1.example.com.", "hostmaster.example.com.", 2026010101, 7200, 3600, 1209600, 300)
    return {
        ("example.com", TYPE_A): [("A", "93.184.216.34")],
        ("example.com", TYPE_AAAA): [("AAAA", "2606:2800:220:1:248:1893:25c8:1946")],
        ("example.com", TYPE_NS): [("NS", "ns1.example.com."), ("NS", "ns2.example.com.")],
        ("example.com", TYPE_MX): [("MX", (10, "mail.example.com."))],
        ("example.com", TYPE_TXT): [("TXT", ["v=spf1 -all"])],
        ("example.com", TYPE_SOA): [("SOA", soa_data)],
        ("example.com", TYPE_CAA): [("CAA", (0, "issue", "letsencrypt.org"))],
        ("example.com", TYPE_DS): [("DS", (12345, 8, 2,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"))],
        ("www.example.com", TYPE_A): [("A", "93.184.216.34")],
        # ns1 resolves to loopback so AXFR tests can reach the fake TCP server.
        ("ns1.example.com", TYPE_A): [("A", "127.0.0.1")],
        ("ns2.example.com", TYPE_A): [("A", "127.0.0.1")],
    }


def wild_table():
    t = example_table()
    t[("__wildcard__", TYPE_A)] = [("A", "203.0.113.7")]
    return t
