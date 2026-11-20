import pytest
import socket
import struct
from dnsx.dns import (
    encode_name, decode_name, build_query, parse_response, DnsClient,
    DnsError, DnsTimeout, TYPE_A, TYPE_AAAA, TYPE_NS, TYPE_MX, TYPE_TXT, TYPE_SOA,
    TYPE_CAA, TYPE_DS, TYPE_PTR, TYPE_SRV
)
from conftest import build_response, example_table

def test_name_encoding_roundtrip():
    for name in ["example.com", "a.b.c.example.com", "."]:
        encoded = encode_name(name)
        decoded, _ = decode_name(encoded, 0)
        assert decoded.lower().rstrip(".") == name.lower().rstrip(".")

def test_encode_name_errors():
    with pytest.raises(ValueError):
        encode_name("a" * 64 + ".com")
    with pytest.raises(ValueError):
        encode_name("a." * 130 + "com")

def test_decode_name_compression():
    data = b"\x07example\x03com\x00"
    data += b"\x03www" + b"\xc0\x00"
    name, _ = decode_name(data, 13)
    assert name == "www.example.com"

def test_decode_pointer_loop():
    data = b"\x03www\xc0\x00"
    with pytest.raises(DnsError):
        decode_name(data, 0)

def test_query_parse_roundtrip():
    qid = 0x1234
    qname = "example.com"
    answers = [("A", "93.184.216.34"), ("MX", (10, "mail.example.com."))]
    resp_data = build_response(qid, qname, TYPE_A, answers)
    parsed = parse_response(resp_data, qid)
    assert len(parsed["answers"]) == 2
    assert parsed["answers"][0]["data"] == "93.184.216.34"
    assert parsed["answers"][1]["data"] == {"preference": 10, "exchange": "mail.example.com"}

def test_parse_response_errors():
    resp_data = build_response(0x1234, "x.com", TYPE_A, [])
    with pytest.raises(DnsError):
        parse_response(resp_data, 0x5555)
    
    nx_data = build_response(0x1234, "x.com", TYPE_A, [], rcode=3)
    with pytest.raises(DnsError, match=r"Non-Existent Domain \(NXDOMAIN\)"):
        parse_response(nx_data, 0x1234)

    fail_data = build_response(0x1234, "x.com", TYPE_A, [], rcode=2)
    with pytest.raises(DnsError, match="Server Failure"):
        parse_response(fail_data, 0x1234)

def test_parse_special_types():
    # TXT multiple
    resp = build_response(1, "x", TYPE_TXT, [("TXT", ["a", "b"])])
    assert parse_response(resp, 1)["answers"][0]["data"] == ["a", "b"]
    # AAAA
    resp = build_response(1, "x", TYPE_AAAA, [("AAAA", "2001:db8::1")])
    assert parse_response(resp, 1)["answers"][0]["data"] == "2001:db8::1"
    # SOA
    soa = ("n", "h", 1, 2, 3, 4, 5)
    resp = build_response(1, "x", TYPE_SOA, [("SOA", soa)])
    assert parse_response(resp, 1)["answers"][0]["data"] == {
        "mname": "n", "rname": "h", "serial": 1, "refresh": 2,
        "retry": 3, "expire": 4, "minimum": 5,
    }
    # Unknown
    raw_rr = b"\x01x\x00" + struct.pack("!HHIH", 99, 1, 60, 2) + b"\xde\xad"
    resp = build_query("x", 1, 1)[:12] + b"\x01x\x00" + struct.pack("!HH", 1, 1) + raw_rr
    resp = resp[:4] + struct.pack("!HHHH", 1, 1, 0, 0) + resp[12:]
    assert parse_response(resp, 1)["answers"][0]["raw"] == b"\xde\xad"

def test_parse_caa_ds():
    # CAA: flags=0, tag "issue", value "letsencrypt.org" (RFC 8659)
    resp = build_response(1, "x", TYPE_CAA, [("CAA", (0, "issue", "letsencrypt.org"))])
    assert parse_response(resp, 1)["answers"][0]["data"] == {
        "flags": 0, "tag": "issue", "value": "letsencrypt.org",
    }
    # CAA with the critical flag set and an iodef tag
    resp = build_response(1, "x", TYPE_CAA, [("CAA", (128, "iodef", "mailto:ops@example.com"))])
    assert parse_response(resp, 1)["answers"][0]["data"] == {
        "flags": 128, "tag": "iodef", "value": "mailto:ops@example.com",
    }
    # DS: key tag 12345, algorithm 8, digest type 2, SHA-256 digest (RFC 4034)
    digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    resp = build_response(1, "x", TYPE_DS, [("DS", (12345, 8, 2, digest))])
    assert parse_response(resp, 1)["answers"][0]["data"] == {
        "key_tag": 12345, "algorithm": 8, "digest_type": 2, "digest": digest,
    }

def _raw_response(rtype, rdata):
    """Hand-built response with one answer RR carrying arbitrary rdata."""
    raw_rr = b"\x01x\x00" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    resp = build_query("x", 1, 1)[:12] + b"\x01x\x00" + struct.pack("!HH", 1, 1) + raw_rr
    return resp[:4] + struct.pack("!HHHH", 1, 1, 0, 0) + resp[12:]

def test_parse_caa_ds_malformed_falls_back_to_raw():
    # CAA rdata too short to hold flags + tag length
    resp = _raw_response(TYPE_CAA, b"\x00")
    assert parse_response(resp, 1)["answers"][0]["raw"] == b"\x00"
    # CAA tag length overruns the record
    resp = _raw_response(TYPE_CAA, b"\x00\x05ab")
    assert parse_response(resp, 1)["answers"][0]["raw"] == b"\x00\x05ab"
    # DS rdata shorter than key-tag + algorithm + digest-type
    resp = _raw_response(TYPE_DS, b"\x30\x39\x08")
    assert parse_response(resp, 1)["answers"][0]["raw"] == b"\x30\x39\x08"

def test_parse_ptr():
    resp = build_response(1, "34.216.184.93.in-addr.arpa", TYPE_PTR, [("PTR", "example.com.")])
    assert parse_response(resp, 1)["answers"][0]["data"] == "example.com"


def test_parse_srv():
    # SRV: priority 0, weight 5, port 5060, target sip.example.com (RFC 2782)
    resp = build_response(1, "x", TYPE_SRV, [("SRV", (0, 5, 5060, "sip.example.com."))])
    assert parse_response(resp, 1)["answers"][0]["data"] == {
        "priority": 0, "weight": 5, "port": 5060, "target": "sip.example.com",
    }
    # Target "." (service explicitly not offered) still decodes
    resp = build_response(1, "x", TYPE_SRV, [("SRV", (0, 0, 0, "."))])
    assert parse_response(resp, 1)["answers"][0]["data"]["target"] == ""


def test_parse_srv_malformed_falls_back_to_raw():
    # SRV rdata shorter than priority + weight + port
    resp = _raw_response(TYPE_SRV, b"\x00\x00\x00\x05")
    assert parse_response(resp, 1)["answers"][0]["raw"] == b"\x00\x00\x00\x05"


def test_dns_client_logic(fake_dns_server):
    fake_dns_server["set"](example_table())
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["udp_port"])

    assert client.query("example.com", TYPE_A)["answers"][0]["data"] == "93.184.216.34"
    assert "ns1.example.com" in [r["data"] for r in client.query("example.com", TYPE_NS)["answers"]]

    with pytest.raises(DnsError, match="NXDOMAIN"):
        client.query("notexists.com", TYPE_A)

    tcp_client = DnsClient(server="127.0.0.1", port=fake_dns_server["tcp_port"])
    assert tcp_client.query_tcp("example.com", TYPE_A)["answers"][0]["data"] == "93.184.216.34"

    axfr_recs = tcp_client.axfr("example.com", "ns1.example.com")
    assert len(axfr_recs) >= 3
    assert sum(1 for r in axfr_recs if r["type"] == TYPE_SOA) == 2

def test_dns_client_axfr_refused(fake_dns_server):
    # Port with no TCP listener: connect is refused.
    fake_dns_server["set"](example_table())
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["udp_port"], timeout=2.0)
    with pytest.raises(DnsError):
        client.axfr("example.com", "ns1.example.com")

def test_dns_client_axfr_timeout(monkeypatch):
    # A connect that stalls must surface as a timeout, not "not supported",
    # so the per-nameserver report can tell timeout apart from refusal.
    class TimeoutSocket:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def connect(self, addr): raise socket.timeout("timed out")
        def sendall(self, data): pass
    monkeypatch.setattr("dnsx.dns.socket.socket", TimeoutSocket)
    client = DnsClient(server="127.0.0.1", port=53, timeout=0.5)
    with pytest.raises(DnsError, match="timed out"):
        client.axfr("example.com", "127.0.0.1")

def test_dns_client_tc_retry_uses_tcp(fake_dns_server):
    """A TC-flagged UDP reply is retried over TCP; the TCP answer wins."""
    from conftest import UDP_STATE
    table = example_table()
    fake_dns_server["set"](table)
    # UDP and TCP disagree on purpose, so the returned answer proves
    # which transport served the query.
    tcp_table = dict(table)
    tcp_table[("example.com", TYPE_A)] = [("A", "203.0.113.9")]
    fake_dns_server["table"].clear()
    fake_dns_server["table"].update(tcp_table)
    UDP_STATE["tc"] = {("example.com", TYPE_A)}
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["tcp_port"])
    resp = client.query("example.com", TYPE_A)
    assert resp["answers"][0]["data"] == "203.0.113.9"
    assert client.tcp_fallbacks == 1


def test_dns_client_tc_truncated_packet_retries_tcp(fake_dns_server):
    """A TC-flagged UDP reply cut short mid-record still retries over TCP.

    This is the case the old code missed: parsing the truncated body
    raised before the TC check ever ran, so no retry happened.
    """
    from conftest import UDP_STATE
    table = example_table()
    fake_dns_server["set"](table)
    tcp_table = dict(table)
    tcp_table[("example.com", TYPE_A)] = [("A", "203.0.113.9")]
    fake_dns_server["table"].clear()
    fake_dns_server["table"].update(tcp_table)
    UDP_STATE["tc"] = {("example.com", TYPE_A)}
    UDP_STATE["truncate_tc"] = True
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["tcp_port"])
    resp = client.query("example.com", TYPE_A)
    assert resp["answers"][0]["data"] == "203.0.113.9"
    assert client.tcp_fallbacks == 1


def test_dns_client_no_tc_uses_udp(fake_dns_server):
    """Without the TC bit the UDP answer is used and TCP is never touched."""
    from conftest import UDP_STATE
    table = example_table()
    fake_dns_server["set"](table)
    tcp_table = dict(table)
    tcp_table[("example.com", TYPE_A)] = [("A", "203.0.113.9")]
    fake_dns_server["table"].clear()
    fake_dns_server["table"].update(tcp_table)
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["tcp_port"])
    resp = client.query("example.com", TYPE_A)
    assert resp["answers"][0]["data"] == "93.184.216.34"
    assert client.tcp_fallbacks == 0


def test_dns_client_use_tcp_forces_tcp(fake_dns_server):
    """With use_tcp=True the query goes over TCP even when UDP would answer."""
    table = example_table()
    fake_dns_server["set"](table)
    # UDP and TCP disagree on purpose, so the returned answer proves
    # which transport served the query.
    tcp_table = dict(table)
    tcp_table[("example.com", TYPE_A)] = [("A", "203.0.113.9")]
    fake_dns_server["table"].clear()
    fake_dns_server["table"].update(tcp_table)
    client = DnsClient(server="127.0.0.1", port=fake_dns_server["tcp_port"], use_tcp=True)
    resp = client.query("example.com", TYPE_A)
    assert resp["answers"][0]["data"] == "203.0.113.9"
    # A direct-TCP query is not a TC fallback.
    assert client.tcp_fallbacks == 0
    assert DnsClient().use_tcp is False


def test_dns_timeout(udp_blackhole):
    client = DnsClient(server="127.0.0.1", port=59999, timeout=0.1, retries=0)
    with pytest.raises(DnsTimeout):
        client.query("example.com", TYPE_A)

