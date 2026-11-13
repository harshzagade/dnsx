import pytest
import socket
import struct
from dnsx.dns import (
    encode_name, decode_name, build_query, parse_response, DnsClient,
    DnsError, DnsTimeout, TYPE_A, TYPE_AAAA, TYPE_NS, TYPE_MX, TYPE_TXT, TYPE_SOA
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

def test_dns_timeout(udp_blackhole):
    client = DnsClient(server="127.0.0.1", port=59999, timeout=0.1, retries=0)
    with pytest.raises(DnsTimeout):
        client.query("example.com", TYPE_A)

