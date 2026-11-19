"""DNSSEC signed-answer check tests."""
import json
import struct
import pytest
from dnsx.dns import (
    DnsError, build_query, parse_response, TYPE_A, TYPE_RRSIG, TYPE_DS,
)
from dnsx.recon import Recon, RECORD_TYPES
from dnsx.report import render_text, render_json


def rrsig_answer(covered="A", key_tag=12345, signer="example.com."):
    """A parsed RRSIG record dict, as parse_response would produce."""
    return {"type": TYPE_RRSIG, "name": "example.com", "ttl": 300, "data": {
        "covered_type": RECORD_TYPES[covered], "algorithm": 8, "labels": 2,
        "original_ttl": 300, "expiration": 1795000000, "inception": 1794000000,
        "key_tag": key_tag, "signer": signer.rstrip(".")}}


class DnssecStubClient:
    """Stub client with controllable flags so the AD bit can be tested."""

    def __init__(self, answers, flags=0x8180):
        self.answers = answers
        self.flags = flags
        self.saw_dnssec = None

    def query(self, name, qtype, dnssec=False):
        self.saw_dnssec = dnssec
        if qtype == TYPE_A:
            return {"answers": self.answers, "authority": [], "additional": [],
                    "rcode": 0, "flags": self.flags}
        raise DnsError("Non-Existent Domain (NXDOMAIN)")


def test_build_query_dnssec_sets_do_bit():
    packet = build_query("example.com", TYPE_A, qid=0x1234, dnssec=True)
    header = struct.unpack("!HHHHHH", packet[:12])
    assert header[5] == 1  # ARCOUNT: one OPT record
    # OPT: root name, type 41, class 1232, TTL flags DO (0x8000), RDLEN 0.
    assert packet[-11:] == b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    plain = build_query("example.com", TYPE_A, qid=0x1234)
    assert struct.unpack("!HHHHHH", plain[:12])[5] == 0


def test_parse_rrsig_record():
    from conftest import build_response
    sig = b"\xde\xad\xbe\xef" * 4
    resp = build_response(0x2222, "example.com", TYPE_A, [
        ("A", "93.184.216.34"),
        ("RRSIG", ("A", 8, 2, 300, 1795000000, 1794000000, 12345,
                    "example.com.", sig)),
    ])
    parsed = parse_response(resp, 0x2222)
    rrsig = [r for r in parsed["answers"] if r["type"] == TYPE_RRSIG][0]
    assert rrsig["data"]["covered_type"] == TYPE_A
    assert rrsig["data"]["algorithm"] == 8
    assert rrsig["data"]["labels"] == 2
    assert rrsig["data"]["original_ttl"] == 300
    assert rrsig["data"]["expiration"] == 1795000000
    assert rrsig["data"]["inception"] == 1794000000
    assert rrsig["data"]["key_tag"] == 12345
    assert rrsig["data"]["signer"] == "example.com"


def test_parse_rrsig_malformed_falls_back_to_raw():
    # RRSIG rdata shorter than the 18-byte fixed part: raw fallback.
    # Hand-build a response with a truncated RRSIG record appended.
    qid = 0x2222
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    from dnsx.dns import encode_name
    body = build_query("example.com", TYPE_A, qid)[12:]
    body += encode_name("example.com")
    body += struct.pack("!HHIH", TYPE_RRSIG, 1, 60, 5) + b"\x00" * 5
    parsed = parse_response(header + body, qid)
    assert parsed["answers"][0]["raw"] == b"\x00" * 5


def test_dnssec_signed_with_ad_bit():
    client = DnssecStubClient(
        [{"type": TYPE_A, "data": "93.184.216.34"},
         rrsig_answer()],
        flags=0x8180 | 0x0020)  # AD bit set
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert client.saw_dnssec is True
    assert res.dnssec["signed"] is True
    assert res.dnssec["ad"] is True
    assert res.dnssec["rrsig_types"] == ["A"]
    assert res.dnssec["has_ds"] is False
    txt = render_text(res)
    assert "DNSSEC: signed (RRSIG for A; AD bit set)" in txt
    assert json.loads(render_json(res))["dnssec"]["signed"] is True


def test_dnssec_unsigned_no_rrsig():
    client = DnssecStubClient([{"type": TYPE_A, "data": "93.184.216.34"}])
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert res.dnssec["signed"] is False
    assert res.dnssec["ad"] is False
    assert res.dnssec["rrsig_types"] == []
    assert "DNSSEC: not signed (no RRSIG records; AD bit not set)" in render_text(res)


def test_dnssec_ad_bit_alone_is_not_signed():
    # A resolver may set AD from cache; without an RRSIG record the zone
    # is not reported as signed.
    client = DnssecStubClient([{"type": TYPE_A, "data": "93.184.216.34"}],
                              flags=0x8180 | 0x0020)
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert res.dnssec["signed"] is False
    assert res.dnssec["ad"] is True
    assert "DNSSEC: not signed (no RRSIG records; AD bit set)" in render_text(res)


def test_dnssec_has_ds_hint():
    client = DnssecStubClient([{"type": TYPE_A, "data": "93.184.216.34"}])
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=("A", "DS"), do_wildcard=False, do_axfr=False)
    # The stub raises NXDOMAIN for DS, so no DS records: has_ds stays False.
    assert res.dnssec["has_ds"] is False
    # With a DS record already enumerated, the hint is set.
    from dnsx.recon import ReconResult
    result = ReconResult(domain="example.com")
    result.records["DS"] = [{"type": TYPE_DS, "data": {"key_tag": 1}}]
    recon._check_dnssec("example.com", result)
    assert result.dnssec["has_ds"] is True


def test_dnssec_query_failure_is_not_fatal():
    class FailingClient:
        def query(self, name, qtype, dnssec=False):
            raise DnsError("Query timed out after 2 attempts")
    recon = Recon(client=FailingClient())
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert res.dnssec["signed"] is False
    assert "timed out" in res.dnssec["error"]
    assert "check failed" in render_text(res)


def test_dnssec_skipped_by_flag():
    client = DnssecStubClient([{"type": TYPE_A, "data": "93.184.216.34"},
                               rrsig_answer()])
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False,
                          do_axfr=False, do_dnssec=False)
    assert res.dnssec is None
    assert "[DNSSEC]" not in render_text(res)


def test_dnssec_live_fake_server(fake_dns_server):
    """End-to-end through the fake server: RRSIG answer arrives signed."""
    sig = b"\x01" * 16
    table = {
        ("example.com", TYPE_A): [
            ("A", "93.184.216.34"),
            ("RRSIG", ("A", 8, 2, 300, 1795000000, 1794000000, 12345,
                       "example.com.", sig)),
        ],
        ("example.com", TYPE_DS): [
            ("DS", (12345, 8, 2,
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90")),
        ],
    }
    fake_dns_server["set"](table)
    recon = Recon(server="127.0.0.1", port=fake_dns_server["tcp_port"], timeout=2.0)
    res = recon.enumerate("example.com", types=("A", "DS"),
                          do_wildcard=False, do_axfr=False,
                          do_cname_chain=False, do_mail_auth=False,
                          do_reverse_dns=False, do_srv=False)
    assert res.dnssec["signed"] is True
    assert res.dnssec["rrsig_types"] == ["A"]
    assert res.dnssec["has_ds"] is True
    assert "DNSSEC: signed (RRSIG for A" in render_text(res)
