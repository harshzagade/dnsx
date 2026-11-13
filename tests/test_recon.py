import pytest
import json
from dnsx.dns import DnsError, TYPE_A, TYPE_NS, TYPE_SOA
from dnsx.recon import Recon, ReconResult, format_record, RECORD_TYPES
from dnsx.report import render_text, render_json

class StubClient:
    def __init__(self, routes=None, axfr_data=None):
        self.routes = routes or {}
        self.axfr_data = axfr_data or []
    def query(self, name, qtype):
        res = self.routes.get((name.lower().rstrip("."), qtype))
        if isinstance(res, Exception): raise res
        if res is None: raise DnsError("Non-Existent Domain (NXDOMAIN)")
        return {"answers": res, "authority": [], "additional": [], "rcode": 0, "flags": 0x8180}
    def query_tcp(self, name, qtype): return self.query(name, qtype)
    def axfr(self, zone, ns):
        if self.axfr_data == "refused": raise DnsError("zone transfer refused")
        return self.axfr_data

def test_recon_happy_path():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "1.2.3.4", "name": "example.com", "ttl": 60}],
        ("example.com", RECORD_TYPES["NS"]): [{"type": 2, "data": "ns2.com.", "name": "example.com", "ttl": 60}, 
                                             {"type": 2, "data": "ns1.com.", "name": "example.com", "ttl": 60}],
    }
    recon = Recon(client=StubClient(routes, axfr_data="refused"))
    res = recon.enumerate("example.com", types=("A", "NS"), do_wildcard=True, do_axfr=True)
    assert res.domain == "example.com"
    assert "A" in res.records
    assert res.nameservers == ["ns1.com.", "ns2.com."]
    assert res.wildcard["detected"] is False
    assert res.zone_transfer["vulnerable"] is False

def test_recon_per_type_error():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "1.2.3.4"}],
        ("example.com", RECORD_TYPES["TXT"]): DnsError("boom")
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("A", "TXT"), do_wildcard=False, do_axfr=False)
    assert "A" in res.records
    assert res.errors["TXT"] == "boom"

def test_recon_wildcard_detected():
    def wild_query(name, qtype):
        if name.startswith("dnsx") and qtype == TYPE_A:
            return {"answers": [{"type": 1, "data": "203.0.113.7"}], "authority": [], "additional": [], "rcode": 0, "flags": 0x8180}
        raise DnsError("NXDOMAIN")
    
    client = StubClient()
    client.query = wild_query
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=True, do_axfr=False)
    assert res.wildcard["detected"] is True
    assert res.wildcard["ips"] == ["203.0.113.7"]

def test_recon_wildcard_onesided():
    count = 0
    def wild_query(name, qtype):
        nonlocal count
        count += 1
        if count == 1: return {"answers": [{"type": 1, "data": "203.0.113.7"}], "authority": [], "additional": [], "rcode": 0, "flags": 0x8180}
        raise DnsError("NXDOMAIN")
    
    client = StubClient()
    client.query = wild_query
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=True, do_axfr=False)
    assert res.wildcard["detected"] is False

def test_recon_zone_transfer():
    axfr_list = [{"type": TYPE_SOA, "data": ("ns1", "h", 1, 2, 3, 4, 5)}, 
                 {"type": TYPE_A, "data": "1.1.1.1"}, 
                 {"type": TYPE_SOA, "data": ("ns1", "h", 1, 2, 3, 4, 5)}]
    routes = {("example.com", TYPE_NS): [{"type": TYPE_NS, "data": "ns1.com."}]}
    client = StubClient(routes, axfr_data=axfr_list)
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=True)
    assert res.zone_transfer["vulnerable"] is True
    assert res.zone_transfer["nameserver"] == "ns1.com."
    assert res.zone_transfer["records"] == 3

def test_recon_axfr_failover():
    routes = {("example.com", TYPE_NS): [{"type": TYPE_NS, "data": "ns1.com."}, {"type": TYPE_NS, "data": "ns2.com."}]}
    class FailClient(StubClient):
        def axfr(self, zone, ns):
            if "ns1" in ns: raise DnsError("refused")
            return [{"type": TYPE_SOA, "data": (1,2,3,4,5,6,7)}]
    recon = Recon(client=FailClient(routes))
    res = recon.enumerate("example.com", types=(), do_axfr=True)
    assert res.zone_transfer["vulnerable"] is True
    assert res.zone_transfer["nameserver"] == "ns2.com."

def test_recon_caa_ds():
    routes = {
        ("example.com", RECORD_TYPES["CAA"]): [
            {"type": 257, "data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
             "name": "example.com", "ttl": 60}],
        ("example.com", RECORD_TYPES["DS"]): [
            {"type": 43, "data": {"key_tag": 12345, "algorithm": 8, "digest_type": 2,
                                 "digest": "aabbccdd"}, "name": "example.com", "ttl": 60}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("CAA", "DS"), do_wildcard=False, do_axfr=False)
    assert res.records["CAA"][0]["data"]["tag"] == "issue"
    assert res.records["DS"][0]["data"]["key_tag"] == 12345
    assert format_record(res.records["CAA"][0]) == '0 issue "letsencrypt.org"'
    assert format_record(res.records["DS"][0]) == "12345 8 2 AABBCCDD"

def test_recon_default_types_include_caa_ds():
    recon = Recon(client=StubClient())
    res = recon.enumerate("example.com", do_wildcard=False, do_axfr=False)
    assert "CAA" in res.records and "DS" in res.records
    assert "A" in res.records and "SOA" in res.records

def test_format_record():
    assert format_record({"type": 1, "data": "1.2.3.4"}) == "1.2.3.4"
    assert format_record({"type": 15, "data": (10, "mx.com")}) == "10 mx.com"
    assert format_record({"type": 16, "data": ["a", "b"]}) == "a b"
    assert "serial=2026" in format_record({"type": 6, "data": ("n", "h", 2026010101, 1, 1, 1, 1)})
    assert format_record({"type": 257, "data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}}) == '0 issue "letsencrypt.org"'
    assert format_record({"type": 43, "data": {"key_tag": 12345, "algorithm": 8, "digest_type": 2, "digest": "abcdef"}}) == "12345 8 2 ABCDEF"
    assert "b'\\x01\\x02'" in format_record({"type": 99, "raw": b"\x01\x02"})

def test_to_dict_serializable():
    res = ReconResult("ex.com", {"A": [{"type": 99, "raw": b"\x01"}]}, {}, [], {"detected": False}, {"vulnerable": False}, 0.1)
    d = res.to_dict()
    assert json.loads(json.dumps(d))["records"]["A"][0]["raw"] == "b'\\x01'"

def test_recon_invalid_domain():
    recon = Recon(client=StubClient())
    with pytest.raises(ValueError): recon.enumerate("", types=())
    with pytest.raises(ValueError): recon.enumerate("has space.com", types=())

def test_reports():
    res = ReconResult("example.com", {"A": [{"type": 1, "data": "93.184.216.34"}]}, {}, [], {"detected": False}, {"vulnerable": False, "notes": "refused"}, 0.1)
    txt = render_text(res)
    assert "DnsX report for example.com" in txt
    assert "[A]" in txt and "93.184.216.34" in txt
    assert "Wildcard DNS: not detected" in txt
    assert "Zone transfer: refused" in txt
    
    js = json.loads(render_json(res))
    assert js["domain"] == "example.com"
    assert js["records"]["A"][0]["data"] == "93.184.216.34"

