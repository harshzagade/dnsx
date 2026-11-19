import pytest
import json
from dnsx.dns import DnsError, TYPE_A, TYPE_NS, TYPE_SOA, TYPE_PTR
from dnsx.recon import (Recon, ReconResult, format_record, RECORD_TYPES,
                        parse_spf_record, parse_dmarc_record)
from dnsx.report import render_text, render_json

class StubClient:
    def __init__(self, routes=None, axfr_data=None):
        self.routes = routes or {}
        self.axfr_data = axfr_data or []
    def query(self, name, qtype, dnssec=False):
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
    def wild_query(name, qtype, dnssec=False):
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
    def wild_query(name, qtype, dnssec=False):
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

def test_recon_axfr_per_server_all_refused():
    routes = {("example.com", TYPE_NS): [{"type": TYPE_NS, "data": "ns1.com."}, {"type": TYPE_NS, "data": "ns2.com."}]}
    recon = Recon(client=StubClient(routes, axfr_data="refused"))
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=True)
    assert res.zone_transfer["vulnerable"] is False
    assert res.zone_transfer["nameserver"] is None
    assert res.zone_transfer["records"] == 0
    servers = res.zone_transfer["servers"]
    assert [(s["nameserver"], s["status"]) for s in servers] == [
        ("ns1.com.", "refused"), ("ns2.com.", "refused")]
    assert res.zone_transfer["note"] == "zone transfer refused by all nameservers"
    text = render_text(res)
    assert "ns1.com.: refused" in text
    assert "ns2.com.: refused" in text

def test_recon_axfr_per_server_mixed():
    routes = {("example.com", TYPE_NS): [{"type": TYPE_NS, "data": "ns1.com."}, {"type": TYPE_NS, "data": "ns2.com."}]}
    class FailClient(StubClient):
        def axfr(self, zone, ns):
            if "ns1" in ns: raise DnsError("zone transfer refused")
            return [{"type": TYPE_SOA, "data": (1,2,3,4,5,6,7)}]
    recon = Recon(client=FailClient(routes))
    res = recon.enumerate("example.com", types=(), do_axfr=True)
    assert res.zone_transfer["vulnerable"] is True
    assert res.zone_transfer["nameserver"] == "ns2.com."
    assert res.zone_transfer["records"] == 1
    servers = res.zone_transfer["servers"]
    assert [(s["nameserver"], s["status"]) for s in servers] == [
        ("ns1.com.", "refused"), ("ns2.com.", "allowed")]
    assert servers[1]["records"] == 1
    text = render_text(res)
    assert "ns1.com.: refused" in text
    assert "ns2.com.: ALLOWED (1 records)" in text
    assert "VULNERABLE via ns2.com. (1 records)" in text

def test_recon_axfr_per_server_timeout():
    routes = {("example.com", TYPE_NS): [{"type": TYPE_NS, "data": "ns1.com."}, {"type": TYPE_NS, "data": "ns2.com."}]}
    class TimeoutClient(StubClient):
        def axfr(self, zone, ns):
            if "ns1" in ns: raise DnsError("zone transfer timed out")
            raise DnsError("zone transfer refused")
    recon = Recon(client=TimeoutClient(routes))
    res = recon.enumerate("example.com", types=(), do_axfr=True)
    assert res.zone_transfer["vulnerable"] is False
    servers = res.zone_transfer["servers"]
    assert [(s["nameserver"], s["status"]) for s in servers] == [
        ("ns1.com.", "timeout"), ("ns2.com.", "refused")]
    assert "timeout" in res.zone_transfer["note"]
    assert "refused" in res.zone_transfer["note"]
    text = render_text(res)
    assert "ns1.com.: timeout" in text
    data = json.loads(render_json(res))
    assert data["zone_transfer"]["servers"][0]["status"] == "timeout"

def test_recon_records_resolver_and_timeout():
    client = StubClient()
    client.server = "1.1.1.1"
    client.timeout = 2.5
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.resolver == "1.1.1.1"
    assert res.timeout == 2.5
    d = res.to_dict()
    assert d["resolver"] == "1.1.1.1"
    assert d["timeout"] == 2.5

def test_recon_resolver_defaults_to_none_without_client_attrs():
    recon = Recon(client=StubClient())
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.resolver is None
    assert res.timeout is None
    assert res.to_dict()["resolver"] is None

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
    assert format_record({"type": 12, "data": "example.com."}) == "example.com."
    assert "b'\\x01\\x02'" in format_record({"type": 99, "raw": b"\x01\x02"})

def test_to_dict_serializable():
    res = ReconResult("ex.com", {"A": [{"type": 99, "raw": b"\x01"}]}, {}, [], {"detected": False}, {"vulnerable": False}, 0.1)
    d = res.to_dict()
    assert json.loads(json.dumps(d))["records"]["A"][0]["raw"] == "b'\\x01'"

def test_recon_cname_chain_resolved():
    routes = {
        ("www.example.com", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "cdn.example.net.", "name": "www.example.com", "ttl": 60}],
        ("cdn.example.net", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "edge.example.net.", "name": "cdn.example.net", "ttl": 60}],
        ("edge.example.net", RECORD_TYPES["A"]): [{"type": 1, "data": "93.184.216.34", "name": "edge.example.net", "ttl": 60}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("www.example.com", types=("A",), do_wildcard=False, do_axfr=False)
    chain = res.cname_chain
    assert chain["status"] == "resolved"
    assert chain["final"] == "edge.example.net"
    assert chain["addresses"] == ["93.184.216.34"]
    assert chain["hops"] == [
        {"name": "www.example.com", "target": "cdn.example.net"},
        {"name": "cdn.example.net", "target": "edge.example.net"},
    ]
    txt = render_text(res)
    assert "www.example.com -> cdn.example.net -> edge.example.net (93.184.216.34)" in txt
    assert json.loads(render_json(res))["cname_chain"]["status"] == "resolved"

def test_recon_cname_chain_loop():
    routes = {
        ("a.example.com", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "b.example.com."}],
        ("b.example.com", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "a.example.com."}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("a.example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.cname_chain["status"] == "loop"
    assert "loop detected" in render_text(res)

def test_recon_cname_chain_dead_end():
    routes = {
        ("www.example.com", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "gone.example.net."}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("www.example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.cname_chain["status"] == "dead-end"
    assert res.cname_chain["addresses"] == []
    assert "no A/AAAA records at gone.example.net" in render_text(res)

def test_recon_no_cname_chain_when_plain_a():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "1.2.3.4"}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert res.cname_chain is None
    assert "[CNAME chain]" not in render_text(res)

def test_recon_cname_chain_skipped_by_flag():
    routes = {
        ("www.example.com", RECORD_TYPES["CNAME"]): [{"type": 5, "data": "cdn.example.net."}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("www.example.com", types=(), do_wildcard=False, do_axfr=False, do_cname_chain=False)
    assert res.cname_chain is None

def test_parse_spf_record():
    parsed = parse_spf_record("v=spf1 include:_spf.google.com include:mailgun.org -all")
    assert parsed["policy"] == "-all"
    assert parsed["includes"] == ["_spf.google.com", "mailgun.org"]
    assert parse_spf_record("v=spf1 ~all")["policy"] == "~all"
    assert parse_spf_record("v=spf1 all")["policy"] == "+all"
    assert parse_spf_record("v=spf1 mx -all")["includes"] == []
    assert parse_spf_record("v=spf1 -all")["policy"] == "-all"
    assert parse_spf_record("not spf") is None
    assert parse_spf_record("v=spf1")["policy"] is None


def test_parse_dmarc_record():
    parsed = parse_dmarc_record("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com")
    assert parsed["policy"] == "reject"
    assert parsed["subdomain_policy"] == "quarantine"
    assert parse_dmarc_record("v=DMARC1; p=none")["subdomain_policy"] is None
    assert parse_dmarc_record("v=spf1 -all") is None


def test_recon_mail_auth_present():
    routes = {
        ("example.com", RECORD_TYPES["TXT"]): [
            {"type": 16, "data": ["v=spf1 include:_spf.google.com include:mailgun.org -all"]}],
        ("_dmarc.example.com", RECORD_TYPES["TXT"]): [
            {"type": 16, "data": ["v=DMARC1; p=reject; sp=quarantine"]}],
        ("google._domainkey.example.com", RECORD_TYPES["TXT"]): [
            {"type": 16, "data": ["v=DKIM1; k=rsa; p=abc"]}],
        ("selector1._domainkey.example.com", RECORD_TYPES["TXT"]): [
            {"type": 16, "data": ["v=DKIM1; k=rsa; p=def"]}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("TXT",), do_wildcard=False, do_axfr=False)
    auth = res.mail_auth
    assert auth["spf"]["policy"] == "-all"
    assert auth["spf"]["includes"] == ["_spf.google.com", "mailgun.org"]
    assert auth["dmarc"]["policy"] == "reject"
    assert auth["dmarc"]["subdomain_policy"] == "quarantine"
    assert auth["dkim"]["selectors"] == ["google", "selector1"]
    txt = render_text(res)
    assert "SPF: -all (2 includes: _spf.google.com, mailgun.org) | DMARC: p=reject (sp=quarantine) | DKIM: google, selector1" in txt
    assert json.loads(render_json(res))["mail_auth"]["dmarc"]["policy"] == "reject"


def test_recon_mail_auth_absent():
    recon = Recon(client=StubClient())
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=False)
    auth = res.mail_auth
    assert auth["spf"] is None
    assert auth["dmarc"] is None
    assert auth["dkim"]["selectors"] == []
    assert "SPF: none | DMARC: none | DKIM: none" in render_text(res)


def test_recon_mail_auth_skipped_by_flag():
    routes = {
        ("example.com", RECORD_TYPES["TXT"]): [
            {"type": 16, "data": ["v=spf1 -all"]}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("TXT",), do_wildcard=False, do_axfr=False, do_mail_auth=False)
    assert res.mail_auth is None
    assert "[Mail auth]" not in render_text(res)

def test_recon_reverse_dns_resolved():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "93.184.216.34"}],
        ("example.com", RECORD_TYPES["AAAA"]): [{"type": 28, "data": "2001:db8::1"}],
        ("34.216.184.93.in-addr.arpa", TYPE_PTR): [{"type": 12, "data": "example.com."}],
        ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", TYPE_PTR):
            [{"type": 12, "data": "v6.example.com."}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("A", "AAAA"), do_wildcard=False, do_axfr=False)
    assert res.reverse_dns == {"lookups": {"93.184.216.34": "example.com.",
                                           "2001:db8::1": "v6.example.com."}}
    txt = render_text(res)
    assert "93.184.216.34 -> example.com." in txt
    assert "2001:db8::1 -> v6.example.com." in txt
    assert json.loads(render_json(res))["reverse_dns"]["lookups"]["93.184.216.34"] == "example.com."


def test_recon_reverse_dns_missing_ptr():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "93.184.216.34"}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False)
    assert res.reverse_dns == {"lookups": {"93.184.216.34": None}}
    assert "93.184.216.34 -> (no PTR record)" in render_text(res)


def test_recon_reverse_dns_no_ips():
    recon = Recon(client=StubClient())
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.reverse_dns == {"lookups": {}}
    assert "[Reverse DNS]" not in render_text(res)


def test_recon_reverse_dns_skipped_by_flag():
    routes = {
        ("example.com", RECORD_TYPES["A"]): [{"type": 1, "data": "93.184.216.34"}],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=("A",), do_wildcard=False, do_axfr=False, do_reverse_dns=False)
    assert res.reverse_dns is None
    assert "[Reverse DNS]" not in render_text(res)


def test_recon_invalid_domain():
    recon = Recon(client=StubClient())
    with pytest.raises(ValueError): recon.enumerate("", types=())
    with pytest.raises(ValueError): recon.enumerate("has space.com", types=())

def _brute_routes():
    return {
        ("www.example.com", TYPE_A): [{"type": 1, "data": "93.184.216.34"}],
        ("api.example.com", TYPE_A): [{"type": 1, "data": "93.184.216.99"}],
        ("mail.example.com", TYPE_A): [{"type": 1, "data": "203.0.113.7"}],
    }

def test_brute_force_hits_and_misses():
    recon = Recon(client=StubClient(_brute_routes()))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False, do_brute_force=True,
                          wordlist=["www", "api", "nope", "mail"])
    bf = res.brute_force
    assert bf["tried"] == 4
    assert [h["subdomain"] for h in bf["hits"]] == [
        "www.example.com", "api.example.com", "mail.example.com"]
    assert bf["hits"][0]["ips"] == ["93.184.216.34"]
    assert bf["filtered"] == []  # wildcard check skipped: nothing filtered
    assert bf["errors"] == 0

def test_brute_force_wildcard_filtering():
    # Wildcard answers 203.0.113.7 for any random label; mail resolves to
    # only that IP so it is filtered, while www/api keep their own IPs.
    def wild_query(name, qtype, dnssec=False):
        routes = _brute_routes()
        key = (name.lower().rstrip("."), qtype)
        if key in routes:
            return {"answers": routes[key], "authority": [], "additional": [], "rcode": 0, "flags": 0x8180}
        if name.startswith("dnsx") and qtype == TYPE_A:
            return {"answers": [{"type": 1, "data": "203.0.113.7"}], "authority": [], "additional": [], "rcode": 0, "flags": 0x8180}
        raise DnsError("NXDOMAIN")
    client = StubClient()
    client.query = wild_query
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=True,
                          do_axfr=False, do_brute_force=True,
                          wordlist=["www", "api", "mail"])
    assert res.wildcard["detected"] is True
    bf = res.brute_force
    assert [h["subdomain"] for h in bf["hits"]] == ["www.example.com", "api.example.com"]
    assert [f["subdomain"] for f in bf["filtered"]] == ["mail.example.com"]
    assert bf["wildcard_ips"] == ["203.0.113.7"]
    txt = render_text(res)
    assert "[Subdomains]" in txt
    assert "Subdomains found: 2 (3 labels tried, 1 filtered as wildcard)" in txt
    assert "www.example.com -> 93.184.216.34" in txt
    assert "mail.example.com" not in txt.split("[Subdomains]")[1]

def test_brute_force_error_counted_not_fatal():
    def flaky_query(name, qtype, dnssec=False):
        if name.startswith("www"):
            raise DnsError("SERVFAIL")
        raise DnsError("NXDOMAIN")
    client = StubClient()
    client.query = flaky_query
    recon = Recon(client=client)
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False, do_brute_force=True,
                          wordlist=["www", "api"])
    assert res.brute_force["errors"] == 1
    assert res.brute_force["hits"] == []

def test_brute_force_off_by_default():
    recon = Recon(client=StubClient(_brute_routes()))
    res = recon.enumerate("example.com", types=(), do_wildcard=False, do_axfr=False)
    assert res.brute_force is None
    assert "[Subdomains]" not in render_text(res)

def test_brute_force_builtin_wordlist():
    from dnsx.recon import BRUTE_WORDLIST
    assert len(BRUTE_WORDLIST) >= 40
    assert "www" in BRUTE_WORDLIST and "api" in BRUTE_WORDLIST
    assert len(set(BRUTE_WORDLIST)) == len(BRUTE_WORDLIST)  # no duplicates
    recon = Recon(client=StubClient(_brute_routes()))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False, do_brute_force=True)
    assert res.brute_force["tried"] == len(BRUTE_WORDLIST)
    assert "www.example.com" in [h["subdomain"] for h in res.brute_force["hits"]]

def test_reports():
    res = ReconResult("example.com", {"A": [{"type": 1, "data": "93.184.216.34"}]}, {}, [], {"detected": False}, {"vulnerable": False, "notes": "refused"}, 0.1)
    txt = render_text(res)
    assert "DnsX report for example.com" in txt
    assert "[A]" in txt and "93.184.216.34" in txt
    assert "Wildcard DNS: not detected" in txt
    assert "Zone transfer: refused" in txt

    # A result that knows its resolver shows it in the text report.
    res2 = ReconResult("example.com", {}, {}, [], None, None, 0.1, "1.1.1.1", 2.5)
    assert "Resolver: 1.1.1.1 (timeout 2.5s)" in render_text(res2)

    js = json.loads(render_json(res))
    assert js["domain"] == "example.com"
    assert js["records"]["A"][0]["data"] == "93.184.216.34"

