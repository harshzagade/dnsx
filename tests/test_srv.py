import json
import pytest
from dnsx.dns import DnsError, TYPE_SRV
from dnsx.recon import Recon, format_record, SRV_SERVICES
from dnsx.report import render_text, render_json
from dnsx.cli import main
from conftest import example_table


class StubClient:
    def __init__(self, routes=None):
        self.routes = routes or {}

    def query(self, name, qtype):
        res = self.routes.get((name.lower().rstrip("."), qtype))
        if isinstance(res, Exception):
            raise res
        if res is None:
            raise DnsError("Non-Existent Domain (NXDOMAIN)")
        return {"answers": res, "authority": [], "additional": [],
                "rcode": 0, "flags": 0x8180}

    def axfr(self, zone, ns):
        raise DnsError("zone transfer refused")


def _srv_record(prio, weight, port, target):
    return {"type": TYPE_SRV,
            "data": {"priority": prio, "weight": weight, "port": port,
                     "target": target},
            "name": "x", "ttl": 60}


def test_srv_found_for_some_services():
    routes = {
        ("_sip._tcp.example.com", TYPE_SRV): [
            _srv_record(0, 5, 5060, "sip.example.com."),
            _srv_record(10, 5, 5060, "sip2.example.com."),
        ],
        ("_ldap._tcp.example.com", TYPE_SRV): [
            _srv_record(0, 100, 389, "ldap.example.com."),
        ],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False)
    assert res.srv == {"services": {
        "_sip._tcp": [
            {"priority": 0, "weight": 5, "port": 5060,
             "target": "sip.example.com."},
            {"priority": 10, "weight": 5, "port": 5060,
             "target": "sip2.example.com."},
        ],
        "_ldap._tcp": [
            {"priority": 0, "weight": 100, "port": 389,
             "target": "ldap.example.com."},
        ],
    }}
    txt = render_text(res)
    assert "[SRV]" in txt
    assert "_sip._tcp.example.com  0 5 5060 sip.example.com." in txt
    assert "_ldap._tcp.example.com  0 100 389 ldap.example.com." in txt
    assert json.loads(render_json(res))["srv"] == res.srv


def test_srv_none_published():
    recon = Recon(client=StubClient())
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False)
    assert res.srv == {"services": {}}
    assert "No SRV records for common services" in render_text(res)


def test_srv_target_dot_kept():
    # RFC 2782: target "." means the service is explicitly not offered;
    # it is reported, not dropped.
    routes = {
        ("_sip._tcp.example.com", TYPE_SRV): [_srv_record(0, 0, 0, ".")],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False)
    assert res.srv["services"]["_sip._tcp"] == [
        {"priority": 0, "weight": 0, "port": 0, "target": "."}]
    assert "_sip._tcp.example.com  0 0 0 ." in render_text(res)


def test_srv_error_on_one_service_does_not_abort_others():
    routes = {
        ("_sip._tcp.example.com", TYPE_SRV): DnsError("boom"),
        ("_ldap._tcp.example.com", TYPE_SRV): [
            _srv_record(0, 100, 389, "ldap.example.com."),
        ],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False)
    assert list(res.srv["services"]) == ["_ldap._tcp"]


def test_srv_skipped_by_flag():
    routes = {
        ("_sip._tcp.example.com", TYPE_SRV): [
            _srv_record(0, 5, 5060, "sip.example.com."),
        ],
    }
    recon = Recon(client=StubClient(routes))
    res = recon.enumerate("example.com", types=(), do_wildcard=False,
                          do_axfr=False, do_srv=False)
    assert res.srv is None
    assert "[SRV]" not in render_text(res)


def test_format_record_srv():
    rec = {"type": TYPE_SRV,
           "data": {"priority": 0, "weight": 5, "port": 5060,
                    "target": "sip.example.com."}}
    assert format_record(rec) == "0 5 5060 sip.example.com."
    rec_tuple = {"type": TYPE_SRV, "data": (10, 5, 5060, "sip2.example.com.")}
    assert format_record(rec_tuple) == "10 5 5060 sip2.example.com."


def test_srv_services_match_queue():
    assert SRV_SERVICES == ("_sip._tcp", "_xmpp-client._tcp",
                            "_ldap._tcp", "_kerberos._tcp")


def test_cli_srv_end_to_end(fake_dns_server, capsys):
    table = example_table()
    table[("_sip._tcp.example.com", TYPE_SRV)] = [
        ("SRV", (0, 5, 5060, "sip.example.com."))]
    table[("_kerberos._tcp.example.com", TYPE_SRV)] = [
        ("SRV", (0, 100, 88, "kdc.example.com."))]
    fake_dns_server["set"](table)
    code = main(["example.com", "--server", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[SRV]" in out
    assert "_sip._tcp.example.com  0 5 5060 sip.example.com" in out
    assert "_kerberos._tcp.example.com  0 100 88 kdc.example.com" in out

    code = main(["example.com", "--server", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]),
                 "--no-axfr", "--no-srv"])
    assert code == 0
    assert "[SRV]" not in capsys.readouterr().out
