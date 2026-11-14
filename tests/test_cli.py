import pytest
import json
from dnsx import __version__
from dnsx.cli import main
from dnsx.dns import TYPE_A, TYPE_CNAME
from conftest import example_table, wild_table


def test_cli_cname_chain_end_to_end(fake_dns_server, capsys):
    table = example_table()
    table[("www.example.com", TYPE_CNAME)] = [("CNAME", "alias.example.com.")]
    table[("alias.example.com", TYPE_A)] = [("A", "93.184.216.34")]
    fake_dns_server["set"](table)
    code = main(["www.example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[CNAME chain]" in out
    assert "www.example.com -> alias.example.com (93.184.216.34)" in out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert f"dnsx {__version__}" in capsys.readouterr().out


def test_cli_basic(fake_dns_server, capsys):
    # UDP queries are answered in-process from the table (see conftest);
    # --port points at the fake TCP server, used for AXFR.
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "DnsX report for example.com" in out
    assert "93.184.216.34" in out
    assert "[MX]" in out
    assert "10 mail.example.com" in out
    assert "[CAA]" in out
    assert '0 issue "letsencrypt.org"' in out
    assert "[DS]" in out
    assert "12345 8 2" in out


def test_cli_resolver(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--resolver", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Resolver: 127.0.0.1" in out
    assert "93.184.216.34" in out


def test_cli_resolver_overrides_server(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--server", "8.8.8.8", "--resolver", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    assert "Resolver: 127.0.0.1" in capsys.readouterr().out


def test_cli_json(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--json", "--no-axfr"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["domain"] == "example.com"
    assert data["records"]["A"][0]["data"] == "93.184.216.34"
    assert data["records"]["CAA"][0]["data"] == {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
    assert data["records"]["DS"][0]["data"]["key_tag"] == 12345
    assert data["records"]["DS"][0]["data"]["algorithm"] == 8
    assert data["records"]["DS"][0]["data"]["digest_type"] == 2
    assert data["resolver"] == "127.0.0.1"
    assert data["timeout"] == 5.0


def test_cli_types_filter(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--types", "A,MX", "--no-axfr"])
    out = capsys.readouterr().out
    assert "[A]" in out and "[MX]" in out
    assert "[NS]" not in out and "[TXT]" not in out


def test_cli_errors(capsys):
    with pytest.raises(SystemExit) as e:
        main(["example.com", "--types", "A,FOO"])
    assert e.value.code == 2

    # Empty domain: enumerate raises ValueError, main returns 2 (no SystemExit).
    assert main(["", "--server", "127.0.0.1"]) == 2
    assert "error:" in capsys.readouterr().err

    with pytest.raises(SystemExit) as e:
        main(["ex.com", "--timeout", "0"])
    assert e.value.code == 2

    with pytest.raises(SystemExit) as e:
        main(["ex.com", "--port", "99999"])
    assert e.value.code == 2

    with pytest.raises(SystemExit) as e:
        main(["ex.com", "--resolver", "not-an-ip"])
    assert e.value.code == 2


def test_cli_wildcard_end_to_end(fake_dns_server, capsys):
    fake_dns_server["set"](wild_table())
    main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert "Wildcard DNS: DETECTED" in capsys.readouterr().out


def test_cli_axfr_end_to_end(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"])])
    assert "Zone transfer: VULNERABLE" in capsys.readouterr().out
