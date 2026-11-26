import pytest
import json
from dnsx import __version__
from dnsx.cli import main
from dnsx.dns import TYPE_A, TYPE_CNAME, TYPE_TXT, TYPE_PTR, TYPE_NS
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


def test_cli_mail_auth_end_to_end(fake_dns_server, capsys):
    table = example_table()
    table[("_dmarc.example.com", TYPE_TXT)] = [("TXT", ["v=DMARC1; p=quarantine"])]
    table[("google._domainkey.example.com", TYPE_TXT)] = [("TXT", ["v=DKIM1; k=rsa; p=abc"])]
    fake_dns_server["set"](table)
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[Mail auth]" in out
    assert "SPF: -all | DMARC: p=quarantine | DKIM: google" in out


def test_cli_reverse_dns_end_to_end(fake_dns_server, capsys):
    table = example_table()
    table[("34.216.184.93.in-addr.arpa", TYPE_PTR)] = [("PTR", "example.com.")]
    fake_dns_server["set"](table)
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[Reverse DNS]" in out
    assert "93.184.216.34 -> example.com" in out
    assert "(no PTR record)" in out  # the AAAA address has no PTR in the table


def test_cli_apex_www_end_to_end(fake_dns_server, capsys):
    # example_table: www has the apex A but no AAAA, so the sets differ.
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[Apex vs www]" in out
    assert "[!] WARNING: apex and www serve different addresses" in out


def test_cli_no_apex_www(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr", "--no-apex-www"])
    assert code == 0
    assert "[Apex vs www]" not in capsys.readouterr().out


def test_cli_tcp_end_to_end(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--no-axfr", "--tcp"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Resolver: 127.0.0.1" in out
    assert "[TCP]" in out
    assert "93.184.216.34" in out


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


def test_cli_brute_end_to_end(fake_dns_server, capsys):
    table = example_table()
    table[("api.example.com", TYPE_A)] = [("A", "93.184.216.99")]
    fake_dns_server["set"](table)
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--brute", "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[Subdomains]" in out
    assert "www.example.com -> 93.184.216.34" in out
    assert "api.example.com -> 93.184.216.99" in out
    assert "ns1.example.com -> 127.0.0.1" in out


def test_cli_brute_wildcard_filter_end_to_end(fake_dns_server, capsys):
    fake_dns_server["set"](wild_table())
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]), "--brute", "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "[Subdomains]" in out
    assert "www.example.com -> 93.184.216.34" in out  # real hit: own IP
    assert "filtered as wildcard" in out
    section = out.split("[Subdomains]")[1]
    assert "mail.example.com" not in section  # only the wildcard IP: filtered


def test_cli_brute_wordlist_file(fake_dns_server, tmp_path, capsys):
    table = example_table()
    table[("api.example.com", TYPE_A)] = [("A", "93.184.216.99")]
    fake_dns_server["set"](table)
    wl = tmp_path / "words.txt"
    wl.write_text("# comment line\n\napi\nwww\n")
    code = main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"]),
                 "--wordlist", str(wl), "--no-axfr"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Subdomains found: 2 (2 labels tried)" in out
    assert "api.example.com -> 93.184.216.99" in out


def test_cli_wordlist_errors(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    with pytest.raises(SystemExit) as e:
        main(["example.com", "--wordlist", str(missing)])
    assert e.value.code == 2

    bad = tmp_path / "bad.txt"
    bad.write_text("good\nbad_label!\n")
    with pytest.raises(SystemExit) as e:
        main(["example.com", "--wordlist", str(bad)])
    assert e.value.code == 2

    empty = tmp_path / "empty.txt"
    empty.write_text("# only a comment\n")
    with pytest.raises(SystemExit) as e:
        main(["example.com", "--wordlist", str(empty)])
    assert e.value.code == 2


def test_cli_batch_end_to_end(fake_dns_server, tmp_path, capsys):
    table = example_table()
    table[("example.org", TYPE_A)] = [("A", "93.184.216.35")]
    table[("example.org", TYPE_NS)] = [("NS", "ns1.example.org.")]
    fake_dns_server["set"](table)
    batch = tmp_path / "domains.txt"
    batch.write_text("# comment line\n\nexample.com\nexample.org\n")
    code = main(["--file", str(batch), "--server", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("example.com:")
    assert "A=93.184.216.34" in lines[0]
    assert "NS=2" in lines[0]
    assert "MX=mail.example.com" in lines[0]
    assert "wildcard=no" in lines[0]
    assert lines[1].startswith("example.org:")
    assert "A=93.184.216.35" in lines[1]
    assert "NS=1" in lines[1]
    assert "MX=none" in lines[1]


def test_cli_batch_json(fake_dns_server, tmp_path, capsys):
    fake_dns_server["set"](example_table())
    batch = tmp_path / "domains.txt"
    batch.write_text("example.com\n")
    code = main(["--file", str(batch), "--server", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]), "--json", "--no-axfr"])
    assert code == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["domain"] == "example.com"
    assert data["records"]["A"][0]["data"] == "93.184.216.34"


def test_cli_batch_bad_line_keeps_going(fake_dns_server, tmp_path, capsys):
    fake_dns_server["set"](example_table())
    batch = tmp_path / "domains.txt"
    batch.write_text("not a domain\nexample.com\n")
    code = main(["--file", str(batch), "--server", "127.0.0.1",
                 "--port", str(fake_dns_server["tcp_port"]), "--no-axfr"])
    assert code == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("not a domain: ERROR")
    assert lines[1].startswith("example.com:")
    assert "A=93.184.216.34" in lines[1]


def test_cli_batch_file_errors(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    with pytest.raises(SystemExit) as e:
        main(["--file", str(missing)])
    assert e.value.code == 2

    empty = tmp_path / "empty.txt"
    empty.write_text("# only a comment\n")
    with pytest.raises(SystemExit) as e:
        main(["--file", str(empty)])
    assert e.value.code == 2

    with pytest.raises(SystemExit) as e:
        main(["example.com", "--file", str(empty)])
    assert e.value.code == 2

    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2


def test_cli_axfr_end_to_end(fake_dns_server, capsys):
    fake_dns_server["set"](example_table())
    main(["example.com", "--server", "127.0.0.1", "--port", str(fake_dns_server["tcp_port"])])
    assert "Zone transfer: VULNERABLE" in capsys.readouterr().out
