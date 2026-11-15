# DnsX

Stdlib-only DNS recon for authorized assessments: enumerate a domain's DNS
records, detect wildcard DNS, and test whether its nameservers allow zone
transfers. No third-party dependencies — the DNS wire protocol (UDP + TCP,
including AXFR) is implemented from scratch on Python's `socket` module.

Built for recon work where you need quick DNS answers without installing
`dnspython` or reaching for `dig` on a box that doesn't have it.

## Install

Python 3.11+ — nothing to install.

```bash
git clone https://github.com/harshzagade/dnsx.git
cd dnsx
python3 -m dnsx example.com
```

Or run it without cloning the entry point:

```bash
python3 -m dnsx --help
```

## Usage

```bash
# Full recon: A, AAAA, NS, MX, TXT, SOA, CAA, DS + wildcard check + zone-transfer test
python3 -m dnsx example.com

# Only some record types, JSON output, custom resolver
python3 -m dnsx example.com --types A,MX,TXT --json --resolver 1.1.1.1

# Skip the wildcard / zone-transfer checks (faster, quieter)
python3 -m dnsx example.com --no-wildcard --no-axfr

# Non-standard resolver port (handy for a local test server)
python3 -m dnsx example.com --server 127.0.0.1 --port 5353
```

Options:

| Flag | Default | Meaning |
|------|---------|---------|
| `domain` | — | Domain to scan |
| `--server` | `8.8.8.8` | DNS resolver to query |
| `--resolver` | — | Resolver IP to query (overrides `--server`; must be an IP) |
| `--port` | `53` | Resolver port |
| `--timeout` | `5.0` | Per-query timeout in seconds |
| `--types` | `A,AAAA,NS,MX,TXT,SOA,CAA,DS` | Comma-separated record types (`A,AAAA,NS,MX,TXT,SOA,CNAME,CAA,DS`) |
| `--json` | off | Machine-readable JSON output |
| `--no-wildcard` | off | Skip wildcard detection |
| `--no-axfr` | off | Skip the zone-transfer test |
| `--no-cname-chain` | off | Skip CNAME chain following |
| `--no-mail-auth` | off | Skip the SPF/DKIM/DMARC summary |
| `--version` | — | Print version and exit |

Exit codes: `0` clean run, `1` DNS/network error, `2` bad arguments or
domain.

## Sample output

```text
$ python3 -m dnsx example.com

DnsX report for example.com

[A]
  example.com           165s  172.66.147.243
  example.com           165s  104.20.23.154

[AAAA]
  example.com           156s  2606:4700:10::ac42:93f3
  example.com           156s  2606:4700:10::6814:179a

[NS]
  example.com           21600s  hera.ns.cloudflare.com
  example.com           21600s  elliott.ns.cloudflare.com

[MX]
  example.com           280s  0 .

[TXT]
  example.com           300s  v=spf1 -all
  example.com           300s  _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9

[SOA]
  example.com           345s  elliott.ns.cloudflare.com dns.cloudflare.com serial=2418004112 refresh=10000 retry=2400 expire=604800 minimum=1800

[CAA]
  example.com           300s  0 issue "letsencrypt.org"

[DS]
  example.com           300s  12345 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90

[Wildcard]
Wildcard DNS: not detected

[Zone transfer]
Zone transfer: zone transfer refused by all nameservers

Scan took 22.778s
```

A vulnerable zone transfer looks like this instead:

```text
[Zone transfer]
Zone transfer: VULNERABLE via ns1.example.com (41 records)
```

(`--json` adds a `sample` field with the first 5 transferred records.)

Every report ends with a one-line mail-authentication summary built from
the domain's own records:

```text
[Mail auth]
SPF: -all (2 includes: _spf.google.com, mailgun.org) | DMARC: p=reject (sp=quarantine) | DKIM: google, selector1
```

SPF is parsed from the domain's TXT records (`v=spf1`, the `all`
qualifier and the `include:` list); DMARC from `_dmarc.<domain>`
(`p=` and `sp=`); DKIM by probing eight well-known selectors
(`default`, `google`, `selector1`, `selector2`, `mail`, `dkim`, `k1`,
`s1`) under `_domainkey.<domain>` for a published `v=DKIM1` key.
Selectors cannot be enumerated from DNS, so a domain using an unusual
selector name simply shows fewer (or no) DKIM selectors — the check
reports what it finds, never guesses. `--json` carries the same data
as a `mail_auth` object.

A CNAME'd name gets its chain followed to the final address:

```text
[CNAME chain]
www.example.com -> cdn.example.net -> edge.example.net (93.184.216.34)
```

A chain that ends at a name with no A/AAAA records is reported as a
dead end, and a cycle (or a chain longer than 10 hops) is flagged
instead of followed forever. `--json` carries the same data as a
`cname_chain` object with `hops`, `final`, `addresses`, and `status`.

`--json` output also carries the `resolver` IP and `timeout` used for the
scan, and the text report prints them under the title, so a saved report
always shows where its answers came from.

## How it works

- **Wire protocol** (`dnsx/dns.py`): builds and parses DNS messages by
  hand — label encoding, compression pointers, and record decoding for
  A, AAAA, NS, CNAME, MX, TXT, SOA, CAA, and DS. UDP with automatic TCP fallback
  when the TC (truncated) bit is set — the bit is read from the reply
  header before the body is parsed, so a reply cut short mid-record still
  triggers the retry instead of surfacing a parse error; AXFR runs over TCP.
  The number of TCP retries is reported as `tcp_fallbacks` in `--json`.
- **Wildcard detection** (`dnsx/recon.py`): queries two random
  `dnsx<hex>.example.com` names. A wildcard is reported only when both
  resolve *and* share at least one IP, so a single anycast fluke can't
  flip the result.
- **Zone-transfer test** (`dnsx/recon.py`): tries AXFR against each
  nameserver in turn (max 3) and reports the first one that hands over
  the zone.
- **CNAME chain following** (`dnsx/recon.py`): when the target returns a
  CNAME, each hop is followed (max 10, cycles detected) until the final
  A/AAAA answer, and every hop is shown in the report.
- **Mail-auth summary** (`dnsx/recon.py`): parses SPF from TXT, DMARC
  from `_dmarc`, and probes well-known DKIM selectors for a published
  key, printed as one summary line.
- **Output** (`dnsx/report.py`): plain-text report for humans, `--json`
  for pipelines.

## Tests

```bash
python3 -m pytest tests/ -q
```

50 tests, all hermetic: record parsing is checked against hand-built
wire bytes, and client/CLI tests run against a fake in-process DNS
server (a fake UDP socket + a real TCP listener on loopback), so the
suite never touches the internet.

## Scope note

DnsX only reads public DNS data and only tests zone transfer against
the target's own nameservers — the same information any resolver would
hand out. Only run it against domains you own or are authorized to
assess.

## License

MIT — see [LICENSE](LICENSE).
