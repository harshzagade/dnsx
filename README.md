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

# Brute-force common subdomains (wildcard IPs are filtered from hits)
python3 -m dnsx example.com --brute

# Same, with your own wordlist (one label per line; implies --brute)
python3 -m dnsx example.com --wordlist subdomains.txt

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
| `--types` | `A,AAAA,NS,MX,TXT,SOA,CAA,DS` | Comma-separated record types (`A,AAAA,NS,MX,TXT,SOA,CNAME,CAA,DS,RRSIG`) |
| `--json` | off | Machine-readable JSON output |
| `--no-wildcard` | off | Skip wildcard detection |
| `--no-axfr` | off | Skip the zone-transfer test |
| `--no-cname-chain` | off | Skip CNAME chain following |
| `--no-mail-auth` | off | Skip the SPF/DKIM/DMARC summary |
| `--no-reverse-dns` | off | Skip reverse DNS (PTR) lookups |
| `--no-ns-glue` | off | Skip the NS glue check |
| `--no-srv` | off | Skip SRV record enumeration |
| `--no-dnssec` | off | Skip the DNSSEC signed-answer check |
| `--brute` | off | Brute-force common subdomains from the built-in wordlist |
| `--wordlist` | — | Wordlist file for `--brute` (one label per line; implies `--brute`) |
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
  ns1.example.com: refused
  ns2.example.com: refused
Zone transfer: zone transfer refused by all nameservers

Scan took 22.778s
```

A vulnerable zone transfer looks like this instead — every nameserver is
reported separately, so a zone that leaks from one NS while the others
refuse is visible at a glance:

```text
[Zone transfer]
  ns1.example.com: ALLOWED (41 records)
  ns2.example.com: refused
Zone transfer: VULNERABLE via ns1.example.com (41 records)
```

(`--json` adds a `sample` field with the first 5 transferred records, and a
`servers` list with one `{nameserver, status, records, detail}` entry per
nameserver — `status` is `allowed`, `refused`, `timeout`, `unresolvable`,
or `error`.)

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
Publishing two or more `v=spf1` records is invalid per RFC 7208 (a
domain must publish at most one), so the summary warns about it and
keeps the first record; `--json` carries the count as
`mail_auth.spf.count`.
Selectors cannot be enumerated from DNS, so a domain using an unusual
selector name simply shows fewer (or no) DKIM selectors — the check
reports what it finds, never guesses. `--json` carries the same data
as a `mail_auth` object.

A CNAME'd name gets its chain followed to the final address:

```text
[CNAME chain]
www.example.com -> cdn.example.net -> edge.example.net (93.184.216.34)
```

Every IP found in the A/AAAA records gets a reverse lookup, so the
report shows which names the addresses point back to:

```text
[Reverse DNS]
  93.184.216.34 -> example.com
  2606:2800:220:1:248:1893:25c8:1946 -> (no PTR record)
```

IPv4 addresses query `<reversed>.in-addr.arpa`, IPv6 the nibble-reversed
`ip6.arpa` name; an address with no PTR record is shown as such, never
as an error. `--json` carries the same data as a `reverse_dns` object
mapping each IP to its PTR name (or `null`).

Every nameserver from the NS records is checked for glue — an A/AAAA
address it resolves to — so a delegation pointing at a dead nameserver
shows up in the report:

```text
[NS glue]
  ns1.example.com. -> 192.0.2.53, 2001:db8::53
  ns2.example.com. -> (no A/AAAA records — missing glue)
  [!] WARNING: 1 nameserver without glue: ns2.example.com.
```

A nameserver that answers NXDOMAIN (or nothing) for both families is
reported as missing glue, never as a scan error, and a nameserver that
fails with any other DNS error is reported with the error instead.
`--json` carries the same data as an `ns_glue` object with `servers`
and `missing`.

Common service SRV records are enumerated too, so exposed SIP, XMPP,
LDAP, and Kerberos endpoints show up in the report:

```text
[SRV]
  _sip._tcp.example.com  0 5 5060 sip.example.com
  _ldap._tcp.example.com  0 100 389 ldap.example.com
```

Only the four well-known service names (`_sip._tcp`,
`_xmpp-client._tcp`, `_ldap._tcp`, `_kerberos._tcp`) are probed — SRV
names cannot be enumerated from DNS, so a domain publishing a service
under an unusual name simply shows fewer (or no) entries. A target of
`.` (the service is explicitly not offered, RFC 2782) is reported as
such, not dropped. `--json` carries the same data as a `srv` object
mapping each service to its list of `priority` / `weight` / `port` /
`target` records.

The DNSSEC signed-answer check re-queries A with the EDNS0 DO bit set
and reports whether the answer carries RRSIG records, and whether the
resolver set the AD (authenticated data) bit:

```text
[DNSSEC]
DNSSEC: signed (RRSIG for A; AD bit set) — DS record present
```

A zone counts as signed only when an RRSIG record actually arrives —
the AD bit alone is not proof, since a resolver may set it from its
cache. A DS record from the enumeration is shown as a signed-delegation
hint, not a verdict. The check reads signatures; it does not validate
them (full chain validation needs the root trust anchor and is out of
scope). `--json` carries the same data as a `dnssec` object with
`signed`, `ad`, `rrsig_types`, and `has_ds`.

A chain that ends at a name with no A/AAAA records is reported as a
dead end, and a cycle (or a chain longer than 10 hops) is flagged
instead of followed forever. `--json` carries the same data as a
`cname_chain` object with `hops`, `final`, `addresses`, and `status`.

`--brute` probes 51 common subdomain labels (`www`, `mail`, `api`,
`admin`, …) with A queries and lists the ones that resolve:

```text
[Subdomains]
Subdomains found: 3 (51 labels tried, 1 filtered as wildcard)
  www.example.com -> 93.184.216.34
  api.example.com -> 93.184.216.99
  ns1.example.com -> 127.0.0.1
```

On a wildcard domain every label resolves, so hits that answer only
with the wildcard IPs are filtered out of the list (counted, not
hidden) — only addresses outside the wildcard set prove a real
subdomain. The filter needs the wildcard check, so `--brute` pairs
with the default wildcard detection; with `--no-wildcard` nothing is
filtered. `--json` carries the same data as a `brute_force` object
with `tried`, `hits`, `filtered`, `errors`, and `wildcard_ips`.

`--json` output also carries the `resolver` IP and `timeout` used for the
scan, and the text report prints them under the title, so a saved report
always shows where its answers came from.

## How it works

- **Wire protocol** (`dnsx/dns.py`): builds and parses DNS messages by
  hand — label encoding, compression pointers, and record decoding for
  A, AAAA, NS, CNAME, MX, TXT, SOA, CAA, DS, SRV, and RRSIG. EDNS0 OPT
  records carry the DO bit for DNSSEC queries. UDP with automatic TCP fallback
  when the TC (truncated) bit is set — the bit is read from the reply
  header before the body is parsed, so a reply cut short mid-record still
  triggers the retry instead of surfacing a parse error; AXFR runs over TCP.
  The number of TCP retries is reported as `tcp_fallbacks` in `--json`.
- **Wildcard detection** (`dnsx/recon.py`): queries two random
  `dnsx<hex>.example.com` names. A wildcard is reported only when both
  resolve *and* share at least one IP, so a single anycast fluke can't
  flip the result.
- **Zone-transfer test** (`dnsx/recon.py`): tries AXFR against every
  nameserver (max 3) and reports each result separately — allowed,
  refused, timeout, unresolvable, or error — in the text report and as
  a `servers` list in `--json`, instead of one overall verdict. A
  stalled AXFR now raises "zone transfer timed out" (`dnsx/dns.py`)
  instead of being lumped in with refusals.
- **CNAME chain following** (`dnsx/recon.py`): when the target returns a
  CNAME, each hop is followed (max 10, cycles detected) until the final
  A/AAAA answer, and every hop is shown in the report.
- **Mail-auth summary** (`dnsx/recon.py`): parses SPF from TXT, DMARC
  from `_dmarc`, and probes well-known DKIM selectors for a published
  key, printed as one summary line.
- **Reverse DNS** (`dnsx/recon.py`): PTR lookup for every IP in the
  enumerated A/AAAA records (`in-addr.arpa` for IPv4, nibble-reversed
  `ip6.arpa` for IPv6), shown as an ip -> name mapping with missing
  PTR records marked, not errored on.
- **SRV enumeration** (`dnsx/recon.py`): queries `_sip._tcp`,
  `_xmpp-client._tcp`, `_ldap._tcp`, and `_kerberos._tcp` for SRV
  records (priority/weight/port/target, RFC 2782) and lists the
  services a domain publishes; a failed query for one service never
  aborts the others.
- **DNSSEC signed-answer check** (`dnsx/recon.py`): re-queries A with
  the EDNS0 DO bit set and reports whether RRSIG records arrived and
  whether the resolver set the AD bit; a DS record from the enumeration
  is shown as a signed-delegation hint. Signatures are read, not
  validated.
- **Subdomain brute-force** (`dnsx/recon.py`): `--brute` probes the
  built-in 51-label wordlist (or `--wordlist FILE`) with A queries;
  hits resolving only to the wildcard IPs are filtered out, so a
  wildcard domain reports no false subdomains.
- **Output** (`dnsx/report.py`): plain-text report for humans, `--json`
  for pipelines.

## Tests

```bash
python3 -m pytest tests/ -q
```

79 tests, all hermetic: record parsing is checked against hand-built
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
