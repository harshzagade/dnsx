import sys
import argparse
import ipaddress
import json
import re
from dnsx import __version__
from dnsx.recon import Recon, RECORD_TYPES
from dnsx.report import render_text, render_json, render_summary
from dnsx.dns import DnsError

_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")

def _load_wordlist(path: str) -> list[str]:
    """Read a brute-force wordlist: one label per line, `#` comments skipped."""
    try:
        with open(path, encoding="utf-8") as fh:
            labels = [ln.strip().lower() for ln in fh
                      if ln.strip() and not ln.strip().startswith("#")]
    except OSError as e:
        raise ValueError(f"Cannot read wordlist {path}: {e}")
    bad = [w for w in labels if not _LABEL_RE.fullmatch(w)]
    if bad:
        raise ValueError(f"Invalid wordlist labels: {', '.join(bad[:5])}")
    if not labels:
        raise ValueError(f"Wordlist {path} is empty")
    return labels

def _load_domain_file(path: str) -> list[str]:
    """Read a batch file: one domain per line, `#` comments skipped."""
    try:
        with open(path, encoding="utf-8") as fh:
            domains = [ln.strip() for ln in fh
                       if ln.strip() and not ln.strip().startswith("#")]
    except OSError as e:
        raise ValueError(f"Cannot read domain file {path}: {e}")
    if not domains:
        raise ValueError(f"Domain file {path} is empty")
    return domains


def _run_scan(recon, args, domain, requested_types, wordlist):
    """Run one enumeration, applying the --no-* skips.

    Returns the ReconResult; raises ValueError / DnsError for a domain
    that cannot be scanned at all (bad name, unreachable resolver).
    Per-record failures land in result.errors instead — they are findings,
    not scan failures.
    """
    result = recon.enumerate(
        domain=domain,
        types=requested_types,
        do_wildcard=not args.no_wildcard,
        do_axfr=not args.no_axfr,
        do_cname_chain=not args.no_cname_chain,
        do_mail_auth=not args.no_mail_auth,
        do_reverse_dns=not args.no_reverse_dns,
        do_ns_glue=not args.no_ns_glue,
        do_apex_www=not args.no_apex_www,
        do_srv=not args.no_srv,
        do_dnssec=not args.no_dnssec,
        do_brute_force=args.brute or wordlist is not None,
        wordlist=wordlist
    )
    if args.no_wildcard:
        result.wildcard = None
    if args.no_axfr:
        result.zone_transfer = None
    return result


def _batch(domains, recon, args, requested_types, wordlist) -> int:
    """Scan each domain in turn, one summary line per domain.

    A domain that cannot be scanned (bad name, resolver error) still
    gets its line — `domain: ERROR <message>` — and the run exits 1,
    so one bad line never aborts the rest of the batch. With --json
    each line is a single JSON object ({"domain", "error"} on failure).
    """
    failed = 0
    for domain in domains:
        try:
            result = _run_scan(recon, args, domain, requested_types, wordlist)
        except (ValueError, DnsError) as e:
            failed += 1
            if args.json:
                print(json.dumps({"domain": domain, "error": str(e)}))
            else:
                print(f"{domain}: ERROR {e}")
            continue
        if args.json:
            print(json.dumps(result.to_dict()))
        else:
            print(render_summary(result))
    return 1 if failed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnsx",
        description="DnsX — stdlib-only DNS recon: enumerate records, detect wildcards, test zone transfer."
    )
    parser.add_argument("domain", nargs="?", default=None, help="Domain to scan")
    parser.add_argument("--file", default=None, metavar="FILE",
                        help="Batch mode: scan one domain per line from FILE, "
                             "one summary line per domain (cannot be combined "
                             "with a positional domain)")
    parser.add_argument("--server", default="8.8.8.8", help="DNS server to use (default: 8.8.8.8)")
    parser.add_argument("--resolver", default=None,
                        help="DNS resolver IP to query (overrides --server)")
    parser.add_argument("--port", type=int, default=53, help="DNS server port (default: 53)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Query timeout in seconds (default: 5.0)")
    parser.add_argument("--tcp", action="store_true", help="Force all queries over TCP (for resolvers that block UDP)")
    parser.add_argument("--types", default="A,AAAA,NS,MX,TXT,SOA,CAA,DS",
                        help="Comma-separated record types (default: A,AAAA,NS,MX,TXT,SOA,CAA,DS)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--no-wildcard", action="store_true", help="Skip wildcard detection")
    parser.add_argument("--no-axfr", action="store_true", help="Skip zone transfer test")
    parser.add_argument("--no-cname-chain", action="store_true", help="Skip CNAME chain following")
    parser.add_argument("--no-mail-auth", action="store_true", help="Skip the SPF/DKIM/DMARC summary")
    parser.add_argument("--no-reverse-dns", action="store_true", help="Skip reverse DNS (PTR) lookups")
    parser.add_argument("--no-ns-glue", action="store_true", help="Skip the NS glue check")
    parser.add_argument("--no-apex-www", action="store_true", help="Skip the apex vs www comparison")
    parser.add_argument("--no-srv", action="store_true", help="Skip SRV record enumeration")
    parser.add_argument("--no-dnssec", action="store_true", help="Skip the DNSSEC signed-answer check")
    parser.add_argument("--brute", action="store_true", help="Brute-force common subdomains from the built-in wordlist")
    parser.add_argument("--wordlist", default=None, metavar="FILE",
                        help="Wordlist file for --brute (one label per line; implies --brute)")
    parser.add_argument("--version", action="version", version=f"dnsx {__version__}")

    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    if args.resolver is not None:
        try:
            ipaddress.ip_address(args.resolver)
        except ValueError:
            parser.error(f"Invalid resolver IP: {args.resolver}")
        args.server = args.resolver

    requested_types = [t.strip().upper() for t in args.types.split(",")]
    for t in requested_types:
        if t not in RECORD_TYPES:
            parser.error(f"Invalid record type: {t}")

    if args.file is not None and args.domain is not None:
        parser.error("--file cannot be combined with a positional domain")
    if args.file is None and args.domain is None:
        parser.error("a domain or --file is required")

    wordlist = None
    if args.wordlist is not None:
        try:
            wordlist = _load_wordlist(args.wordlist)
        except ValueError as e:
            parser.error(str(e))

    domains = None
    if args.file is not None:
        try:
            domains = _load_domain_file(args.file)
        except ValueError as e:
            parser.error(str(e))

    recon = Recon(server=args.server, port=args.port, timeout=args.timeout, use_tcp=args.tcp)

    if domains is not None:
        return _batch(domains, recon, args, requested_types, wordlist)

    try:
        result = _run_scan(recon, args, args.domain, requested_types, wordlist)

        if args.json:
            print(render_json(result), end="")
        else:
            print(render_text(result))

    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except DnsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
