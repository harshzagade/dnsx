import sys
import argparse
import ipaddress
import re
from dnsx import __version__
from dnsx.recon import Recon, RECORD_TYPES
from dnsx.report import render_text, render_json
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

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnsx",
        description="DnsX — stdlib-only DNS recon: enumerate records, detect wildcards, test zone transfer."
    )
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--server", default="8.8.8.8", help="DNS server to use (default: 8.8.8.8)")
    parser.add_argument("--resolver", default=None,
                        help="DNS resolver IP to query (overrides --server)")
    parser.add_argument("--port", type=int, default=53, help="DNS server port (default: 53)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Query timeout in seconds (default: 5.0)")
    parser.add_argument("--types", default="A,AAAA,NS,MX,TXT,SOA,CAA,DS",
                        help="Comma-separated record types (default: A,AAAA,NS,MX,TXT,SOA,CAA,DS)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--no-wildcard", action="store_true", help="Skip wildcard detection")
    parser.add_argument("--no-axfr", action="store_true", help="Skip zone transfer test")
    parser.add_argument("--no-cname-chain", action="store_true", help="Skip CNAME chain following")
    parser.add_argument("--no-mail-auth", action="store_true", help="Skip the SPF/DKIM/DMARC summary")
    parser.add_argument("--no-reverse-dns", action="store_true", help="Skip reverse DNS (PTR) lookups")
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

    wordlist = None
    if args.wordlist is not None:
        try:
            wordlist = _load_wordlist(args.wordlist)
        except ValueError as e:
            parser.error(str(e))

    recon = Recon(server=args.server, port=args.port, timeout=args.timeout)
    
    try:
        result = recon.enumerate(
            domain=args.domain,
            types=requested_types,
            do_wildcard=not args.no_wildcard,
            do_axfr=not args.no_axfr,
            do_cname_chain=not args.no_cname_chain,
            do_mail_auth=not args.no_mail_auth,
            do_reverse_dns=not args.no_reverse_dns,
            do_srv=not args.no_srv,
            do_dnssec=not args.no_dnssec,
            do_brute_force=args.brute or wordlist is not None,
            wordlist=wordlist
        )
        
        if args.no_wildcard:
            result.wildcard = None
        if args.no_axfr:
            result.zone_transfer = None

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
