import sys
import argparse
import ipaddress
from dnsx import __version__
from dnsx.recon import Recon, RECORD_TYPES
from dnsx.report import render_text, render_json
from dnsx.dns import DnsError

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

    recon = Recon(server=args.server, port=args.port, timeout=args.timeout)
    
    try:
        result = recon.enumerate(
            domain=args.domain,
            types=requested_types,
            do_wildcard=not args.no_wildcard,
            do_axfr=not args.no_axfr
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
