import time
import secrets
import ipaddress
from dataclasses import dataclass, field
from dnsx.dns import (
    DnsClient, DnsError,
    TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_AAAA,
    TYPE_CAA, TYPE_DS, TYPE_PTR
)

RECORD_TYPES = {
    "A": TYPE_A,
    "AAAA": TYPE_AAAA,
    "NS": TYPE_NS,
    "MX": TYPE_MX,
    "TXT": TYPE_TXT,
    "SOA": TYPE_SOA,
    "CNAME": TYPE_CNAME,
    "CAA": TYPE_CAA,
    "DS": TYPE_DS
}

TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}

@dataclass
class ReconResult:
    domain: str
    records: dict[str, list] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    wildcard: dict | None = None
    zone_transfer: dict | None = None
    duration_seconds: float = 0.0
    resolver: str | None = None
    timeout: float | None = None
    cname_chain: dict | None = None
    mail_auth: dict | None = None
    tcp_fallbacks: int = 0
    reverse_dns: dict | None = None

    def to_dict(self) -> dict:
        def _safe(records):
            out = []
            for r in records:
                clean = dict(r)
                if isinstance(clean.get("data"), bytes):
                    clean["data"] = repr(clean["data"])
                if isinstance(clean.get("raw"), bytes):
                    clean["raw"] = repr(clean["raw"])
                out.append(clean)
            return out

        return {
            "domain": self.domain,
            "records": {k: _safe(v) for k, v in self.records.items()},
            "errors": self.errors,
            "nameservers": self.nameservers,
            "wildcard": self.wildcard,
            "zone_transfer": self.zone_transfer,
            "duration_seconds": round(self.duration_seconds, 3),
            "resolver": self.resolver,
            "timeout": self.timeout,
            "cname_chain": self.cname_chain,
            "mail_auth": self.mail_auth,
            "tcp_fallbacks": self.tcp_fallbacks,
            "reverse_dns": self.reverse_dns
        }

def format_record(record: dict) -> str:
    rtype = record.get("type")
    data = record.get("data")
    if "raw" in record:
        return repr(record["raw"])
    if rtype in (TYPE_A, TYPE_AAAA, TYPE_NS, TYPE_CNAME, TYPE_PTR):
        return str(data)
    if rtype == TYPE_MX:
        if isinstance(data, dict):
            return f"{data.get('preference')} {data.get('exchange') or '.'}"
        # tolerate tuple form (preference, exchange) from hand-built records
        return f"{data[0]} {data[1] or '.'}"
    if rtype == TYPE_TXT:
        return " ".join(data)
    if rtype == TYPE_SOA:
        if isinstance(data, dict):
            return (f"{data.get('mname')} {data.get('rname')} "
                    f"serial={data.get('serial')} refresh={data.get('refresh')} "
                    f"retry={data.get('retry')} expire={data.get('expire')} "
                    f"minimum={data.get('minimum')}")
        # tolerate tuple form (mname, rname, serial, refresh, retry, expire, minimum)
        return (f"{data[0]} {data[1]} "
                f"serial={data[2]} refresh={data[3]} "
                f"retry={data[4]} expire={data[5]} "
                f"minimum={data[6]}")
    if rtype == TYPE_CAA:
        # Zone-file form: 0 issue "letsencrypt.org"
        if isinstance(data, dict):
            return (f"{data.get('flags')} {data.get('tag')} "
                    f"\"{data.get('value')}\"")
        return str(data)
    if rtype == TYPE_DS:
        # Zone-file form: key-tag algorithm digest-type DIGEST (upper hex)
        if isinstance(data, dict):
            return (f"{data.get('key_tag')} {data.get('algorithm')} "
                    f"{data.get('digest_type')} "
                    f"{str(data.get('digest')).upper()}")
        return str(data)
    if isinstance(data, bytes):
        return repr(data)
    return str(data)

def parse_spf_record(text: str) -> dict | None:
    """Parse a v=spf1 TXT record: the `all` qualifier and include: list.

    Returns None when the text is not an SPF record. A bare `all` (no
    qualifier) is normalized to "+all".
    """
    if not text.strip().lower().startswith("v=spf1"):
        return None
    policy = None
    includes = []
    for tok in text.split()[1:]:
        low = tok.lower()
        if low.startswith("include:"):
            includes.append(tok.split(":", 1)[1])
        elif low in ("all", "+all", "-all", "~all", "?all"):
            policy = "+all" if low == "all" else low
    return {"record": text, "policy": policy, "includes": includes}


def parse_dmarc_record(text: str) -> dict | None:
    """Parse a v=DMARC1 TXT record: the p= and sp= policies."""
    if not text.strip().lower().startswith("v=dmarc1"):
        return None
    tags = {}
    for part in text.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return {"record": text, "policy": tags.get("p"),
            "subdomain_policy": tags.get("sp")}


def _txt_strings(record: dict) -> str:
    """Join a TXT record's character-strings (they concatenate directly)."""
    data = record.get("data")
    if isinstance(data, list):
        return "".join(data)
    return str(data or "")


class Recon:
    def __init__(self, client=None, server="8.8.8.8", port=53, timeout=5.0):
        self.client = client or DnsClient(server=server, port=port, timeout=timeout)

    def enumerate(self, domain: str, types=("A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA", "DS"),
                  do_wildcard: bool = True, do_axfr: bool = True,
                  do_cname_chain: bool = True, do_mail_auth: bool = True,
                  do_reverse_dns: bool = True) -> ReconResult:
        start_time = time.perf_counter()
        domain = domain.strip(".").lower()
        if not domain or " " in domain:
            raise ValueError("Invalid domain name")

        result = ReconResult(domain=domain)
        # Record which resolver answered and with what timeout, so the
        # report (text and JSON) shows where the answers came from.
        result.resolver = getattr(self.client, "server", None)
        result.timeout = getattr(self.client, "timeout", None)
        last_resp = None

        for tname in types:
            if tname not in RECORD_TYPES:
                continue
            try:
                resp = self.client.query(domain, RECORD_TYPES[tname])
                result.records[tname] = resp.get("answers", [])
                last_resp = resp
            except DnsError as e:
                result.errors[tname] = str(e)
                result.records[tname] = []

        self._get_nameservers(domain, result, last_resp)

        if do_cname_chain:
            self._follow_cname_chain(domain, result)
        if do_mail_auth:
            self._check_mail_auth(domain, result)
        if do_reverse_dns:
            self._check_reverse_dns(domain, result)
        if do_wildcard:
            self._check_wildcard(domain, result)
        if do_axfr:
            self._check_zone_transfer(domain, result)

        result.duration_seconds = time.perf_counter() - start_time
        result.tcp_fallbacks = getattr(self.client, "tcp_fallbacks", 0)
        return result

    # A chain longer than this is treated as misconfigured rather than
    # followed forever (a cycle is caught earlier by the visited set).
    MAX_CNAME_HOPS = 10

    def _follow_cname_chain(self, domain, result):
        """Follow a CNAME chain from `domain` to its final A/AAAA answer.

        Sets result.cname_chain to {"hops", "final", "addresses", "status"}
        when the domain returns a CNAME; leaves it None when there is no
        CNAME to follow, so reports stay clean for plain A-record domains.
        Status is "resolved" (final name has A/AAAA), "dead-end" (final
        name answers nothing), "loop" (a target repeats) or "too-long".
        """
        try:
            resp = self.client.query(domain, TYPE_CNAME)
            first = [r for r in resp.get("answers", []) if r.get("type") == TYPE_CNAME]
        except DnsError:
            return
        if not first:
            return

        hops = []
        visited = {domain}
        current = domain
        target = str(first[0]["data"]).rstrip(".")
        while True:
            hops.append({"name": current, "target": target})
            if target in visited:
                result.cname_chain = {"hops": hops, "final": target,
                                      "addresses": [], "status": "loop"}
                return
            visited.add(target)
            if len(hops) >= self.MAX_CNAME_HOPS:
                result.cname_chain = {"hops": hops, "final": target,
                                      "addresses": [], "status": "too-long"}
                return
            current = target
            try:
                resp = self.client.query(current, TYPE_CNAME)
                nxt = [r for r in resp.get("answers", []) if r.get("type") == TYPE_CNAME]
            except DnsError:
                nxt = []
            if nxt:
                target = str(nxt[0]["data"]).rstrip(".")
                continue
            addresses = []
            for qtype in (TYPE_A, TYPE_AAAA):
                try:
                    resp = self.client.query(current, qtype)
                    addresses += [r["data"] for r in resp.get("answers", [])
                                  if r.get("type") == qtype]
                except DnsError:
                    continue
            result.cname_chain = {
                "hops": hops, "final": current, "addresses": addresses,
                "status": "resolved" if addresses else "dead-end",
            }
            return

    # Well-known DKIM selector names probed for a published key. There is
    # no way to enumerate selectors from DNS itself, so a fixed list of the
    # common ones is the honest approach (documented in the README).
    DKIM_SELECTORS = ("default", "google", "selector1", "selector2",
                      "mail", "dkim", "k1", "s1")

    def _check_mail_auth(self, domain, result):
        """Summarize the domain's mail authentication posture.

        SPF comes from the already-fetched TXT records; DMARC from
        _dmarc.<domain>; DKIM from probing the well-known selectors above
        for a v=DKIM1 key. Sets result.mail_auth to {"spf", "dmarc",
        "dkim"} with None / empty values where nothing was published.
        """
        spf = None
        for rec in result.records.get("TXT", []):
            spf = parse_spf_record(_txt_strings(rec))
            if spf:
                break

        dmarc = None
        try:
            resp = self.client.query(f"_dmarc.{domain}", TYPE_TXT)
            for rec in resp.get("answers", []):
                dmarc = parse_dmarc_record(_txt_strings(rec))
                if dmarc:
                    break
        except DnsError:
            pass

        selectors = []
        for sel in self.DKIM_SELECTORS:
            try:
                resp = self.client.query(f"{sel}._domainkey.{domain}", TYPE_TXT)
            except DnsError:
                continue
            for rec in resp.get("answers", []):
                if _txt_strings(rec).strip().lower().startswith("v=dkim1"):
                    selectors.append(sel)
                    break

        result.mail_auth = {"spf": spf, "dmarc": dmarc,
                            "dkim": {"selectors": selectors}}

    @staticmethod
    def _ptr_name(ip: str) -> str | None:
        """Reverse-map an IP to its in-addr.arpa / ip6.arpa query name.

        Returns None for strings that are not valid IPs (hand-built
        records can carry anything, and those are skipped, not crashed on).
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv4Address):
            return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        nibbles = addr.exploded.replace(":", "")[::-1]
        return ".".join(nibbles) + ".ip6.arpa"

    def _check_reverse_dns(self, domain, result):
        """PTR lookup for every IP discovered during enumeration.

        Sets result.reverse_dns to {"lookups": {ip: ptr-or-None}} using the
        A/AAAA records already fetched, deduplicated in first-seen order.
        An IP with no PTR record maps to None — that is normal, not an
        error, so a failed lookup never aborts the rest of the scan.
        """
        ips = []
        for tname in ("A", "AAAA"):
            for rec in result.records.get(tname, []):
                data = rec.get("data")
                if isinstance(data, str) and data not in ips:
                    ips.append(data)
        lookups = {}
        for ip in ips:
            arpa = self._ptr_name(ip)
            ptr = None
            if arpa is not None:
                try:
                    resp = self.client.query(arpa, TYPE_PTR)
                    answers = [r for r in resp.get("answers", [])
                               if r.get("type") == TYPE_PTR]
                    if answers:
                        ptr = str(answers[0]["data"])
                except DnsError:
                    pass
            lookups[ip] = ptr
        result.reverse_dns = {"lookups": lookups}

    def _get_nameservers(self, domain, result, last_resp):
        ns_list = []
        if "NS" in result.records and result.records["NS"]:
            ns_list = [r["data"] for r in result.records["NS"]]
        
        if not ns_list:
            try:
                resp = self.client.query(domain, TYPE_NS)
                ns_list = [r["data"] for r in resp.get("answers", [])]
                if not ns_list:
                    ns_list = [r["data"] for r in resp.get("authority", []) if r["type"] == TYPE_NS]
            except DnsError:
                pass

        if not ns_list and last_resp:
            ns_list = [r["data"] for r in last_resp.get("authority", []) if r["type"] == TYPE_NS]
        
        result.nameservers = sorted(list(set(ns_list)))

    def _check_wildcard(self, domain, result):
        labels = [f"dnsx{secrets.token_hex(5)}" for _ in range(2)]
        ips = []
        try:
            for label in labels:
                try:
                    resp = self.client.query(f"{label}.{domain}", TYPE_A)
                except DnsError as e:
                    # NXDOMAIN on a random name is the expected "no wildcard"
                    # signal, not an error: that probe simply resolved to nothing.
                    if "NXDOMAIN" in str(e) or "Non-Existent Domain" in str(e):
                        ips.append(set())
                        continue
                    raise
                ips.append({r["data"] for r in resp.get("answers", []) if r["type"] == TYPE_A})

            shared = sorted(list(ips[0].intersection(ips[1])))
            detected = len(shared) > 0
            result.wildcard = {"detected": detected, "probes": labels, "ips": shared}
        except DnsError as e:
            result.wildcard = {"detected": False, "probes": labels, "ips": [], "error": str(e)}

    def _check_zone_transfer(self, domain, result):
        for ns in result.nameservers[:3]:
            try:
                records = self.client.axfr(domain, ns)
                if records:
                    sample = []
                    for r in records[:5]:
                        clean_r = r.copy()
                        if isinstance(clean_r.get("data"), bytes):
                            clean_r["data"] = repr(clean_r["data"])
                        sample.append(clean_r)
                    result.zone_transfer = {
                        "vulnerable": True, 
                        "nameserver": ns, 
                        "records": len(records), 
                        "sample": sample
                    }
                    return
            except DnsError:
                continue
        
        result.zone_transfer = {
            "vulnerable": False, 
            "nameserver": None, 
            "records": 0, 
            "sample": [], 
            "note": "zone transfer refused by all nameservers"
        }

