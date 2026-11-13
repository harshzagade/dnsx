import time
import secrets
from dataclasses import dataclass, field
from dnsx.dns import (
    DnsClient, DnsError, 
    TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_AAAA
)

RECORD_TYPES = {
    "A": TYPE_A,
    "AAAA": TYPE_AAAA,
    "NS": TYPE_NS,
    "MX": TYPE_MX,
    "TXT": TYPE_TXT,
    "SOA": TYPE_SOA,
    "CNAME": TYPE_CNAME
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
            "duration_seconds": round(self.duration_seconds, 3)
        }

def format_record(record: dict) -> str:
    rtype = record.get("type")
    data = record.get("data")
    if "raw" in record:
        return repr(record["raw"])
    if rtype in (TYPE_A, TYPE_AAAA, TYPE_NS, TYPE_CNAME):
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
    if isinstance(data, bytes):
        return repr(data)
    return str(data)

class Recon:
    def __init__(self, client=None, server="8.8.8.8", port=53, timeout=5.0):
        self.client = client or DnsClient(server=server, port=port, timeout=timeout)

    def enumerate(self, domain: str, types=("A", "AAAA", "NS", "MX", "TXT", "SOA"), 
                  do_wildcard: bool = True, do_axfr: bool = True) -> ReconResult:
        start_time = time.perf_counter()
        domain = domain.strip(".").lower()
        if not domain or " " in domain:
            raise ValueError("Invalid domain name")

        result = ReconResult(domain=domain)
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
        
        if do_wildcard:
            self._check_wildcard(domain, result)
        if do_axfr:
            self._check_zone_transfer(domain, result)

        result.duration_seconds = time.perf_counter() - start_time
        return result

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

