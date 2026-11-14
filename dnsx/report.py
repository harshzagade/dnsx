import json
from dnsx.recon import ReconResult, format_record, TYPE_NAMES

def render_text(result: ReconResult) -> str:
    lines = [f"DnsX report for {result.domain}", ""]
    if result.resolver is not None:
        resolver_line = f"Resolver: {result.resolver}"
        if result.timeout is not None:
            resolver_line += f" (timeout {result.timeout}s)"
        lines.append(resolver_line)
        lines.append("")
    
    order = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "CAA", "DS"]
    for tname in order:
        recs = result.records.get(tname, [])
        if recs:
            lines.append(f"[{tname}]")
            for r in recs:
                fmt = format_record(r)
                lines.append(f"  {r.get('name', ''):<20}  {r.get('ttl', '?')}s  {fmt}")
            lines.append("")

    if result.cname_chain:
        chain = result.cname_chain
        lines.append("[CNAME chain]")
        path = [chain["hops"][0]["name"]] + [h["target"] for h in chain["hops"]]
        status = chain["status"]
        if status == "resolved":
            lines.append(f"{' -> '.join(path)} ({', '.join(chain['addresses'])})")
        elif status == "dead-end":
            lines.append(f"{' -> '.join(path)} (no A/AAAA records at {chain['final']})")
        elif status == "loop":
            lines.append(f"{' -> '.join(path)} (loop detected)")
        else:  # too-long
            lines.append(f"{' -> '.join(path)} (chain longer than 10 hops)")
        lines.append("")

    if result.wildcard:
        lines.append("[Wildcard]")
        if result.wildcard.get("detected"):
            ips = ", ".join(result.wildcard.get("ips", []))
            lines.append(f"Wildcard DNS: DETECTED (shared IPs: {ips})")
        else:
            msg = "Wildcard DNS: not detected"
            if "error" in result.wildcard:
                msg += f" (error: {result.wildcard['error']})"
            lines.append(msg)
        lines.append("")

    if result.zone_transfer:
        lines.append("[Zone transfer]")
        if result.zone_transfer.get("vulnerable"):
            ns = result.zone_transfer.get("nameserver")
            cnt = result.zone_transfer.get("records")
            lines.append(f"Zone transfer: VULNERABLE via {ns} ({cnt} records)")
        else:
            lines.append(f"Zone transfer: {result.zone_transfer.get('note', 'refused')}")
        lines.append("")

    if result.errors:
        lines.append("[Errors]")
        for tname, msg in result.errors.items():
            lines.append(f"  {tname}: {msg}")
        lines.append("")

    lines.append(f"Scan took {round(result.duration_seconds, 3)}s")
    return "\n".join(lines)

def render_json(result: ReconResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"

