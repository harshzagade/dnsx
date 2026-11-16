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

    if result.mail_auth is not None:
        auth = result.mail_auth
        lines.append("[Mail auth]")
        spf = auth.get("spf")
        if spf:
            spf_part = f"SPF: {spf['policy'] or 'no-all'}"
            if spf["includes"]:
                n = len(spf["includes"])
                spf_part += f" ({n} include{'s' if n != 1 else ''}: {', '.join(spf['includes'])})"
        else:
            spf_part = "SPF: none"
        dmarc = auth.get("dmarc")
        if dmarc and dmarc.get("policy"):
            dmarc_part = f"DMARC: p={dmarc['policy']}"
            if dmarc.get("subdomain_policy"):
                dmarc_part += f" (sp={dmarc['subdomain_policy']})"
        else:
            dmarc_part = "DMARC: none"
        selectors = auth.get("dkim", {}).get("selectors", [])
        dkim_part = f"DKIM: {', '.join(selectors)}" if selectors else "DKIM: none"
        lines.append(f"{spf_part} | {dmarc_part} | {dkim_part}")
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

    if result.reverse_dns and result.reverse_dns.get("lookups"):
        lines.append("[Reverse DNS]")
        for ip, ptr in result.reverse_dns["lookups"].items():
            lines.append(f"  {ip} -> {ptr if ptr else '(no PTR record)'}")
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

    if result.brute_force is not None:
        bf = result.brute_force
        lines.append("[Subdomains]")
        hits = bf.get("hits", [])
        filtered = bf.get("filtered", [])
        summary = f"Subdomains found: {len(hits)} ({bf.get('tried', 0)} labels tried"
        if filtered:
            summary += f", {len(filtered)} filtered as wildcard"
        if bf.get("errors"):
            summary += f", {bf['errors']} error{'s' if bf['errors'] != 1 else ''}"
        lines.append(summary + ")")
        for h in hits:
            lines.append(f"  {h['subdomain']} -> {', '.join(h['ips'])}")
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

