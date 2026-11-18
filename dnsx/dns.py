import socket
import struct
import random
import ipaddress
import time
from typing import Any, Dict, List, Tuple, Optional

# Constants
A, NS, CNAME, SOA, MX, TXT, AAAA, AXFR, ANY = 1, 2, 5, 6, 15, 16, 28, 252, 255
PTR = 12
CAA, DS = 257, 43
SRV = 33
IN = 1

# TYPE_* aliases (public surface used by dnsx.recon)
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_AAAA, TYPE_AXFR, TYPE_ANY = (
    A, NS, CNAME, SOA, MX, TXT, AAAA, AXFR, ANY,
)
TYPE_PTR = PTR
TYPE_CAA, TYPE_DS = CAA, DS
TYPE_SRV = SRV

RCODE_MAP = {
    1: "Format Error",
    2: "Server Failure",
    3: "Non-Existent Domain (NXDOMAIN)",
    4: "Not Implemented",
    5: "Query Refused"
}

class DnsError(Exception):
    """Base class for DNS related errors."""
    pass

class DnsTimeout(DnsError):
    """Raised when a DNS query times out."""
    pass

def encode_name(name: str) -> bytes:
    """Encodes a domain name into DNS label format."""
    if not name or name == ".":
        return b"\x00"
    if len(name) > 253:
        raise ValueError("Name too long")
    
    parts = name.rstrip(".").split(".")
    encoded = b""
    for part in parts:
        if not part:
            raise ValueError("Empty label")
        if len(part) > 63:
            raise ValueError("Label too long")
        encoded += struct.pack("!B", len(part)) + part.encode("ascii")
    return encoded + b"\x00"

def decode_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decodes a DNS name, handling compression pointers."""
    labels = []
    jumped = False
    new_offset = -1
    hops = 0
    ptr = offset

    def _byte(at: int) -> int:
        if at < 0 or at >= len(message):
            raise DnsError("Truncated DNS name")
        return message[at]

    while True:
        if hops > 10:
            raise DnsError("Too many compression pointers")

        length = _byte(ptr)
        if length & 0xC0 == 0xC0:
            if not jumped:
                new_offset = ptr + 2
            if ptr + 1 >= len(message):
                raise DnsError("Truncated DNS name")
            pointer = struct.unpack("!H", message[ptr:ptr+2])[0] & 0x3FFF
            ptr = pointer
            jumped = True
            hops += 1
        elif length == 0:
            if not jumped:
                new_offset = ptr + 1
            break
        else:
            if ptr + 1 + length > len(message):
                raise DnsError("Truncated DNS name")
            ptr += 1
            labels.append(message[ptr:ptr+length].decode("utf-8", "replace"))
            ptr += length

    return ".".join(labels), new_offset

def build_query(name: str, qtype: int, qid: Optional[int] = None) -> bytes:
    """Constructs a DNS query message."""
    if qid is None:
        qid = random.getrandbits(16)
    
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, IN)
    return header + question

def parse_record(message: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    """Parses a single DNS resource record."""
    name, offset = decode_name(message, offset)
    if offset + 10 > len(message):
        raise DnsError("Truncated DNS record")
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset:offset+10])
    rdata_start = offset + 10
    if rdata_start + rdlength > len(message):
        raise DnsError("Truncated DNS record data")
    rdata_raw = message[rdata_start:rdata_start+rdlength]
    
    res = {"name": name, "type": rtype, "ttl": ttl}
    
    try:
        if rtype == A:
            res["data"] = str(ipaddress.IPv4Address(rdata_raw))
        elif rtype == AAAA:
            res["data"] = ipaddress.IPv6Address(rdata_raw).compressed
        elif rtype in (NS, CNAME, PTR):
            res["data"], _ = decode_name(message, rdata_start)
        elif rtype == MX:
            pref = struct.unpack("!H", rdata_raw[:2])[0]
            exch, _ = decode_name(message, rdata_start + 2)
            res["data"] = {"preference": pref, "exchange": exch}
        elif rtype == TXT:
            texts = []
            pos = 0
            while pos < rdlength:
                l = rdata_raw[pos]
                texts.append(rdata_raw[pos+1:pos+1+l].decode("utf-8", "replace"))
                pos += 1 + l
            res["data"] = texts
        elif rtype == SOA:
            mname, next_off = decode_name(message, rdata_start)
            rname, next_off = decode_name(message, next_off)
            ser, ref, ret, exp, min_ttl = struct.unpack("!IIIII", message[next_off:next_off+20])
            res["data"] = {
                "mname": mname, "rname": rname, "serial": ser,
                "refresh": ref, "retry": ret, "expire": exp, "minimum": min_ttl
            }
        elif rtype == CAA:
            # RFC 8659: flags (1B), tag length (1B), tag, value.
            if len(rdata_raw) < 2:
                raise ValueError("short CAA record")
            flags = rdata_raw[0]
            tag_len = rdata_raw[1]
            if 2 + tag_len > len(rdata_raw):
                raise ValueError("CAA tag overruns record")
            tag = rdata_raw[2:2 + tag_len].decode("ascii")
            value = rdata_raw[2 + tag_len:].decode("utf-8", "replace")
            res["data"] = {"flags": flags, "tag": tag, "value": value}
        elif rtype == DS:
            # RFC 4034: key tag (2B), algorithm (1B), digest type (1B),
            # digest (rest, kept as lowercase hex).
            if len(rdata_raw) < 4:
                raise ValueError("short DS record")
            key_tag, alg, dtype = struct.unpack("!HBB", rdata_raw[:4])
            res["data"] = {
                "key_tag": key_tag,
                "algorithm": alg,
                "digest_type": dtype,
                "digest": rdata_raw[4:].hex(),
            }
        elif rtype == SRV:
            # RFC 2782: priority (2B), weight (2B), port (2B), target name.
            if len(rdata_raw) < 6:
                raise ValueError("short SRV record")
            prio, weight, port = struct.unpack("!HHH", rdata_raw[:6])
            target, _ = decode_name(message, rdata_start + 6)
            res["data"] = {
                "priority": prio,
                "weight": weight,
                "port": port,
                "target": target,
            }
        else:
            res["raw"] = rdata_raw
    except Exception:
        res["raw"] = rdata_raw

    return res, rdata_start + rdlength

def parse_response(data: bytes, qid: int) -> Dict[str, Any]:
    """Parses a DNS response message."""
    if len(data) < 12:
        raise DnsError("Response too short")
    
    header = struct.unpack("!HHHHHH", data[:12])
    if header[0] != qid:
        raise DnsError("Transaction ID mismatch")
    
    flags = header[1]
    rcode = flags & 0x000F
    if rcode != 0:
        err = RCODE_MAP.get(rcode, f"Unknown Error ({rcode})")
        raise DnsError(f"DNS Server returned {err}")
    
    qdcount, ancount, nscount, arcount = header[2:]
    offset = 12
    
    # Skip question section
    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4
        
    sections = [("answers", ancount), ("authority", nscount), ("additional", arcount)]
    result = {"rcode": rcode, "flags": flags, "answers": [], "authority": [], "additional": []}
    
    for key, count in sections:
        for _ in range(count):
            rec, offset = parse_record(data, offset)
            result[key].append(rec)
            
    return result

class DnsClient:
    def __init__(self, server: str = "8.8.8.8", port: int = 53, timeout: float = 5.0, retries: int = 1):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.retries = retries
        # Queries retried over TCP after a truncated (TC-bit) UDP reply.
        self.tcp_fallbacks = 0

    def query(self, name: str, qtype: int) -> Dict[str, Any]:
        """Performs a DNS query over UDP, falling back to TCP if truncated.

        The TC bit is read from the 12-byte header *before* the body is
        parsed: a truncated reply is often cut short mid-record, so parsing
        it first would raise before the retry ever runs. Only a TC flag on
        a response carrying our transaction ID triggers the retry.
        """
        qid = random.getrandbits(16)
        packet = build_query(name, qtype, qid)

        for i in range(self.retries + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                try:
                    s.sendto(packet, (self.server, self.port))
                    data, _ = s.recvfrom(4096)
                    if len(data) >= 12:
                        resp_qid, flags = struct.unpack("!HH", data[0:4])
                        if resp_qid == qid and flags & 0x0200:  # TC bit
                            self.tcp_fallbacks += 1
                            return self.query_tcp(name, qtype)
                    return parse_response(data, qid)
                except socket.timeout:
                    if i == self.retries:
                        raise DnsTimeout(f"Query timed out after {self.retries + 1} attempts")
                    continue
                except OSError as e:
                    raise DnsError(f"Network error: {e}") from e

    @staticmethod
    def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
        """Read exactly nbytes from a TCP socket (b'' on early close)."""
        data = b""
        while len(data) < nbytes:
            chunk = sock.recv(nbytes - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def query_tcp(self, name: str, qtype: int) -> Dict[str, Any]:
        """Performs a DNS query over TCP."""
        qid = random.getrandbits(16)
        packet = build_query(name, qtype, qid)
        tcp_packet = struct.pack("!H", len(packet)) + packet

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            try:
                s.connect((self.server, self.port))
                s.sendall(tcp_packet)
            except OSError as e:
                raise DnsError(f"Network error: {e}") from e

            len_bytes = self._recv_exact(s, 2)
            if len(len_bytes) < 2:
                raise DnsError("Empty TCP response")
            resp_len = struct.unpack("!H", len_bytes)[0]

            data = self._recv_exact(s, resp_len)
            if len(data) < resp_len:
                raise DnsError("Truncated TCP response")
            return parse_response(data, qid)

    def axfr(self, zone: str, nameserver: str) -> List[Dict[str, Any]]:
        """Attempts a Zone Transfer (AXFR) over TCP."""
        target_ip = nameserver
        try:
            ipaddress.ip_address(nameserver)
        except ValueError:
            resp = self.query(nameserver, A)
            if not resp["answers"]:
                raise DnsError(f"Could not resolve nameserver {nameserver}")
            target_ip = resp["answers"][0]["data"]

        qid = random.getrandbits(16)
        packet = build_query(zone, AXFR, qid)
        tcp_packet = struct.pack("!H", len(packet)) + packet
        
        all_records = []
        soa_count = 0
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            try:
                s.connect((target_ip, self.port))
                s.sendall(tcp_packet)
                
                while True:
                    len_bytes = self._recv_exact(s, 2)
                    if len(len_bytes) < 2:
                        break
                    resp_len = struct.unpack("!H", len_bytes)[0]
                    data = self._recv_exact(s, resp_len)
                    if len(data) < resp_len:
                        break
                    
                    try:
                        resp = parse_response(data, qid)
                    except DnsError as e:
                        if "Refused" in str(e):
                            raise DnsError("zone transfer refused")
                        raise
                        
                    for rec in resp["answers"]:
                        all_records.append(rec)
                        if rec["type"] == SOA:
                            soa_count += 1
                    
                    if soa_count >= 2:
                        break
            except socket.timeout:
                if not all_records:
                    raise DnsError("zone transfer timed out")
            except ConnectionError:
                if not all_records:
                    raise DnsError("zone transfer not supported")
        
        if not all_records:
            raise DnsError("zone transfer not supported")
            
        return all_records

