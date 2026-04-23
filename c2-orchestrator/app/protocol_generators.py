# ============================================================================
# FuzzStrike C2 Orchestrator — Protocol-Aware Packet Generators
# ============================================================================
# Generates structurally valid but semantically corrupted binary packets
# for network protocol fuzzing. Each protocol generator produces packets
# that look correct enough to be accepted by protocol parsers but contain
# malformed fields designed to trigger crashes and vulnerabilities.
#
# Supported Protocols:
#   DNS    — Malformed DNS queries (UDP/53)
#   DHCP   — Fuzzed DHCP Discover/Request packets (UDP/67-68)
#   OSPF   — Corrupted OSPF Hello packets (IP protocol 89)
#   LLDP   — Malformed LLDP TLV frames (Ethernet 0x88cc)
#   RADIUS — Fuzzed Access-Request packets (UDP/1812)
#
# All generators return hex-encoded byte strings for JSON transport.
# The attack node decodes them to raw bytes before transmission.
# ============================================================================

import os
import random
import struct
from typing import Callable

from loguru import logger


# ============================================================================
# Generator Registry
# ============================================================================

_PROTO_GENERATORS: dict[str, Callable[[], list[dict]]] = {}


def _register_proto(name: str):
    """Decorator to register a protocol generator."""
    def decorator(func):
        _PROTO_GENERATORS[name] = func
        return func
    return decorator


# ============================================================================
# Helper — Corruption Primitives
# ============================================================================

def _corrupt_bytes(data: bytearray, intensity: int = 3) -> bytearray:
    """Apply random byte-level corruption to a packet."""
    result = bytearray(data)
    for _ in range(min(intensity, len(result))):
        idx = random.randint(0, len(result) - 1)
        result[idx] = random.randint(0, 255)
    return result


def _overflow_field(max_size: int = 1500) -> bytes:
    """Generate an oversized field to trigger buffer overflow."""
    size = random.choice([256, 512, 1024, 4096, 65535])
    return os.urandom(min(size, max_size))


# ============================================================================
# DNS Packet Generator
# ============================================================================

@_register_proto("dns")
def generate_dns_packets(count: int = 50) -> list[dict]:
    """
    Generate malformed DNS query packets.

    DNS packet structure (RFC 1035):
        Header: 12 bytes (ID, Flags, QD/AN/NS/AR counts)
        Question: QNAME (labels) + QTYPE (2B) + QCLASS (2B)

    Fuzzing targets:
        - Oversized domain labels (>63 chars violates spec)
        - Invalid compression pointers (circular references)
        - Corrupted QType/QClass values
        - Truncated packets
        - Excessive question count
    """
    results = []
    FUZZ_DOMAINS = [
        b"\x03www\x06google\x03com\x00",           # Normal
        b"\x3f" + b"A" * 63 + b"\x03com\x00",       # Max label length
        b"\xff" + os.urandom(200) + b"\x00",         # Oversized label
        b"\xc0\x0c",                                   # Compression pointer (circular)
        b"\xc0\xc0\xc0\xc0",                           # Nested compression
        b"\x00",                                        # Empty domain
        b"\x01" + b"\x00" + b"\x03com\x00",           # Null byte in label
    ]

    FUZZ_QTYPES = [
        1,      # A record (normal)
        28,     # AAAA record
        255,    # ANY (amplification)
        0,      # Invalid
        65535,  # Max value
        random.randint(256, 65534),  # Unknown type
    ]

    for i in range(count):
        txn_id = random.randint(0, 65535)
        flags = random.choice([0x0100, 0x0000, 0xFFFF, 0x8000, random.randint(0, 65535)])
        qd_count = random.choice([1, 0, 100, 65535])
        an_count = random.choice([0, random.randint(1, 100)])
        ns_count = random.choice([0, random.randint(1, 50)])
        ar_count = random.choice([0, random.randint(1, 50)])

        header = struct.pack("!HHHHHH", txn_id, flags, qd_count, an_count, ns_count, ar_count)
        qname = random.choice(FUZZ_DOMAINS)
        qtype = random.choice(FUZZ_QTYPES)
        qclass = random.choice([1, 0, 255, 65535, random.randint(2, 254)])
        question = qname + struct.pack("!HH", qtype, qclass)

        packet = bytearray(header + question)

        # Apply random corruption at ~30% probability
        if random.random() < 0.3:
            packet = _corrupt_bytes(packet, random.randint(1, 5))

        # Randomly truncate at ~15% probability
        if random.random() < 0.15 and len(packet) > 4:
            packet = packet[:random.randint(2, len(packet) - 1)]

        hex_content = packet.hex()
        results.append({
            "content": hex_content,
            "mutation_type": f"DNS_FUZZ_{random.choice(['LABEL_OVERFLOW', 'COMPRESSION', 'QTYPE', 'TRUNCATE', 'CORRUPT'])}",
            "size_bytes": len(packet),
        })

    return results


# ============================================================================
# DHCP Packet Generator
# ============================================================================

@_register_proto("dhcp")
def generate_dhcp_packets(count: int = 50) -> list[dict]:
    """
    Generate malformed DHCP Discover/Request packets.

    DHCP packet structure (RFC 2131):
        op(1) + htype(1) + hlen(1) + hops(1) + xid(4) + secs(2) + flags(2)
        ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4)
        chaddr(16) + sname(64) + file(128)
        Magic Cookie (4 bytes: 0x63825363)
        Options (TLV format)

    Fuzzing targets:
        - Invalid magic cookie
        - Oversized option values
        - Option length overflow
        - Invalid message type
        - Corrupted hardware address length
    """
    results = []
    MAGIC_COOKIE = b"\x63\x82\x53\x63"
    FUZZ_COOKIES = [MAGIC_COOKIE, b"\x00\x00\x00\x00", os.urandom(4), b"\xff\xff\xff\xff"]

    DHCP_MSG_TYPES = [1, 2, 3, 4, 5, 6, 7, 8, 0, 255, random.randint(9, 254)]

    for i in range(count):
        op = random.choice([1, 2, 0, 255])          # 1=BOOTREQUEST, 2=BOOTREPLY
        htype = random.choice([1, 6, 0, 255])        # 1=Ethernet
        hlen = random.choice([6, 0, 16, 255])         # 6=MAC length
        hops = random.choice([0, 1, 255])
        xid = random.randint(0, 0xFFFFFFFF)
        secs = random.randint(0, 65535)
        flags = random.choice([0x0000, 0x8000, 0xFFFF])

        # Build fixed header (236 bytes)
        header = struct.pack("!BBBB I HH",
            op, htype, hlen, hops, xid, secs, flags
        )
        # Client/Server/Gateway IPs (16 bytes)
        ciaddr = struct.pack("!I", random.choice([0, 0xFFFFFFFF, random.randint(0, 0xFFFFFFFF)]))
        yiaddr = struct.pack("!I", random.choice([0, random.randint(0, 0xFFFFFFFF)]))
        siaddr = struct.pack("!I", random.choice([0, random.randint(0, 0xFFFFFFFF)]))
        giaddr = struct.pack("!I", random.choice([0, random.randint(0, 0xFFFFFFFF)]))

        # Hardware address (16 bytes) + sname (64) + file (128)
        chaddr = os.urandom(16)
        sname = os.urandom(64)
        boot_file = os.urandom(128)

        # Magic cookie
        cookie = random.choice(FUZZ_COOKIES)

        # DHCP Options
        options = bytearray()
        # Option 53: DHCP Message Type
        msg_type = random.choice(DHCP_MSG_TYPES)
        options += struct.pack("BBB", 53, 1, msg_type)

        # Fuzz: oversized option at ~40% probability
        if random.random() < 0.4:
            opt_code = random.randint(1, 254)
            opt_len = random.choice([0, 255, random.randint(50, 200)])
            opt_data = os.urandom(opt_len)
            options += struct.pack("BB", opt_code, opt_len) + opt_data

        # End option
        options += b"\xff"

        packet = bytearray(header + ciaddr + yiaddr + siaddr + giaddr +
                           chaddr + sname + boot_file + cookie + options)

        if random.random() < 0.2:
            packet = _corrupt_bytes(packet, random.randint(2, 8))

        hex_content = packet.hex()
        results.append({
            "content": hex_content,
            "mutation_type": f"DHCP_FUZZ_{random.choice(['COOKIE', 'OPTION_OVERFLOW', 'MSG_TYPE', 'HLEN', 'CORRUPT'])}",
            "size_bytes": len(packet),
        })

    return results


# ============================================================================
# OSPF Packet Generator
# ============================================================================

@_register_proto("ospf")
def generate_ospf_packets(count: int = 50) -> list[dict]:
    """
    Generate corrupted OSPF Hello packets.

    OSPF header structure (RFC 2328):
        Version(1) + Type(1) + Packet Length(2) + Router ID(4)
        Area ID(4) + Checksum(2) + Auth Type(2) + Auth Data(8)
        Hello body: Network Mask(4) + Hello Interval(2) + Options(1)
        + Priority(1) + Dead Interval(4) + DR(4) + BDR(4)

    Fuzzing targets:
        - Invalid version/type
        - Wrong packet length
        - Corrupted Router/Area IDs
        - Bad checksums
        - Malformed Hello intervals
    """
    results = []

    for i in range(count):
        version = random.choice([2, 0, 1, 3, 255])  # 2 = OSPFv2
        pkt_type = random.choice([1, 2, 3, 4, 5, 0, 255])  # 1 = Hello
        router_id = struct.pack("!I", random.randint(0, 0xFFFFFFFF))
        area_id = struct.pack("!I", random.choice([0, 0xFFFFFFFF, random.randint(0, 0xFFFFFFFF)]))
        auth_type = random.choice([0, 1, 2, 255, 65535])
        auth_data = os.urandom(8)

        # Hello body
        network_mask = struct.pack("!I", random.choice([
            0xFFFFFF00, 0xFFFF0000, 0, 0xFFFFFFFF, random.randint(0, 0xFFFFFFFF)
        ]))
        hello_interval = random.choice([10, 0, 1, 65535, random.randint(1, 300)])
        options = random.randint(0, 255)
        priority = random.choice([1, 0, 255])
        dead_interval = random.choice([40, 0, 1, 0xFFFFFFFF, random.randint(1, 1000)])
        dr = struct.pack("!I", random.randint(0, 0xFFFFFFFF))
        bdr = struct.pack("!I", random.randint(0, 0xFFFFFFFF))

        hello_body = network_mask + struct.pack("!HBB I", hello_interval, options, priority, dead_interval) + dr + bdr

        # Add random neighbor entries (~20% chance)
        if random.random() < 0.2:
            num_neighbors = random.randint(1, 50)
            for _ in range(num_neighbors):
                hello_body += struct.pack("!I", random.randint(0, 0xFFFFFFFF))

        # Calculate packet length (may be intentionally wrong)
        real_length = 24 + len(hello_body)
        reported_length = random.choice([real_length, 0, 65535, real_length + random.randint(-10, 10)])

        header = struct.pack("!BBH", version, pkt_type, reported_length)
        header += router_id + area_id
        header += struct.pack("!HH", 0, auth_type)  # Checksum=0, will be wrong
        header += auth_data

        packet = bytearray(header + hello_body)

        if random.random() < 0.25:
            packet = _corrupt_bytes(packet, random.randint(1, 6))

        hex_content = packet.hex()
        results.append({
            "content": hex_content,
            "mutation_type": f"OSPF_FUZZ_{random.choice(['VERSION', 'LENGTH', 'ROUTER_ID', 'AREA_ID', 'CHECKSUM', 'HELLO'])}",
            "size_bytes": len(packet),
        })

    return results


# ============================================================================
# LLDP Packet Generator
# ============================================================================

@_register_proto("lldp")
def generate_lldp_packets(count: int = 50) -> list[dict]:
    """
    Generate malformed LLDP (Link Layer Discovery Protocol) TLV frames.

    LLDP structure (IEEE 802.1AB):
        Series of TLV (Type-Length-Value) entries:
            Type (7 bits) + Length (9 bits) + Value (variable)
        Mandatory TLVs: Chassis ID (1), Port ID (2), TTL (3)
        End of LLDPDU: Type=0, Length=0

    Fuzzing targets:
        - Invalid TLV types
        - Oversized TLV values
        - Missing mandatory TLVs
        - Truncated TLV chains
        - Incorrect length fields
    """
    results = []

    def make_tlv(tlv_type: int, value: bytes) -> bytes:
        """Encode a single LLDP TLV with type (7 bits) + length (9 bits)."""
        length = len(value)
        type_length = ((tlv_type & 0x7F) << 9) | (length & 0x1FF)
        return struct.pack("!H", type_length) + value

    for i in range(count):
        tlvs = bytearray()

        # TLV 1: Chassis ID
        chassis_subtype = random.choice([4, 0, 255])  # 4=MAC
        chassis_value = bytes([chassis_subtype]) + os.urandom(random.choice([6, 0, 100, 255]))
        tlvs += make_tlv(1, chassis_value)

        # TLV 2: Port ID
        port_subtype = random.choice([5, 0, 255])  # 5=Interface name
        port_value = bytes([port_subtype]) + os.urandom(random.choice([4, 0, 128]))
        tlvs += make_tlv(2, port_value)

        # TLV 3: TTL
        ttl_value = struct.pack("!H", random.choice([120, 0, 65535]))
        tlvs += make_tlv(3, ttl_value)

        # Random extra TLVs at ~60% probability
        if random.random() < 0.6:
            num_extra = random.randint(1, 10)
            for _ in range(num_extra):
                extra_type = random.choice([4, 5, 6, 7, 8, 127, 0, random.randint(9, 126)])
                extra_value = os.urandom(random.choice([0, 10, 50, 200, 511]))
                tlvs += make_tlv(extra_type, extra_value)

        # End of LLDPDU (type=0, length=0)
        if random.random() < 0.8:  # 20% chance of missing end TLV
            tlvs += make_tlv(0, b"")

        packet = bytearray(tlvs)

        if random.random() < 0.2:
            packet = _corrupt_bytes(packet, random.randint(1, 4))

        hex_content = packet.hex()
        results.append({
            "content": hex_content,
            "mutation_type": f"LLDP_FUZZ_{random.choice(['CHASSIS', 'PORT', 'TTL', 'TLV_OVERFLOW', 'NO_END', 'CORRUPT'])}",
            "size_bytes": len(packet),
        })

    return results


# ============================================================================
# RADIUS Packet Generator
# ============================================================================

@_register_proto("radius")
def generate_radius_packets(count: int = 50) -> list[dict]:
    """
    Generate fuzzed RADIUS Access-Request packets.

    RADIUS packet structure (RFC 2865):
        Code(1) + Identifier(1) + Length(2) + Authenticator(16)
        Attributes: Type(1) + Length(1) + Value(variable)

    Fuzzing targets:
        - Invalid code values
        - Wrong packet length
        - Corrupted authenticator
        - Oversized attribute values
        - Invalid attribute types
    """
    results = []

    RADIUS_CODES = [
        1,    # Access-Request (normal)
        2,    # Access-Accept
        3,    # Access-Reject
        4,    # Accounting-Request
        0,    # Invalid
        255,  # Reserved
        random.randint(5, 254),
    ]

    for i in range(count):
        code = random.choice(RADIUS_CODES)
        identifier = random.randint(0, 255)
        authenticator = os.urandom(16)

        # Build attributes
        attrs = bytearray()

        # Attribute 1: User-Name
        username = random.choice([
            b"admin",
            b"root",
            os.urandom(random.choice([10, 100, 253])),
            b"\x00" * 50,
            b"A" * 253,  # Max attribute value length
        ])
        attr_len = min(len(username) + 2, 255)
        attrs += struct.pack("BB", 1, attr_len) + username[:attr_len - 2]

        # Attribute 2: User-Password (fuzzed)
        password = os.urandom(random.choice([16, 0, 128, 253]))
        attr_len = min(len(password) + 2, 255)
        attrs += struct.pack("BB", 2, attr_len) + password[:attr_len - 2]

        # Random extra attributes at ~50% probability
        if random.random() < 0.5:
            num_extra = random.randint(1, 10)
            for _ in range(num_extra):
                attr_type = random.choice([4, 5, 6, 26, 79, 80, 0, 255])
                attr_value = os.urandom(random.choice([0, 10, 50, 200, 253]))
                attr_len = min(len(attr_value) + 2, 255)
                attrs += struct.pack("BB", attr_type, attr_len) + attr_value[:attr_len - 2]

        # Total packet length (may be intentionally wrong)
        real_length = 20 + len(attrs)
        reported_length = random.choice([
            real_length,
            0,
            65535,
            real_length + random.randint(-10, 10),
            4096,
        ])

        header = struct.pack("!BBH", code, identifier, reported_length) + authenticator
        packet = bytearray(header + attrs)

        if random.random() < 0.2:
            packet = _corrupt_bytes(packet, random.randint(1, 5))

        hex_content = packet.hex()
        results.append({
            "content": hex_content,
            "mutation_type": f"RADIUS_FUZZ_{random.choice(['CODE', 'LENGTH', 'AUTH', 'ATTR_OVERFLOW', 'CORRUPT'])}",
            "size_bytes": len(packet),
        })

    return results


# ============================================================================
# Public API
# ============================================================================

def generate_protocol_packets(protocol: str, count: int = 50) -> list[dict]:
    """
    Generate fuzzed packets for the specified protocol.

    Args:
        protocol: Protocol name (dns, dhcp, ospf, lldp, radius).
        count: Number of packets to generate.

    Returns:
        list[dict]: Each dict has content (hex), mutation_type, size_bytes.

    Raises:
        ValueError: If protocol is not supported.
    """
    protocol = protocol.lower()
    if protocol not in _PROTO_GENERATORS:
        raise ValueError(
            f"Unsupported protocol: '{protocol}'. "
            f"Supported: {list(_PROTO_GENERATORS.keys())}"
        )

    generator = _PROTO_GENERATORS[protocol]
    results = generator(count=count)

    logger.info(
        f"Protocol generator [{protocol.upper()}]: generated {len(results)} packets, "
        f"total size: {sum(r['size_bytes'] for r in results):,} bytes"
    )

    return results


def get_supported_protocols() -> list[str]:
    """Return list of supported protocol names."""
    return list(_PROTO_GENERATORS.keys())
