# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import collections
import random
import struct
from collections.abc import Iterable
from typing import Any, Self

import dns._text_util
import dns.exception
import dns.ipv4
import dns.ipv6
import dns.name
import dns.rdata
import dns.rdatatype
import dns.tokenizer
import dns.wire


class _GatewayKind:
    """The behaviour of one gateway type, as used by :py:class:`Gateway`."""

    def check(self, gateway: Any, name: str) -> str | dns.name.Name | None:
        """Check *gateway* and return the value to store."""
        raise NotImplementedError  # pragma: no cover

    def to_styled_text(self, gateway: Any, style: dns.rdata.RdataStyle) -> str:
        raise NotImplementedError  # pragma: no cover

    def from_text(
        self, tok, origin=None, relativize=True, relativize_to=None
    ) -> str | dns.name.Name:
        return tok.get_string()

    def to_wire(self, gateway: Any, file, origin=None) -> None:
        raise NotImplementedError  # pragma: no cover

    def from_wire_parser(self, parser, origin=None) -> str | dns.name.Name | None:
        raise NotImplementedError  # pragma: no cover


class _NoGateway(_GatewayKind):
    """Gateway type 0: no gateway."""

    def check(self, gateway, name):
        if gateway not in (".", None):
            raise SyntaxError(f"invalid {name} for type 0")
        return None

    def to_styled_text(self, gateway, style):
        return "."

    def to_wire(self, gateway, file, origin=None):
        pass

    def from_wire_parser(self, parser, origin=None):
        return None


class _IPv4Gateway(_GatewayKind):
    """Gateway type 1: an IPv4 address."""

    def check(self, gateway, name):
        assert isinstance(gateway, str)
        dns.ipv4.inet_aton(gateway)
        return gateway

    def to_styled_text(self, gateway, style):
        return gateway

    def to_wire(self, gateway, file, origin=None):
        file.write(dns.ipv4.inet_aton(gateway))

    def from_wire_parser(self, parser, origin=None):
        return dns.ipv4.inet_ntoa(parser.get_bytes(4))


class _IPv6Gateway(_GatewayKind):
    """Gateway type 2: an IPv6 address."""

    def check(self, gateway, name):
        assert isinstance(gateway, str)
        dns.ipv6.inet_aton(gateway)
        return gateway

    def to_styled_text(self, gateway, style):
        return gateway

    def to_wire(self, gateway, file, origin=None):
        file.write(dns.ipv6.inet_aton(gateway))

    def from_wire_parser(self, parser, origin=None):
        return dns.ipv6.inet_ntoa(parser.get_bytes(16))


class _NameGateway(_GatewayKind):
    """Gateway type 3: a domain name."""

    def check(self, gateway, name):
        if not isinstance(gateway, dns.name.Name):
            raise SyntaxError(f"invalid {name}; not a name")
        return gateway

    def to_styled_text(self, gateway, style):
        return gateway.to_styled_text(style)

    def from_text(self, tok, origin=None, relativize=True, relativize_to=None):
        return tok.get_name(origin, relativize, relativize_to)

    def to_wire(self, gateway, file, origin=None):
        gateway.to_wire(file, None, origin, False)

    def from_wire_parser(self, parser, origin=None):
        return parser.get_name(origin)


_GATEWAY_KINDS: dict[int, _GatewayKind] = {
    0: _NoGateway(),
    1: _IPv4Gateway(),
    2: _IPv6Gateway(),
    3: _NameGateway(),
}


class Gateway:
    """A helper class for the IPSECKEY gateway and AMTRELAY relay fields"""

    name = ""

    def __init__(self, type: Any, gateway: str | dns.name.Name | None = None):
        self.type: int = dns.rdata.Rdata._as_uint8(type)
        self.gateway: str | dns.name.Name | None = gateway
        self._check()

    @classmethod
    def _invalid_type(cls, gateway_type):
        return f"invalid {cls.name} type: {gateway_type}"

    @property
    def _kind(self) -> _GatewayKind:
        kind = _GATEWAY_KINDS.get(self.type)
        if kind is None:
            raise ValueError(self._invalid_type(self.type))  # pragma: no cover
        return kind

    def _check(self):
        if self.type not in _GATEWAY_KINDS:
            raise SyntaxError(self._invalid_type(self.type))
        self.gateway = self._kind.check(self.gateway, self.name)

    def to_text(self, origin=None, relativize=True) -> str:
        return self.to_styled_text(
            dns.rdata.RdataStyle(origin=origin, relativize=relativize)
        )

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        return self._kind.to_styled_text(self.gateway, style)

    @classmethod
    def from_text(
        cls, gateway_type, tok, origin=None, relativize=True, relativize_to=None
    ):
        kind = _GATEWAY_KINDS.get(gateway_type)
        if kind is None:
            raise dns.exception.SyntaxError(
                cls._invalid_type(gateway_type)
            )  # pragma: no cover
        gateway = kind.from_text(tok, origin, relativize, relativize_to)
        return cls(gateway_type, gateway)

    # pylint: disable=unused-argument
    def to_wire(self, file, compress=None, origin=None, canonicalize=False):
        self._kind.to_wire(self.gateway, file, origin)

    # pylint: enable=unused-argument

    @classmethod
    def from_wire_parser(cls, gateway_type, parser, origin=None):
        kind = _GATEWAY_KINDS.get(gateway_type)
        if kind is None:
            raise dns.exception.FormError(cls._invalid_type(gateway_type))
        gateway = kind.from_wire_parser(parser, origin)
        return cls(gateway_type, gateway)


class Bitmap:
    """A helper class for the NSEC/NSEC3/CSYNC type bitmaps"""

    type_name = ""

    def __init__(self, windows: Iterable[tuple[int, bytes]] | None = None):
        last_window = -1
        if windows is None:
            windows = []
        self.windows: list[tuple[int, bytes]] = []
        for window, bitmap in windows:
            if not isinstance(window, int):
                raise ValueError(f"bad {self.type_name} window type")
            if window <= last_window:
                raise ValueError(f"bad {self.type_name} window order")
            if window > 255:
                raise ValueError(f"bad {self.type_name} window number")
            last_window = window
            if not isinstance(bitmap, bytes):
                raise ValueError(f"bad {self.type_name} octets type")
            if len(bitmap) == 0 or len(bitmap) > 32:
                raise ValueError(f"bad {self.type_name} octets")
            if bitmap[-1] == 0:
                # RFC 4034 section 4.1.2: blocks with no types present must not
                # be included and trailing zero octets must be omitted, so the
                # last octet of a window's bitmap is always non-zero.
                raise ValueError(f"bad {self.type_name} octets: trailing zero octet")
            self.windows.append((window, bitmap))

    def to_text(self) -> str:
        text = ""
        for window, bitmap in self.windows:
            bits = []
            for i, byte in enumerate(bitmap):
                for j in range(0, 8):
                    if byte & (0x80 >> j):
                        rdtype = dns.rdatatype.RdataType.make(window * 256 + i * 8 + j)
                        bits.append(dns.rdatatype.to_text(rdtype))
            text += " " + " ".join(bits)
        return text

    @classmethod
    def from_text(cls, tok: "dns.tokenizer.Tokenizer") -> Self:
        rdtypes = []
        for token in tok.get_remaining():
            rdtype = dns.rdatatype.from_text(token.unescape().value)
            # RFC 4035 says you MUST NOT send "pseudo-types" like TYPE0, AXFR, etc.
            # but also says you MUST ignore them if you see them.  We used to
            # ban TYPE0 here, but this means TYPE0 doesn't "round trip" if we
            # get one in an AXFR, for example, and write it to a zonefile.  So,
            # to promote round-tripping, we no longer object to it.
            rdtypes.append(rdtype)
        return cls.from_rdtypes(rdtypes)

    @classmethod
    def from_rdtypes(cls, rdtypes: list[dns.rdatatype.RdataType]) -> Self:
        rdtypes = sorted(rdtypes)
        window = 0
        octets = 0
        prior_rdtype = None
        bitmap = bytearray(b"\0" * 32)
        windows = []
        for rdtype in rdtypes:
            if rdtype == prior_rdtype:
                continue
            prior_rdtype = rdtype
            new_window = rdtype // 256
            if new_window != window:
                if octets != 0:
                    windows.append((window, bytes(bitmap[0:octets])))
                bitmap = bytearray(b"\0" * 32)
                window = new_window
            offset = rdtype % 256
            byte = offset // 8
            bit = offset % 8
            octets = byte + 1
            bitmap[byte] = bitmap[byte] | (0x80 >> bit)
        if octets != 0:
            windows.append((window, bytes(bitmap[0:octets])))
        return cls(windows)

    def to_wire(self, file: Any) -> None:
        for window, bitmap in self.windows:
            file.write(struct.pack("!BB", window, len(bitmap)))
            file.write(bitmap)

    @classmethod
    def from_wire_parser(cls, parser: "dns.wire.Parser") -> Self:
        windows = []
        while parser.remaining() > 0:
            window = parser.get_uint8()
            bitmap = parser.get_counted_bytes()
            windows.append((window, bitmap))
        return cls(windows)


def _priority_table(items):
    by_priority = collections.defaultdict(list)
    for rdata in items:
        by_priority[rdata._processing_priority()].append(rdata)
    return by_priority


def priority_processing_order(iterable):
    items = list(iterable)
    if len(items) == 1:
        return items
    by_priority = _priority_table(items)
    ordered = []
    for k in sorted(by_priority.keys()):
        rdatas = by_priority[k]
        random.shuffle(rdatas)
        ordered.extend(rdatas)
    return ordered


_no_weight = 0.1


def weighted_processing_order(iterable):
    items = list(iterable)
    if len(items) == 1:
        return items
    by_priority = _priority_table(items)
    ordered = []
    for k in sorted(by_priority.keys()):
        rdatas = by_priority[k]
        total = sum(rdata._processing_weight() or _no_weight for rdata in rdatas)
        while len(rdatas) > 1:
            r = random.uniform(0, total)
            for n, rdata in enumerate(rdatas):  # noqa: B007
                weight = rdata._processing_weight() or _no_weight
                if weight > r:
                    break
                r -= weight
            total -= weight  # pyright: ignore
            # pylint: disable=undefined-loop-variable
            ordered.append(rdata)  # pyright: ignore
            del rdatas[n]  # pyright: ignore
        ordered.append(rdatas[0])
    return ordered


def parse_formatted_hex(formatted, num_chunks, chunk_size, separator):
    if len(formatted) != num_chunks * (chunk_size + 1) - 1:
        raise ValueError("invalid formatted hex string")
    value = b""
    for _ in range(num_chunks):
        chunk = formatted[0:chunk_size]
        # int() would also accept a sign, underscores, or surrounding
        # whitespace; the presentation format is hex digits only.
        if not dns._text_util.is_ascii_digits(chunk, 16):
            raise ValueError("invalid formatted hex string")
        value += int(chunk, 16).to_bytes(chunk_size // 2, "big")
        formatted = formatted[chunk_size:]
        if len(formatted) > 0 and formatted[0] != separator:
            raise ValueError("invalid formatted hex string")
        formatted = formatted[1:]
    return value
