"""Decoding raw TLS records, for the CONNECT-abuse checks."""

from __future__ import annotations

_TLS_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
}
_TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
_TLS_ALERT_LEVELS = {1: "warning", 2: "fatal"}
_TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
}


def annotate_tls_bytes(data: bytes) -> str:
    """Decode TLS records (esp. alerts) instead of dumping repr(). Falls
    back to a hex/repr summary when the bytes are not TLS records at all
    (e.g. plaintext HTTP forwarded into a tunnel)."""
    records: list[str] = []
    offset = 0
    while offset + 5 <= len(data) and len(records) < 8:
        ctype = data[offset]
        version = int.from_bytes(data[offset + 1 : offset + 3], "big")
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if ctype not in _TLS_CONTENT_TYPES:
            break
        body = data[offset + 5 : offset + 5 + length]
        ctype_name = _TLS_CONTENT_TYPES.get(ctype, f"unknown({ctype})")
        version_name = _TLS_VERSIONS.get(version, f"0x{version:04x}")
        line = f"type={ctype_name}({ctype}) version={version_name} length={length}"
        if ctype == 21 and len(body) >= 2:
            level = _TLS_ALERT_LEVELS.get(body[0], f"unknown({body[0]})")
            desc = _TLS_ALERT_DESCRIPTIONS.get(body[1], f"unknown({body[1]})")
            line += f" -> alert level={level}({body[0]}) description={desc}({body[1]})"
        records.append(line)
        offset += 5 + length
    if records:
        summary = "; ".join(records)
        remaining = data[offset:]
        if remaining:
            summary += f"; +{len(remaining)} trailing bytes: {remaining[:32].hex()}"
        return summary
    return (
        f"not a recognized TLS record; first bytes: {data[:32].hex()} ({data[:32]!r})"
    )
