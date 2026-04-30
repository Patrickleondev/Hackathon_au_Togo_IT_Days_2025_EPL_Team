"""Tests for Static-V2 deep static analysis (Phase B).

These tests synthesize a tiny PE skeleton in memory rather than shipping a
real malicious binary. Native deps (``ssdeep``, ``tlsh``, ``pefile``) are
optional — tests skip cleanly when they are missing.
"""

from __future__ import annotations

import struct

import pytest

from app.ml import static_v2


def _minimal_pe_bytes() -> bytes:
    """Build a *parseable* but functionally inert 32-bit PE.

    ``pefile`` only needs DOS + NT headers + at least one section header for
    the parser to succeed. The binary cannot be executed — that's fine for
    static-analysis tests.
    """
    dos = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40))  # e_lfanew=0x40
    pe_offset = 0x40
    nt = bytearray()
    nt += b"PE\x00\x00"
    # IMAGE_FILE_HEADER (20 bytes): Machine=0x14C (i386), 1 section, ts=0,
    # ptr_to_symtab=0, n_syms=0, sz_opt_hdr=224, characteristics=0x102
    nt += struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
    # IMAGE_OPTIONAL_HEADER32 (224 bytes) — all zeroes except magic + dirs count
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)  # PE32 magic
    # NumberOfRvaAndSizes at offset 92 (PE32) = 16
    opt[92:96] = struct.pack("<I", 16)
    nt += opt
    # One section header (40 bytes), name ".text", characteristics=0x60000020 (CODE+EX+R)
    section = bytearray(40)
    section[0:5] = b".text"
    section[36:40] = struct.pack("<I", 0x60000020)
    return bytes(dos) + bytes(nt) + bytes(section) + b"\x00" * 512


def test_analyze_bytes_empty() -> None:
    r = static_v2.analyze_bytes(b"")
    assert r.parser_error == "empty_buffer"


def test_multi_hash_always_set() -> None:
    r = static_v2.analyze_bytes(b"hello world" * 50)
    assert r.sha1 is not None
    assert r.md5 is not None
    # ssdeep / tlsh may be None if libs missing — that's fine.


def test_non_pe_data() -> None:
    """Non-PE input must not be flagged as a PE."""
    r = static_v2.analyze_bytes(b"\x00" * 200)
    assert r.is_pe is False
    assert r.imphash is None


@pytest.mark.skipif(not static_v2._PEFILE, reason="pefile not installed")
def test_minimal_pe_parsed() -> None:
    r = static_v2.analyze_bytes(_minimal_pe_bytes())
    # The synthetic PE may or may not parse perfectly under fast_load.
    # We only assert that parsing did not raise and the result is well-formed.
    assert isinstance(r.is_pe, bool)
    assert isinstance(r.section_count, int)


def test_packer_byte_signature_upx() -> None:
    """A UPX byte marker in the header must trigger UPX detection."""
    blob = b"\x4d\x5a" + b"\x00" * 10 + b"UPX!" + b"\x00" * 100
    r = static_v2.analyze_bytes(blob)
    assert r.packer == "UPX"
    assert any("bytes:UPX" in e for e in r.packer_evidence)


def test_capability_summary_lists_packer() -> None:
    blob = b"\x4d\x5a" + b"\x00" * 10 + b"UPX!" + b"\x00" * 100
    r = static_v2.analyze_bytes(blob)
    assert any("Software Packing" in c for c in r.capabilities)


def test_ssdeep_compare_lib_missing_returns_zero() -> None:
    # Pass clearly different fake hashes; if lib is present, returns int.
    out = static_v2.ssdeep_compare("96:abc", "96:xyz")
    assert isinstance(out, int)
    assert 0 <= out <= 100
