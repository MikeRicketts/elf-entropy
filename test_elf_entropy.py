#!/usr/bin/env python3
"""Unit tests for elf_entropy.py. Run with:  python test_elf_entropy.py -v

Most tests build small ELF files in memory, so no sample binaries are needed.
On Linux, extra tests run against /bin/ls and, if `upx` is installed, a
UPX-packed copy of it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import elf_entropy as ee  # noqa: E402

SCRIPT = os.path.join(HERE, "elf_entropy.py")
SHF_ALLOC, SHF_EXEC, SHF_WRITE = ee.SHF_ALLOC, ee.SHF_EXECINSTR, ee.SHF_WRITE
PT_LOAD = 1
R, W, X = ee.PF_R, ee.PF_W, ee.PF_X


def rand_bytes(n: int, seed: int = 1) -> bytes:
    if n == 0:
        return b""
    return random.Random(seed).getrandbits(8 * n).to_bytes(n, "little")


def code_like(n: int, seed: int = 2) -> bytes:
    """Bytes with a skewed distribution, roughly like machine code."""
    rng = random.Random(seed)
    common = [0x00, 0x48, 0x89, 0x8B, 0xE8, 0xFF, 0x0F, 0x85, 0xC3, 0x24]
    return bytes(rng.choice(common) if rng.random() < 0.55 else rng.randrange(256)
                 for _ in range(n))


def compressed(n: int, seed: int = 3) -> bytes:
    """zlib output of repetitive, structured text, at least n bytes long."""
    rng = random.Random(seed)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"func", b"ret", b"mov",
             b"call", b"push", b"pop", b"0x", b"\n", b" ", b"="]
    out = b""
    while len(out) < n:
        text = b"".join(rng.choice(words) + str(rng.randrange(500)).encode()
                        for _ in range(n))
        out = zlib.compress(text, 9)
    return out[:n]


def build_elf(sections=(), segments=(), *, is64=True, little=True,
              e_type=3, machine=62, ext_numbering=False, trailer=b""):
    """Build an ELF image.

    sections: (name, sh_type, sh_flags, content) tuples.
    segments: dicts with p_type, p_flags and either 'section' (cover that
              section) or explicit 'offset'/'filesz'; optional 'memsz'.
    """
    e = "<" if little else ">"
    eh_size = 64 if is64 else 52
    ph_fmt = e + ("IIQQQQQQ" if is64 else "IIIIIIII")
    sh_fmt = e + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    ph_size, sh_size = struct.calcsize(ph_fmt), struct.calcsize(sh_fmt)

    body = bytearray(b"\0" * (eh_size + ph_size * len(segments)))
    shstr = bytearray(b"\0")
    placed = []  # (name_off, type, flags, offset, size)
    for name, stype, flags, content in sections:
        name_off = len(shstr)
        shstr += name.encode("latin-1") + b"\0"
        while len(body) % 16:
            body.append(0)
        off = len(body)
        if stype != ee.SHT_NOBITS:
            body += content
        placed.append((name_off, stype, flags, off, len(content)))
    shstr_name = len(shstr)
    shstr += b".shstrtab\0"
    shstr_off = len(body)
    body += shstr
    placed.append((shstr_name, 3, 0, shstr_off, len(shstr)))
    body += trailer
    while len(body) % 8:
        body.append(0)
    shoff = len(body)

    shnum = len(placed) + 1
    shstrndx = shnum - 1
    sh0 = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if ext_numbering:
        sh0 = (0, 0, 0, 0, 0, shnum, shstrndx, 0, 0, 0)
    body += struct.pack(sh_fmt, *sh0)
    for name_off, stype, flags, off, size in placed:
        body += struct.pack(sh_fmt, name_off, stype, flags, 0, off, size,
                            0, 0, 1, 0)

    by_name = {sec[0]: placed[i] for i, sec in enumerate(sections)}
    for i, seg in enumerate(segments):
        if "section" in seg:
            _n, _t, _f, off, size = by_name[seg["section"]]
        else:
            off, size = seg["offset"], seg["filesz"]
        memsz = seg.get("memsz", size)
        if is64:
            vals = (seg["p_type"], seg["p_flags"], off, 0, 0, size, memsz, 0x1000)
        else:
            vals = (seg["p_type"], off, 0, 0, size, memsz, seg["p_flags"], 0x1000)
        struct.pack_into(ph_fmt, body, eh_size + i * ph_size, *vals)

    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1]) + b"\0" * 9
    hdr_fmt = e + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    hdr = struct.pack(hdr_fmt, e_type, machine, 1, 0,
                      eh_size if segments else 0, shoff, 0, eh_size,
                      ph_size, len(segments), sh_size,
                      0 if ext_numbering else shnum,
                      ee.SHN_XINDEX if ext_numbering else shstrndx)
    body[0:eh_size] = ident + hdr
    return bytes(body)


def raw_elf64(payload: bytes, shdrs=(), phdrs=(), *, shnum=None, phnum=None):
    """Minimal ELF64 with hand-written header tables appended after payload.
    shdrs/phdrs: tuples in struct field order."""
    sh_fmt, ph_fmt = "<IIQQQQIIQQ", "<IIQQQQQQ"
    body = bytearray(64) + payload
    phoff = len(body) if phdrs else 0
    for p in phdrs:
        body += struct.pack(ph_fmt, *p)
    shoff = len(body) if shdrs else 0
    for s in shdrs:
        body += struct.pack(sh_fmt, *s)
    hdr = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, phoff, shoff, 0, 64, 56,
                      len(phdrs) if phnum is None else phnum, 64,
                      len(shdrs) if shnum is None else shnum, 0)
    body[0:64] = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + hdr
    return bytes(body)


def normal_binary(**kw):
    text = code_like(20000)
    return build_elf(
        sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, text),
                  (".rodata", 1, SHF_ALLOC, b"hello world\0" * 300),
                  (".data", 1, SHF_ALLOC | SHF_WRITE, bytes(range(64)) * 4),
                  (".bss", ee.SHT_NOBITS, SHF_ALLOC | SHF_WRITE, b"\0" * 512)],
        segments=[{"p_type": PT_LOAD, "p_flags": R | X, "section": ".text"},
                  {"p_type": PT_LOAD, "p_flags": R, "section": ".rodata"},
                  {"p_type": PT_LOAD, "p_flags": R | W, "section": ".data"}],
        **kw)


def cats(rep):
    return {i.category for i in rep.indicators if i.weight}


# --------------------------------------------------------------------------- #

class ByteStatsTests(unittest.TestCase):
    def test_entropy_extremes(self):
        self.assertEqual(ee.shannon_entropy(b""), 0.0)
        self.assertEqual(ee.shannon_entropy(b"\0" * 1000), 0.0)
        self.assertAlmostEqual(ee.shannon_entropy(bytes(range(256)) * 10), 8.0)
        self.assertAlmostEqual(ee.shannon_entropy(b"ab" * 50), 1.0)

    def test_chi_square_uniform_is_zero(self):
        _ent, chi2 = ee.byte_stats(bytes(range(256)) * 20)
        self.assertAlmostEqual(chi2, 0.0)
        self.assertAlmostEqual(ee.chi2_pvalue(255), 0.5, delta=0.02)

    def test_random_vs_compressed(self):
        self.assertEqual(ee.randomness(rand_bytes(60000)), "random")
        self.assertEqual(ee.randomness(compressed(60000)), "structured")

    def test_padding_does_not_hide_random_data(self):
        # Zero padding inside ciphertext used to push it to "structured".
        data = rand_bytes(50000) + b"\0" * 1024 + rand_bytes(50000, seed=4)
        self.assertEqual(ee.randomness(data), "random")

    def test_randomness_skips_small_or_low_entropy(self):
        self.assertIsNone(ee.randomness(rand_bytes(1000)))
        self.assertIsNone(ee.randomness(b"abc" * 2000))

    def test_classify(self):
        self.assertEqual(ee.classify(3.0, 7.2), "low")
        self.assertEqual(ee.classify(6.0, 7.2), "code-like")
        self.assertEqual(ee.classify(7.0, 7.2), "high")
        self.assertEqual(ee.classify(7.5, 7.2), "very high")

    def test_regions(self):
        data = b"\0" * 8192 + rand_bytes(8192) + b"\0" * 8192
        regions = ee.high_entropy_regions(data, 1024, 7.0)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0]["offset"], 8192)
        self.assertEqual(regions[0]["size"], 8192)
        self.assertGreater(regions[0]["entropy"], 7.9)
        self.assertEqual(regions[0]["randomness"], "random")

    def test_expected_random_entropy(self):
        self.assertLess(ee.expected_random_entropy(256), 7.3)
        self.assertGreater(ee.expected_random_entropy(1024), 7.8)


class ByteCounterTests(unittest.TestCase):
    def setUp(self):
        self.data = rand_bytes(20000) + b"\0" * 5000 + code_like(10000)

    def check(self, counter, ranges):
        for a, b in ranges:
            self.assertEqual(counter.counts(a, b),
                             ee._histogram(self.data[a:b]), (a, b))

    def test_indexed_ranges_match_direct_counts(self):
        ranges = [(0, 20000), (20000, 25000), (100, 30000), (0, len(self.data))]
        counter = ee.ByteCounter(self.data, [x for r in ranges for x in r])
        self.assertIsNotNone(counter.cuts)
        self.check(counter, ranges)
        self.check(counter, [(5, 77)])  # not on a cut: counted directly

    def test_fallback_when_too_many_boundaries(self):
        offsets = range(0, ee.MAX_BOUNDARIES + 10)
        counter = ee.ByteCounter(self.data, offsets)
        self.assertIsNone(counter.cuts)
        self.check(counter, [(0, 1000), (3, 30000)])

    def test_budget_stops_runaway_work(self):
        counter = ee.ByteCounter(self.data, range(ee.MAX_BOUNDARIES + 10))
        counter.budget = 25000
        self.assertIsNotNone(counter.counts(0, 20000))
        self.assertIsNotNone(counter.counts(0, 20000))  # cached, free
        self.assertIsNone(counter.counts(1, 20000))
        self.assertTrue(counter.over_budget)


class ParsingTests(unittest.TestCase):
    def check_layout(self, is64, little):
        rep = ee.analyze_bytes(normal_binary(is64=is64, little=little))
        self.assertEqual(rep.elf_class, "ELF64" if is64 else "ELF32")
        self.assertEqual(rep.endian, "little" if little else "big")
        self.assertEqual(rep.elf_type, "DYN")
        self.assertEqual(rep.machine, "x86-64")
        names = [s.name for s in rep.sections]
        self.assertEqual(names, [".text", ".rodata", ".data", ".bss", ".shstrtab"])
        text = rep.sections[0]
        self.assertEqual((text.type, text.flags, text.size), ("PROGBITS", "AX", 20000))
        self.assertIsNone(rep.sections[3].entropy)  # NOBITS has no file bytes
        self.assertEqual([g.flags for g in rep.segments], ["R-X", "R--", "RW-"])
        self.assertEqual(rep.segments[0].entropy, text.entropy)
        self.assertEqual(rep.verdict, "clean")
        self.assertEqual(rep.score, 0)
        return rep

    def test_all_class_and_endian_combinations(self):
        reps = [self.check_layout(is64, little)
                for is64 in (True, False) for little in (True, False)]
        for rep in reps[1:]:
            self.assertEqual([s.entropy for s in rep.sections],
                             [s.entropy for s in reps[0].sections])

    def test_entropy_matches_direct_calculation(self):
        data = normal_binary()
        rep = ee.analyze_bytes(data)
        self.assertAlmostEqual(rep.entropy, ee.shannon_entropy(data), places=4)
        for s in rep.sections:
            if s.entropy is not None:
                self.assertAlmostEqual(
                    s.entropy, ee.shannon_entropy(data[s.offset:s.offset + s.size]),
                    places=4)

    def test_extended_section_numbering(self):
        rep = ee.analyze_bytes(normal_binary(ext_numbering=True))
        self.assertEqual(len(rep.sections), 5)
        self.assertEqual(rep.sections[0].name, ".text")

    def test_pn_xnum_reads_count_from_section_zero(self):
        payload = code_like(4000)
        phdrs = [(PT_LOAD, R | X, 64, 0, 0, 4000, 4000, 0x1000)] * 3
        # Section 0's sh_info holds the real program header count.
        data = raw_elf64(payload, phdrs=phdrs, phnum=ee.PN_XNUM,
                         shdrs=[(0, 0, 0, 0, 0, 0, 0, 3, 0, 0)])
        rep = ee.analyze_bytes(data)
        self.assertEqual(len(rep.segments), 3)

    def test_not_elf(self):
        with self.assertRaises(ee.ELFError):
            ee.analyze_bytes(b"MZ" + b"\0" * 100)

    def test_bad_class(self):
        data = bytearray(normal_binary())
        data[4] = 7
        with self.assertRaises(ee.ELFError):
            ee.analyze_bytes(bytes(data))

    def test_truncated_section_table(self):
        rep = ee.analyze_bytes(normal_binary()[:-40])
        self.assertTrue(any("truncated" in i.message for i in rep.indicators))
        self.assertLess(rep.score, ee.SCORE_SUSPICIOUS)

    def test_section_past_end_of_file(self):
        data = raw_elf64(code_like(2000), shdrs=[
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (0, 1, SHF_ALLOC | SHF_EXEC, 0, 64, 50000, 0, 0, 1, 0),   # runs past EOF
            (0, 1, SHF_ALLOC, 0, 2 ** 64 - 1, 100, 0, 0, 1, 0),       # starts past EOF
        ])
        rep = ee.analyze_bytes(data)
        self.assertTrue(rep.sections[0].truncated)
        self.assertIsNotNone(rep.sections[0].entropy)
        self.assertEqual(rep.sections[1].rating, "past end of file")
        self.assertIn("past_eof", cats(rep))

    def test_hostile_identical_headers_are_fast(self):
        # 65,535 section headers that all cover the whole file. This used to
        # re-count the whole file once per header.
        n, payload = 0xFFFF, rand_bytes(300000)
        size = 64 + len(payload) + 64 * n
        sh = (0, 1, SHF_ALLOC, 0, 0, size, 0, 0, 1, 0)
        data = raw_elf64(payload, shdrs=[sh] * n)
        start = time.perf_counter()
        rep = ee.analyze_bytes(data)
        self.assertLess(time.perf_counter() - start, 15)
        self.assertEqual(len(rep.sections), n)  # entry 0 isn't null here either

    def test_hostile_distinct_ranges_are_bounded(self):
        # Many distinct, overlapping ranges: too many to index, so the work
        # budget has to kick in.
        n, payload = 6000, rand_bytes(400000)
        sh = [(0, 1, SHF_ALLOC, 0, i, len(payload) - i, 0, 0, 1, 0)
              for i in range(n)]
        data = raw_elf64(payload, shdrs=sh)
        start = time.perf_counter()
        rep = ee.analyze_bytes(data)
        self.assertLess(time.perf_counter() - start, 15)
        self.assertTrue(any(s.rating == "skipped (work limit)" for s in rep.sections))
        self.assertIn("malformed", cats(rep))

    def test_too_many_headers_capped(self):
        sh = [(0, 1, 0, 0, 64, 10, 0, 0, 1, 0)] * 10
        data = raw_elf64(b"x" * 100, shdrs=sh, shnum=0)
        # Extended numbering claiming 2**32-1 sections.
        data = bytearray(data)
        shoff, = struct.unpack_from("<Q", data, 0x28)
        struct.pack_into("<Q", data, shoff + 32, 0xFFFFFFFF)
        rep = ee.analyze_bytes(bytes(data))
        self.assertTrue(any("truncated" in i.message for i in rep.indicators))


class DetectionTests(unittest.TestCase):
    def test_encrypted_text(self):
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, rand_bytes(30000)),
                      (".rodata", 1, SHF_ALLOC, b"str\0" * 500)],
            segments=[{"p_type": PT_LOAD, "p_flags": R | X, "section": ".text"}])
        rep = ee.analyze_bytes(data)
        self.assertIn("exec_entropy", cats(rep))
        self.assertIn("random_code", cats(rep))
        self.assertEqual(rep.sections[0].randomness, "random")
        self.assertEqual(rep.verdict, "likely packed/encrypted")

    def test_compressed_text_labelled_structured(self):
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, compressed(30000))])
        rep = ee.analyze_bytes(data)
        self.assertEqual(rep.sections[0].randomness, "structured")
        self.assertIn("exec_entropy", cats(rep))
        self.assertNotIn("random_code", cats(rep))

    def test_compressed_debug_section_is_expected(self):
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, code_like(8000)),
                      (".debug_info", 1, ee.SHF_COMPRESSED, compressed(20000)),
                      (".zdebug_line", 1, 0, compressed(20000, seed=9)),
                      (".gnu_debugdata", 1, 0, compressed(20000, seed=8))])
        rep = ee.analyze_bytes(data)
        self.assertEqual(rep.sections[1].flags, "C")
        for s in rep.sections[1:4]:
            self.assertEqual(s.expected, "compressed section", s.name)
        self.assertEqual(rep.score, 0)

    def test_hash_table_is_expected(self):
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, code_like(8000)),
                      (".gnu.hash", ee.SHT_GNU_HASH, SHF_ALLOC, rand_bytes(4000))])
        rep = ee.analyze_bytes(data)
        self.assertEqual(rep.sections[1].expected, "hash table")
        self.assertEqual(rep.score, 0)

    def test_embedded_data_blob_scores_once(self):
        # A normal library with a big compressed table (like gconv's GB18030
        # or kheaders.ko) used to get +3 and +1 for the same bytes.
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, code_like(8000)),
                      (".rodata", 1, SHF_ALLOC, compressed(200000))])
        rep = ee.analyze_bytes(data)
        self.assertGreater(rep.entropy, 7.2)
        self.assertNotIn("file_entropy", cats(rep))
        self.assertEqual(cats(rep), {"data_entropy"})
        self.assertIn("accounts for", rep.indicators[0].message)
        self.assertEqual(rep.verdict, "clean")

    def test_upx_header_location(self):
        payload = b"\0\0\0\0" + ee.UPX_MAGIC + compressed(30000) + b"\0" * 28 \
            + ee.UPX_MAGIC + b"\0" * 32
        phdrs = [(PT_LOAD, R | X, 0, 0, 0, 64 + 56 + len(payload),
                  64 + 56 + len(payload), 0x1000)]
        # raw_elf64 puts payload before the phdrs; rebuild so the l_info
        # block sits right after the program headers like real UPX output.
        data = bytearray(raw_elf64(b"", phdrs=phdrs)) + payload
        struct.pack_into("<Q", data, 0x20, 64)
        rep = ee.analyze_bytes(bytes(data))
        sig = [i for i in rep.indicators if i.category == "packer_signature"]
        self.assertEqual(len(sig), 1)
        self.assertIn("after program headers", sig[0].message)
        self.assertIn("at end of file", sig[0].message)

    def test_upx_text_elsewhere_not_scored(self):
        # The upx tool itself contains "UPX!" but isn't packed.
        text = code_like(20000) + b"magic is UPX! here" + code_like(5000, seed=6)
        data = build_elf(sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, text),
                                   (".rodata", 1, SHF_ALLOC, b"x" * 1000)])
        rep = ee.analyze_bytes(data)
        self.assertEqual(rep.score, 0)
        self.assertTrue(any(i.category == "info" for i in rep.indicators))

    def test_upx_like_binary(self):
        data = bytearray(build_elf(
            segments=[{"p_type": PT_LOAD, "p_flags": R | W | X,
                       "offset": 0, "filesz": 120000, "memsz": 2_000_000}],
            trailer=compressed(40000)))
        data += b"\0" * 20 + ee.UPX_MAGIC + b"\0" * 32   # UPX PackHeader at EOF
        # Drop the section table entirely, like a packer would.
        struct.pack_into("<Q", data, 0x28, 0)        # e_shoff
        struct.pack_into("<HH", data, 0x3C, 0, 0)    # e_shnum, e_shstrndx
        rep = ee.analyze_bytes(bytes(data))
        for c in ("packer_signature", "no_sections", "rwx_segment",
                  "past_eof", "runtime_unpack", "sectionless_static"):
            self.assertIn(c, cats(rep))
        self.assertEqual(rep.verdict, "likely packed/encrypted")
        self.assertTrue(rep.segments[0].truncated)

    def test_overlay(self):
        rep = ee.analyze_bytes(normal_binary(trailer=rand_bytes(20000)))
        self.assertIn("overlay", cats(rep))

    def test_score_counts_each_category_once(self):
        data = build_elf(
            sections=[(".text", 1, SHF_ALLOC | SHF_EXEC, compressed(30000)),
                      (".init", 1, SHF_ALLOC | SHF_EXEC, compressed(20000, seed=5)),
                      (".rodata", 1, SHF_ALLOC, b"\0" * 60000)],
            segments=[{"p_type": PT_LOAD, "p_flags": R | X, "section": ".text"}])
        rep = ee.analyze_bytes(data)
        hits = [i for i in rep.indicators if i.category == "exec_entropy"]
        self.assertEqual(len(hits), 3)
        self.assertEqual(sum(i.counted for i in hits), 1)
        self.assertEqual(rep.score, ee.WEIGHTS["exec_entropy"])
        self.assertEqual(rep.score, sum(i.weight for i in rep.indicators if i.counted))
        self.assertEqual(rep.verdict, "suspicious")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.clean = os.path.join(d, "clean.elf")
        self.packed = os.path.join(d, "packed.elf")
        self.text = os.path.join(d, "notes.txt")
        with open(self.clean, "wb") as f:
            f.write(normal_binary())
        with open(self.packed, "wb") as f:
            f.write(build_elf(sections=[(".text", 1, SHF_ALLOC | SHF_EXEC,
                                         rand_bytes(30000))]))
        with open(self.text, "w") as f:
            f.write("not an elf")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                code = ee.main(list(args))
            except SystemExit as e:   # argparse errors
                code = e.code
        return code, out.getvalue()

    def run_subprocess(self, *args, env=None):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True,
                              timeout=60, env=env)

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(self.clean)[0], 0)
        self.assertEqual(self.run_cli(self.packed)[0], 2)
        self.assertEqual(self.run_cli(self.text)[0], 1)
        self.assertEqual(self.run_cli(self.packed, "--min-score", "99")[0], 0)

    def test_directory_scan_skips_non_elf(self):
        code, out = self.run_cli("-s", self.tmp.name)
        self.assertEqual(code, 2)
        self.assertIn("clean.elf", out)
        self.assertIn("packed.elf", out)
        self.assertNotIn("notes.txt", out)

    def test_json_output(self):
        code, out = self.run_cli("-j", "-w", "1024", self.packed)
        data = json.loads(out)
        self.assertEqual(data[0]["verdict"], "likely packed/encrypted")
        self.assertTrue(data[0]["regions"])
        ind = data[0]["indicators"]
        self.assertEqual(data[0]["score"],
                         sum(i["weight"] for i in ind if i["counted"]))

    def test_window_validation(self):
        self.assertEqual(self.run_cli("-w", "256", self.clean)[0], 2)  # argparse
        self.assertEqual(self.run_cli("-w", "-5", self.clean)[0], 2)
        self.assertEqual(self.run_cli("-w", "512", self.clean)[0], 0)

    def test_hostile_section_name_is_escaped(self):
        bad = build_elf(sections=[(".te\x81xt\x1b[31m", 1, SHF_ALLOC | SHF_EXEC,
                                   code_like(5000))])
        path = os.path.join(self.tmp.name, "badname.elf")
        with open(path, "wb") as f:
            f.write(bad)
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        res = self.run_subprocess("-v", path, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(b".te\\x81xt\\x1b[31m", res.stdout)
        self.assertNotIn(b"\x1b", res.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs POSIX FIFOs")
    def test_recursive_scan_skips_fifo(self):
        os.mkfifo(os.path.join(self.tmp.name, "pipe"))
        res = self.run_subprocess("-s", "-r", self.tmp.name)  # used to hang
        self.assertEqual(res.returncode, 2)
        self.assertNotIn(b"pipe", res.stdout)

    def test_explicit_non_regular_file(self):
        code, out = self.run_cli("-s", self.tmp.name + os.sep + ".")
        self.assertEqual(code, 2)  # directory is scanned, not read as a file
        if os.path.exists("/dev/zero"):
            code, out = self.run_cli("-s", "/dev/zero")
            self.assertEqual(code, 1)
            self.assertIn("not", out)

    def test_symlinks_and_hard_links_scanned_once(self):
        try:
            os.symlink(self.clean, os.path.join(self.tmp.name, "link.elf"))
        except (OSError, NotImplementedError):
            self.skipTest("can't create symlinks here")
        try:
            os.link(self.clean, os.path.join(self.tmp.name, "hard.elf"))
        except OSError:
            pass
        code, out = self.run_cli("-s", "-r", self.tmp.name)
        self.assertNotIn("link.elf", out)
        lines = [line for line in out.splitlines()
                 if "clean.elf" in line or "hard.elf" in line]
        if os.stat(self.clean).st_ino:
            self.assertEqual(len(lines), 1)


@unittest.skipUnless(os.path.isfile("/bin/ls") and ee.is_elf("/bin/ls"),
                     "needs a Linux /bin/ls")
class RealBinaryTests(unittest.TestCase):
    def test_ls_is_clean(self):
        rep = ee.analyze("/bin/ls")
        self.assertEqual(rep.verdict, "clean")
        self.assertTrue(any(s.name == ".text" for s in rep.sections))

    @unittest.skipUnless(shutil.which("upx"), "upx not installed")
    def test_upx_packed_ls(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "ls_upx")
            subprocess.run(["upx", "-q", "-o", out, "/bin/ls"], check=True,
                           capture_output=True, timeout=120)
            rep = ee.analyze(out)
        self.assertEqual(rep.verdict, "likely packed/encrypted")
        self.assertIn("packer_signature", cats(rep))


if __name__ == "__main__":
    unittest.main()
