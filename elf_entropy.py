#!/usr/bin/env python3
"""
elf_entropy.py - Measure Shannon entropy in Linux ELF binaries.

Reports entropy for the whole file, every section and every program segment,
optionally scans with a sliding window to find high-entropy regions, and scores
signs of packing, compression or encryption (e.g. a UPX header, missing section
table, high-entropy executable code, segments that run past the end of file).

High-entropy data also gets a chi-square test on its byte distribution. Both
compressed and encrypted data score close to 8.0 bits/byte, but encrypted
(or random) bytes are spread almost perfectly evenly, while compressed output
usually is not. The test only looks at 4 KB blocks that are themselves near
8.0 (so padding does not skew it), needs at least 2,560 such bytes, and gets
more reliable with size: compressed data under ~10 KB can pass as random.
Treat "random" as a hint, not proof of encryption.

Pure Python 3.9+, no third-party dependencies. Works on 32/64-bit and
little/big-endian ELF files, so it runs on Windows, macOS or Linux. Built to
be run on untrusted files: every header is bounds-checked, and the amount of
work is bounded by the file size, however the headers are crafted.

Entropy scale (bits per byte, 0.0 - 8.0):
    < 5.0   low        plain data / text / zero padding
    5.0-6.8 code-like  typical compiled machine code
    6.8-7.2 high       compressed-looking
    > 7.2   very high  very likely packed, compressed or encrypted

Score: each kind of warning sign adds points (the highest weight per kind).
    0-2  clean
    3-4  suspicious
    5+   likely packed/encrypted

Usage:
    python elf_entropy.py /bin/ls
    python elf_entropy.py -r ./samples -s
    python elf_entropy.py suspicious.elf --window 1024 --threshold 7.0 --json

Exit codes: 0 = all files below --min-score, 1 = error / no ELF files,
            2 = at least one file scored --min-score (default 3) or more.
"""

from __future__ import annotations

import argparse
import bisect
import json
import math
import os
import stat
import struct
import sys
from array import array
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import NamedTuple

ELF_MAGIC = b"\x7fELF"

SHT_HASH = 5
SHT_NOBITS = 8
SHT_GNU_HASH = 0x6FFFFFF6
SHN_XINDEX = 0xFFFF
PN_XNUM = 0xFFFF

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_COMPRESSED = 0x800

PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

# Entropy bands (bits per byte). The "very high" band starts at --threshold.
ENTROPY_CODE = 5.0
ENTROPY_HIGH = 6.8

# Chi-square test: block size, minimum entropy of a block to be included,
# minimum bytes tested (about 10 expected hits per byte value), and the
# p-value below which bytes are called "structured".
CHI2_BLOCK = 4096
CHI2_BLOCK_MIN_ENTROPY = 7.85
CHI2_MIN_BYTES = 2560
CHI2_P_RANDOM = 0.001

# Limits that keep hostile files from causing unbounded work.
MAX_TABLE_ENTRIES = 65536      # section / program headers parsed per file
MAX_BOUNDARIES = 4096          # distinct offsets kept in the byte-count index
MIN_WINDOW = 512               # smaller windows can't reach typical thresholds

E_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
E_MACHINES = {
    2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    22: "S390", 40: "ARM", 43: "SPARCv9", 50: "IA-64", 62: "x86-64",
    183: "AArch64", 243: "RISC-V", 258: "LoongArch",
}
PT_TYPES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB",
    6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY",
}
SH_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
    18: "SYMTAB_SHNDX", 0x6FFFFFF6: "GNU_HASH", 0x6FFFFFFD: "VERDEF",
    0x6FFFFFFE: "VERNEED", 0x6FFFFFFF: "VERSYM",
}

UPX_MAGIC = b"UPX!"

# Score weights per kind of warning sign. Only the highest weight of each kind
# counts, so a packed file with both a hot .text and a hot LOAD segment is not
# counted twice. "info" notes are shown but never scored.
WEIGHTS = {
    "packer_signature": 5,
    "exec_entropy": 4,
    "file_entropy": 3,
    "no_sections": 2,
    "rwx_segment": 2,
    "runtime_unpack": 2,
    "past_eof": 2,
    "overlay": 2,
    "random_code": 1,
    "data_entropy": 1,
    "sectionless_static": 1,
    "malformed": 1,
    "info": 0,
}
SCORE_SUSPICIOUS = 3
SCORE_PACKED = 5


# --------------------------------------------------------------------------- #
# Byte statistics
# --------------------------------------------------------------------------- #

def _histogram(data) -> list[int]:
    counts = [0] * 256
    for byte, n in Counter(data).items():
        counts[byte] = n
    return counts


def entropy_from_counts(counts, total: int) -> float:
    if total == 0:
        return 0.0
    log_total = math.log2(total)
    ent = log_total - sum(c * math.log2(c) for c in counts if c) / total
    return min(8.0, max(0.0, ent))  # clamp float rounding noise


def chi2_from_counts(counts, total: int) -> float:
    if total == 0:
        return 0.0
    expected = total / 256
    return sum((c - expected) ** 2 for c in counts) / expected


def byte_stats(data) -> tuple[float, float]:
    """Return (Shannon entropy in bits/byte, chi-square vs uniform)."""
    counts = _histogram(data)
    return entropy_from_counts(counts, len(data)), chi2_from_counts(counts, len(data))


def shannon_entropy(data) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    return entropy_from_counts(_histogram(data), len(data))


def chi2_pvalue(chi2: float, dof: int = 255) -> float:
    """Upper-tail p-value of a chi-square statistic (Wilson-Hilferty)."""
    if chi2 <= 0:
        return 1.0
    k = float(dof)
    z = ((chi2 / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def randomness(data, entropy: float | None = None) -> str | None:
    """'random' (encrypted-like) or 'structured' (compressed-like) for
    high-entropy data, or None when there isn't enough of it to tell.

    Only near-8.0 blocks are tested, so zero padding or headers mixed into
    encrypted data don't make it look structured."""
    if entropy is None:
        entropy = shannon_entropy(data)
    if len(data) < CHI2_MIN_BYTES or entropy < ENTROPY_HIGH:
        return None
    view = memoryview(data)
    total_counts = [0] * 256
    total = 0
    for start in range(0, len(view) - CHI2_BLOCK + 1, CHI2_BLOCK):
        counts = _histogram(view[start:start + CHI2_BLOCK])
        if entropy_from_counts(counts, CHI2_BLOCK) >= CHI2_BLOCK_MIN_ENTROPY:
            total_counts = [a + b for a, b in zip(total_counts, counts)]
            total += CHI2_BLOCK
    if total == 0 and len(view) < 2 * CHI2_BLOCK:
        # Small blob: test it whole rather than not at all.
        total_counts, total = _histogram(view), len(view)
    if total < CHI2_MIN_BYTES:
        return None
    p = chi2_pvalue(chi2_from_counts(total_counts, total))
    return "random" if p >= CHI2_P_RANDOM else "structured"


def classify(entropy: float, threshold: float) -> str:
    if entropy >= threshold:
        return "very high"
    if entropy >= ENTROPY_HIGH:
        return "high"
    if entropy >= ENTROPY_CODE:
        return "code-like"
    return "low"


def expected_random_entropy(size: int) -> float:
    """Typical entropy of `size` truly random bytes (small samples score
    below 8.0 because not every byte value can appear evenly)."""
    return 8.0 - 255 / (2 * size * math.log(2))


def high_entropy_regions(data, window: int, threshold: float,
                         step: int | None = None) -> list[dict]:
    """Slide a window over data and return merged regions above threshold."""
    if window <= 0 or len(data) < window:
        return []
    view = memoryview(data)
    step = step or max(1, window // 2)
    regions: list[list] = []  # [start, end, max_entropy]
    for start in range(0, len(view) - window + 1, step):
        ent = shannon_entropy(view[start:start + window])
        if ent < threshold:
            continue
        end = start + window
        if regions and start <= regions[-1][1]:
            regions[-1][1] = end
            regions[-1][2] = max(regions[-1][2], ent)
        else:
            regions.append([start, end, ent])
    out = []
    for s, e, m in regions:
        chunk = view[s:e]
        out.append({"offset": s, "size": e - s, "max_entropy": round(m, 4),
                    "entropy": round(shannon_entropy(chunk), 4),
                    "randomness": randomness(chunk)})
    return out


class ByteCounter:
    """Answers "byte counts for data[start:end]" while reading every byte of
    the file only once.

    The file is cut at every section/segment boundary and running totals are
    kept per cut, so any range between two cuts costs 256 subtractions. If a
    crafted file has more boundaries than MAX_BOUNDARIES, ranges are counted
    directly instead, with a cache for repeated ranges and a total byte budget
    so the work stays proportional to the file size."""

    def __init__(self, data: bytes, offsets):
        self.data = data
        self.view = memoryview(data)
        size = len(data)
        cuts = {0, size}
        for off in offsets:
            if 0 <= off <= size:
                cuts.add(off)
        self.cuts: list[int] | None = None
        self.prefix: list[array] = []
        self.cache: dict[tuple[int, int], list[int]] = {}
        self.budget = 4 * size + (16 << 20)
        self.over_budget = False
        if len(cuts) > MAX_BOUNDARIES:
            return
        self.cuts = sorted(cuts)
        running = array("Q", bytes(8 * 256))
        self.prefix.append(array("Q", running))
        for a, b in zip(self.cuts, self.cuts[1:]):
            for byte, n in Counter(self.view[a:b]).items():
                running[byte] += n
            self.prefix.append(array("Q", running))

    def counts(self, start: int, end: int) -> list[int] | None:
        """Byte counts for data[start:end], or None if over budget."""
        if self.cuts is not None:
            i = bisect.bisect_left(self.cuts, start)
            j = bisect.bisect_left(self.cuts, end)
            if i < len(self.cuts) and j < len(self.cuts) and \
                    self.cuts[i] == start and self.cuts[j] == end:
                hi, lo = self.prefix[j], self.prefix[i]
                return [h - l for h, l in zip(hi, lo)]
        key = (start, end)
        if key not in self.cache:
            if end - start > self.budget:
                self.over_budget = True
                return None
            self.budget -= end - start
            self.cache[key] = _histogram(self.view[start:end])
        return self.cache[key]

    def whole(self) -> list[int]:
        return self.counts(0, len(self.data)) or _histogram(self.view)

    def spend(self, nbytes: int) -> bool:
        """Charge extra work (e.g. randomness tests) against the budget."""
        if nbytes > self.budget:
            self.over_budget = True
            return False
        self.budget -= nbytes
        return True


# --------------------------------------------------------------------------- #
# Report model
# --------------------------------------------------------------------------- #

class ELFError(Exception):
    pass


class Measure(NamedTuple):
    entropy: float | None
    rating: str
    randomness: str | None
    truncated: bool


@dataclass
class Section:
    index: int
    name: str
    type: str
    flags: str
    offset: int
    size: int
    entropy: float | None
    rating: str
    randomness: str | None = None
    expected: str | None = None   # why high entropy is normal here
    truncated: bool = False       # runs past end of file


@dataclass
class Segment:
    index: int
    type: str
    flags: str
    offset: int
    filesz: int
    memsz: int
    entropy: float | None
    rating: str
    randomness: str | None = None
    truncated: bool = False


@dataclass
class Indicator:
    category: str
    weight: int
    message: str
    counted: bool = False   # True for the one indicator per kind that scores


@dataclass
class Report:
    path: str
    size: int
    elf_class: str = ""
    endian: str = ""
    elf_type: str = ""
    machine: str = ""
    entropy: float = 0.0
    rating: str = ""
    randomness: str | None = None
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    regions: list[dict] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    error: str | None = None

    def flag(self, category: str, message: str) -> None:
        self.indicators.append(Indicator(category, WEIGHTS[category], message))

    def finish_scoring(self) -> None:
        best: dict[str, Indicator] = {}
        for ind in self.indicators:
            if ind.category not in best or ind.weight > best[ind.category].weight:
                best[ind.category] = ind
        for ind in best.values():
            ind.counted = ind.weight > 0
        self.score = sum(i.weight for i in best.values())
        self.verdict = verdict(self.score)


def verdict(score: int) -> str:
    if score >= SCORE_PACKED:
        return "likely packed/encrypted"
    if score >= SCORE_SUSPICIOUS:
        return "suspicious"
    return "clean"


# --------------------------------------------------------------------------- #
# ELF parsing
# --------------------------------------------------------------------------- #

class Header(NamedTuple):
    is64: bool
    end: str           # struct byte-order prefix
    e_type: int
    e_machine: int
    phoff: int
    shoff: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


def _sh_flags(flags: int) -> str:
    return "".join(c for bit, c in ((SHF_WRITE, "W"), (SHF_ALLOC, "A"),
                                    (SHF_EXECINSTR, "X"), (SHF_COMPRESSED, "C"))
                   if flags & bit)


def _p_flags(flags: int) -> str:
    return "".join(c if flags & bit else "-"
                   for bit, c in ((PF_R, "R"), (PF_W, "W"), (PF_X, "X")))


def _expected_high(name: str, stype: int, flags: int) -> str | None:
    """Sections whose content is normally high-entropy."""
    if flags & SHF_COMPRESSED or name.startswith(".zdebug") \
            or name == ".gnu_debugdata":
        return "compressed section"
    if stype in (SHT_HASH, SHT_GNU_HASH) or name in (".hash", ".gnu.hash"):
        return "hash table"
    if name.startswith(".note.gnu.build-id"):
        return "build id"
    return None


def _read_header(data: bytes) -> Header:
    if data[:4] != ELF_MAGIC:
        raise ELFError("not an ELF file")
    if len(data) < 52:
        raise ELFError("truncated ELF header")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ELFError(f"invalid EI_CLASS {ei_class}")
    if ei_data not in (1, 2):
        raise ELFError(f"invalid EI_DATA {ei_data}")
    is64 = ei_class == 2
    end = "<" if ei_data == 1 else ">"
    if is64 and len(data) < 64:
        raise ELFError("truncated ELF64 header")
    fmt = end + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    (e_type, e_machine, _ver, _entry, phoff, shoff, _flags, _ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(fmt, data, 16)
    return Header(is64, end, e_type, e_machine, phoff, shoff, phentsize, phnum,
                  shentsize, shnum, shstrndx)


def _read_table(rep: Report, data: bytes, kind: str, offset: int, entsize: int,
                count: int, fmt: str) -> list[tuple]:
    """Unpack `count` fixed-size headers, stopping at the end of the file."""
    need = struct.calcsize(fmt)
    if not offset or entsize < need:
        return []
    if count > MAX_TABLE_ENTRIES:
        rep.flag("malformed", f"{count:,} {kind} headers; only the first "
                 f"{MAX_TABLE_ENTRIES:,} were analysed")
        count = MAX_TABLE_ENTRIES
    rows = []
    for i in range(count):
        off = offset + i * entsize
        if off + need > len(data):
            rep.flag("malformed", f"{kind} header table truncated at entry {i}")
            break
        rows.append(struct.unpack_from(fmt, data, off))
    return rows


def _parse_sections(rep: Report, data: bytes, h: Header) -> list[tuple]:
    """Return raw section header tuples, with names resolved, skipping the
    null entry: (index, name, type, flags, offset, size, info)."""
    fmt = h.end + ("IIQQQQIIQQ" if h.is64 else "IIIIIIIIII")
    need = struct.calcsize(fmt)
    shnum, shstrndx = h.shnum, h.shstrndx
    # Extended numbering: real counts live in section header 0.
    if h.shoff and h.shentsize >= need and h.shoff + need <= len(data) \
            and (shnum == 0 or shstrndx == SHN_XINDEX):
        sh0 = struct.unpack_from(fmt, data, h.shoff)
        if shnum == 0:
            shnum = sh0[5]
        if shstrndx == SHN_XINDEX:
            shstrndx = sh0[6]
    raw = _read_table(rep, data, "section", h.shoff, h.shentsize, shnum, fmt)

    strtab = b""
    if 0 < shstrndx < len(raw):
        s = raw[shstrndx]
        strtab = data[s[4]:s[4] + s[5]]

    def name_at(idx: int) -> str:
        if idx >= len(strtab):
            return ""
        endp = strtab.find(b"\0", idx)
        return strtab[idx:endp if endp != -1 else None].decode("latin-1")

    out = []
    for i, (name_off, stype, flags, _addr, offset, size, _link, info, *_r) in enumerate(raw):
        out.append((i, name_at(name_off) or f"<{i}>", stype, flags, offset,
                    size, info))
    return out


def _parse_segments(rep: Report, data: bytes, h: Header,
                    phnum: int) -> list[tuple]:
    """Return (index, type, flags, offset, filesz, memsz) per program header."""
    fmt = h.end + ("IIQQQQQQ" if h.is64 else "IIIIIIII")
    out = []
    for i, f in enumerate(_read_table(rep, data, "program", h.phoff,
                                      h.phentsize, phnum, fmt)):
        if h.is64:
            p_type, p_flags, p_offset, _va, _pa, p_filesz, p_memsz, _al = f
        else:
            p_type, p_offset, _va, _pa, p_filesz, p_memsz, p_flags, _al = f
        out.append((i, p_type, p_flags, p_offset, p_filesz, p_memsz))
    return out


def analyze(path: str, threshold: float = 7.2, window: int = 0) -> Report:
    with open(path, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ELFError("not a regular file")
        if f.read(4) != ELF_MAGIC:  # don't read a big non-ELF file into memory
            raise ELFError("not an ELF file")
        f.seek(0)
        data = f.read()
    return analyze_bytes(data, path, threshold, window)


def analyze_bytes(data: bytes, path: str = "<memory>", threshold: float = 7.2,
                  window: int = 0) -> Report:
    h = _read_header(data)
    rep = Report(path=path, size=len(data))
    rep.elf_class = "ELF64" if h.is64 else "ELF32"
    rep.endian = "little" if h.end == "<" else "big"
    rep.elf_type = E_TYPES.get(h.e_type, hex(h.e_type))
    rep.machine = E_MACHINES.get(h.e_machine, str(h.e_machine))

    raw_secs = _parse_sections(rep, data, h)
    phnum = h.phnum
    if phnum == PN_XNUM and raw_secs:
        phnum = raw_secs[0][6]  # sh_info of section 0
    raw_segs = _parse_segments(rep, data, h, phnum)

    # Count every byte once, cut at all section/segment boundaries.
    size = len(data)
    offsets = []
    for _i, _n, stype, _f, off, sz, _info in raw_secs:
        if stype != SHT_NOBITS and sz:
            offsets += (off, min(off + sz, size))
    for _i, _t, _f, off, filesz, _m in raw_segs:
        if filesz:
            offsets += (off, min(off + filesz, size))
    counter = ByteCounter(data, offsets)
    rnd_cache: dict[tuple[int, int], str | None] = {}

    def measure(offset: int, length: int) -> Measure:
        if offset >= size:
            return Measure(None, "past end of file", None, True)
        stop = min(offset + length, size)
        counts = counter.counts(offset, stop)
        if counts is None:
            return Measure(None, "skipped (work limit)", None, stop < offset + length)
        ent = entropy_from_counts(counts, stop - offset)
        rnd = None
        if ent >= ENTROPY_HIGH and stop - offset >= CHI2_MIN_BYTES:
            key = (offset, stop)
            if key not in rnd_cache:
                rnd_cache[key] = randomness(memoryview(data)[offset:stop], ent) \
                    if counter.spend(stop - offset) else None
            rnd = rnd_cache[key]
        ent = round(ent, 4)
        return Measure(ent, classify(ent, threshold), rnd, stop < offset + length)

    whole = counter.whole()
    rep.entropy = round(entropy_from_counts(whole, size), 4)
    rep.rating = classify(rep.entropy, threshold)
    if rep.entropy >= ENTROPY_HIGH:
        rep.randomness = randomness(data, rep.entropy)

    for i, name, stype, flags, offset, sz, _info in raw_secs:
        if i == 0 and stype == 0:
            continue
        m = measure(offset, sz) if stype != SHT_NOBITS and sz else \
            Measure(None, "n/a", None, False)
        rep.sections.append(Section(
            index=i, name=name, type=SH_TYPES.get(stype, hex(stype)),
            flags=_sh_flags(flags), offset=offset, size=sz, entropy=m.entropy,
            rating=m.rating, randomness=m.randomness,
            expected=_expected_high(name, stype, flags), truncated=m.truncated))

    for i, p_type, p_flags, offset, filesz, memsz in raw_segs:
        m = measure(offset, filesz) if filesz else Measure(None, "n/a", None, False)
        rep.segments.append(Segment(
            index=i, type=PT_TYPES.get(p_type, hex(p_type)),
            flags=_p_flags(p_flags), offset=offset, filesz=filesz,
            memsz=memsz, entropy=m.entropy, rating=m.rating,
            randomness=m.randomness, truncated=m.truncated))

    if counter.over_budget:
        rep.flag("malformed", "headers describe far more data than the file "
                 "holds; some ranges were not measured")

    if window:
        rep.regions = high_entropy_regions(data, window, threshold)

    _add_indicators(rep, data, h, threshold, counter, whole)
    rep.finish_scoring()
    return rep


# --------------------------------------------------------------------------- #
# Indicators
# --------------------------------------------------------------------------- #

def _rnd_note(rnd: str | None) -> str:
    return {"random": " (random bytes: encrypted?)",
            "structured": " (structured: compressed?)"}.get(rnd, "")


def _check_upx(rep: Report, data: bytes, h: Header) -> None:
    """UPX writes 'UPX!' just after the program headers (l_info) and near the
    end of the file (PackHeader). The string elsewhere, e.g. inside the upx
    tool itself or an antivirus engine, is not a sign of packing."""
    end_ph = h.phoff + h.phentsize * h.phnum
    at_header = UPX_MAGIC in data[end_ph:end_ph + 16] if h.phoff else False
    at_trailer = UPX_MAGIC in data[-64:]
    if at_header or at_trailer:
        where = " and ".join(w for w, ok in (("after program headers", at_header),
                                             ("at end of file", at_trailer)) if ok)
        rep.flag("packer_signature", f"UPX header found ({where})")
    elif UPX_MAGIC in data:
        rep.flag("info", "'UPX!' text present, but not where UPX puts its "
                 "headers (not scored)")


def _merge_ranges(ranges) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, stop in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], stop)
        else:
            merged.append([start, stop])
    return [(a, b) for a, b in merged]


def _strip_ranges(data: bytes, ranges) -> bytes:
    parts, pos = [], 0
    for start, stop in _merge_ranges(ranges):
        if start > pos:
            parts.append(data[pos:start])
        pos = max(pos, stop)
    return b"".join(parts) + data[pos:]


def _entropy_without(counter: ByteCounter, whole: list[int], size: int,
                     ranges) -> float:
    """Entropy of the file with `ranges` left out, by subtracting their byte
    counts instead of copying the remaining bytes."""
    counts, total = list(whole), size
    for start, stop in _merge_ranges(ranges):
        part = counter.counts(start, stop)
        if part is None:   # over the work budget: fall back to copying
            rest = _strip_ranges(counter.data, ranges)
            return shannon_entropy(rest)
        counts = [c - p for c, p in zip(counts, part)]
        total -= stop - start
    return entropy_from_counts(counts, total)


def _add_indicators(rep: Report, data: bytes, h: Header, threshold: float,
                    counter: ByteCounter, whole: list[int]) -> None:
    _check_upx(rep, data, h)

    if rep.elf_type in ("EXEC", "DYN") and not rep.sections:
        # Also true for a table holding only the null entry.
        rep.flag("no_sections", "no section headers (stripped hard or packed)")

    data_hot = []   # high-entropy non-code sections
    for s in rep.sections:
        if s.truncated:
            rep.flag("past_eof", f"section {s.name} extends past end of file")
        if s.entropy is None or s.expected or s.entropy < threshold:
            continue
        if "X" in s.flags:
            rep.flag("exec_entropy", f"executable section {s.name} entropy "
                     f"{s.entropy:.2f}" + _rnd_note(s.randomness))
            if s.randomness == "random":
                rep.flag("random_code", f"executable section {s.name} bytes "
                         "are evenly spread, like encrypted data")
        elif s.size >= 1024:
            data_hot.append(s)

    # Whole-file entropy, leaving out sections that are meant to be
    # high-entropy (compressed debug info, hash tables). If what remains is
    # only high because of embedded data sections, that's reported once, on
    # those sections, instead of scoring the same bytes twice.
    size = len(data)
    expected = [(s.offset, min(s.offset + s.size, size)) for s in rep.sections
                if s.expected and s.entropy is not None]
    if expected:
        rest_ent = _entropy_without(counter, whole, size, expected)
        label = f"entropy {rest_ent:.2f} excluding compressed/hash sections"
    else:
        rest_ent = rep.entropy
        label = f"whole-file entropy {rest_ent:.2f}"
    explained = False
    if rest_ent >= threshold:
        if data_hot:
            hot = [(s.offset, min(s.offset + s.size, size)) for s in data_hot]
            explained = _entropy_without(counter, whole, size,
                                         expected + hot) < threshold
        if not explained:
            rnd = rep.randomness
            if expected:
                rest = _strip_ranges(data, expected)
                rnd = randomness(rest, rest_ent)
            rep.flag("file_entropy", f"{label} >= {threshold}" + _rnd_note(rnd))
    for s in data_hot:
        note = " (accounts for the high whole-file entropy)" if explained else ""
        rep.flag("data_entropy", f"section {s.name} entropy {s.entropy:.2f}"
                 + _rnd_note(s.randomness) + note)

    loads = [g for g in rep.segments if g.type == "LOAD"]
    for g in rep.segments:
        if g.truncated:
            on_disk = max(0, min(g.filesz, rep.size - g.offset))
            rep.flag("past_eof", f"{g.type} segment #{g.index} extends past "
                     f"end of file ({g.filesz:,} bytes declared, "
                     f"{on_disk:,} present)")
    for g in loads:
        if g.entropy is not None and "X" in g.flags and g.entropy >= threshold:
            rep.flag("exec_entropy", f"executable LOAD segment #{g.index} "
                     f"entropy {g.entropy:.2f}" + _rnd_note(g.randomness))
            if g.randomness == "random":
                rep.flag("random_code", f"executable LOAD segment #{g.index} "
                         "bytes are evenly spread, like encrypted data")
        if "W" in g.flags and "X" in g.flags:
            rep.flag("rwx_segment",
                     f"LOAD segment #{g.index} is writable+executable (RWX)")
        if g.filesz and g.memsz / g.filesz > 10 and "X" in g.flags:
            rep.flag("runtime_unpack", f"LOAD segment #{g.index} memsz is "
                     f"{g.memsz // g.filesz}x filesz (unpacks at runtime?)")

    if rep.segments and not rep.sections and len(loads) <= 2 \
            and not any(g.type in ("INTERP", "DYNAMIC") for g in rep.segments):
        rep.flag("sectionless_static",
                 "static, sectionless binary with few LOAD segments")

    # Data appended after the last mapped byte (overlay).
    covered = 0
    for g in rep.segments:
        if g.filesz and g.entropy is not None:
            covered = max(covered, g.offset + g.filesz)
    for s in rep.sections:
        if s.size and s.type != "NOBITS" and s.entropy is not None:
            covered = max(covered, s.offset + s.size)
    overlay = len(data) - covered
    if covered and overlay > 4096:
        tail = memoryview(data)[covered:]
        tail_ent = shannon_entropy(tail)
        if tail_ent >= threshold:
            rep.flag("overlay", f"{overlay:,} bytes of overlay data after last "
                     f"section/segment (entropy {tail_ent:.2f})"
                     + _rnd_note(randomness(tail, tail_ent)))


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def safe_name(text: str) -> str:
    """Escape anything but printable ASCII (section names come from the file
    and could carry terminal escape sequences)."""
    return "".join(c if " " <= c <= "~" else f"\\x{ord(c):02x}" for c in text)


def safe_path(text: str) -> str:
    """Escape control characters in a path, keep normal Unicode."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}"
                   if ord(c) < 256 else f"\\u{ord(c):04x}" for c in text)


def _bar(entropy: float | None, width: int = 20) -> str:
    if entropy is None:
        return " " * width
    filled = int(round(entropy / 8.0 * width))
    return "#" * filled + "." * (width - filled)


def _note(rating: str, rnd: str | None, extra: str | None = None,
          truncated: bool = False) -> str:
    parts = [rating]
    if rnd:
        parts.append(rnd)
    if extra:
        parts.append(f"expected: {extra}")
    if truncated and rating != "past end of file":
        parts.append("TRUNCATED")
    return ", ".join(parts)


def print_report(rep: Report, verbose: bool) -> None:
    print("=" * 78)
    print(f"File:     {safe_path(rep.path)}")
    if rep.error:
        print(f"Error:    {rep.error}")
        return
    print(f"Format:   {rep.elf_class} {rep.endian}-endian {rep.elf_type} "
          f"({rep.machine}), {rep.size:,} bytes")
    print(f"Entropy:  {rep.entropy:.4f}  [{_bar(rep.entropy)}]  "
          f"{_note(rep.rating, rep.randomness)}")

    if rep.sections:
        print("\nSections:")
        print(f"  {'#':>3} {'name':<22} {'flg':<4} {'size':>10}  {'entropy':>7}  "
              f"{'':20}  rating")
        for s in rep.sections:
            if not verbose and (s.entropy is None or s.size < 64):
                continue
            ent = f"{s.entropy:.4f}" if s.entropy is not None else "   -   "
            print(f"  {s.index:>3} {safe_name(s.name)[:22]:<22} {s.flags:<4} "
                  f"{s.size:>10,}  {ent:>7}  {_bar(s.entropy)}  "
                  f"{_note(s.rating, s.randomness, s.expected, s.truncated)}")

    if rep.segments:
        print("\nSegments:")
        print(f"  {'#':>3} {'type':<14} {'flg':<3} {'filesz':>10}  {'entropy':>7}  "
              f"{'':20}  rating")
        for g in rep.segments:
            if not verbose and g.type != "LOAD":
                continue
            ent = f"{g.entropy:.4f}" if g.entropy is not None else "   -   "
            print(f"  {g.index:>3} {g.type:<14} {g.flags:<3} {g.filesz:>10,}  "
                  f"{ent:>7}  {_bar(g.entropy)}  "
                  f"{_note(g.rating, g.randomness, truncated=g.truncated)}")

    if rep.regions:
        print("\nHigh-entropy regions:")
        for r in rep.regions:
            rnd = f", {r['randomness']}" if r["randomness"] else ""
            print(f"  0x{r['offset']:08x} - 0x{r['offset'] + r['size']:08x}  "
                  f"({r['size']:,} bytes, entropy {r['entropy']:.4f}, "
                  f"max {r['max_entropy']:.4f}{rnd})")

    print(f"\nVerdict:  {rep.verdict.upper()}  (score {rep.score})")
    for i in rep.indicators:
        pts = f"+{i.weight}" if i.counted else "  "
        print(f"  {pts:>3}  {safe_name(i.message)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def iter_targets(paths: list[str], recursive: bool, errors: list[str]):
    """Yield (path, explicit). Directory scans only yield regular files, skip
    symlinks (the files they point to are scanned under their own name) and
    skip hard links to a file already seen."""
    seen: set[tuple[int, int]] = set()

    def fresh(st: os.stat_result) -> bool:
        if not st.st_ino:          # filesystem without inode numbers
            return True
        key = (st.st_dev, st.st_ino)
        if key in seen:
            return False
        seen.add(key)
        return True

    def from_dir(entries):
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                st = entry.stat(follow_symlinks=False)
                if not st.st_ino:
                    # Windows directory listings leave the file ID at 0;
                    # a full stat fills it in, so hard links are caught.
                    st = os.stat(entry.path, follow_symlinks=False)
            except OSError as e:
                errors.append(f"{entry.path}: {e.strerror or e}")
                continue
            if stat.S_ISREG(st.st_mode) and fresh(st):
                yield entry.path

    for p in paths:
        if os.path.isdir(p):
            if recursive:
                def onerror(e, _p=p):
                    errors.append(f"{e.filename or _p}: {e.strerror or e}")
                for root, _dirs, _files in os.walk(p, onerror=onerror):
                    try:
                        with os.scandir(root) as it:
                            entries = sorted(it, key=lambda e: e.name)
                    except OSError as e:
                        errors.append(f"{root}: {e.strerror or e}")
                        continue
                    for path in from_dir(entries):
                        yield path, False
            else:
                try:
                    with os.scandir(p) as it:
                        entries = sorted(it, key=lambda e: e.name)
                except OSError as e:
                    errors.append(f"{p}: {e.strerror or e}")
                    continue
                for path in from_dir(entries):
                    yield path, False
        else:
            try:
                fresh(os.stat(p))
            except OSError:
                pass
            yield p, True  # explicitly named: report if it's not ELF


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:  # never crash on characters the console can't encode
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="Measure Shannon entropy of ELF files, sections and segments.")
    ap.add_argument("paths", nargs="+", help="ELF files or directories")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="recurse into directories")
    ap.add_argument("-t", "--threshold", type=float, default=7.2,
                    help="entropy considered packed/encrypted (default 7.2)")
    ap.add_argument("-w", "--window", type=int, default=0, metavar="BYTES",
                    help="sliding-window size to locate high-entropy regions "
                         f"(0 = off, otherwise at least {MIN_WINDOW}; 1024 "
                         "is a good start)")
    ap.add_argument("-m", "--min-score", type=int, default=SCORE_SUSPICIOUS,
                    help="score at which the exit code becomes 2 "
                         f"(default {SCORE_SUSPICIOUS})")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show all sections/segments, not just the meaningful ones")
    ap.add_argument("-s", "--summary", action="store_true",
                    help="one line per file")
    args = ap.parse_args(argv)

    if not 0 < args.threshold <= 8:
        ap.error("--threshold must be between 0 and 8")
    if args.window and args.window < MIN_WINDOW:
        ap.error(f"--window must be 0 or at least {MIN_WINDOW} bytes "
                 "(smaller windows can't measure entropy near 8.0)")
    if args.window and expected_random_entropy(args.window) < args.threshold + 0.05:
        print(f"warning: random data only averages "
              f"{expected_random_entropy(args.window):.2f} bits/byte in a "
              f"{args.window}-byte window, close to the {args.threshold} "
              "threshold; use a larger --window for reliable regions",
              file=sys.stderr)

    reports: list[Report] = []
    walk_errors: list[str] = []
    for path, explicit in iter_targets(args.paths, args.recursive, walk_errors):
        if not explicit and not is_elf(path):
            continue
        try:
            rep = analyze(path, args.threshold, args.window)
        except (OSError, ELFError, struct.error, MemoryError) as e:
            rep = Report(path=path, size=0,
                         error=getattr(e, "strerror", None) or str(e))
        reports.append(rep)

        if args.json:
            continue
        if args.summary:
            if rep.error:
                print(f"{'ERROR':<8} {'-':>5}  {'-':>6}  {safe_path(path)}: "
                      f"{rep.error}")
            else:
                label = {"clean": "ok", "suspicious": "SUSPECT"}.get(
                    rep.verdict, "PACKED")
                print(f"{label:<8} {rep.score:>5}  {rep.entropy:.4f}  "
                      f"{safe_path(path)}")
        else:
            print_report(rep, args.verbose)

    for err in walk_errors:
        print(f"warning: skipped {safe_path(err)}", file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(r) for r in reports], indent=2))
    elif not reports:
        print("No ELF files found.", file=sys.stderr)

    if any(not r.error and r.score >= args.min_score for r in reports):
        return 2
    had_error = any(r.error for r in reports) or bool(walk_errors)
    return 1 if had_error or not reports else 0


if __name__ == "__main__":
    sys.exit(main())
