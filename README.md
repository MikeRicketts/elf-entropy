# elf-entropy

[![tests](https://github.com/MikeRicketts/elf-entropy/actions/workflows/tests.yml/badge.svg)](https://github.com/MikeRicketts/elf-entropy/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

Detect packed, compressed or encrypted Linux ELF binaries by measuring their
**Shannon entropy**: for the whole file, every section, every program segment,
and (optionally) a sliding window. The result is a score with a verdict:
clean, suspicious, or likely packed.

It's a single Python file with no dependencies. It runs on Linux, macOS and
Windows, and reads 32/64-bit and little/big-endian ELF files.

## Why entropy?

Entropy measures how unpredictable a file's bytes are, from 0 to 8 bits per
byte. Normal machine code has a lot of repetition (common opcodes, registers,
zero padding) and lands around **5–6.5**. Compressed or encrypted data looks
almost random and lands near **8.0**. Packers like UPX compress the real
program and add a small unpacking stub. That leaves a binary whose code is
almost all high-entropy, which is easy to see and a common red flag in
malware analysis.

| Entropy   | Rating     | Typical content                          |
|-----------|------------|------------------------------------------|
| < 5.0     | low        | text, tables, zero padding               |
| 5.0 – 6.8 | code-like  | compiled machine code                    |
| 6.8 – 7.2 | high       | compressed-looking                       |
| ≥ 7.2     | very high  | packed, compressed or encrypted          |

## Usage

```bash
python elf_entropy.py /bin/ls                      # full report
python elf_entropy.py -s -r /usr/bin               # one line per file, recursive
python elf_entropy.py sample.elf -w 1024           # find high-entropy byte ranges
python elf_entropy.py sample.elf --json > out.json # machine-readable
```

| Option | Meaning |
|---|---|
| `-r`, `--recursive` | scan directories recursively (skips symlinks, devices and pipes) |
| `-s`, `--summary` | one line per file: verdict, score, entropy, path |
| `-v`, `--verbose` | show every section and segment, including tiny ones |
| `-w BYTES` | sliding-window scan; `0` = off, otherwise at least 512 (1024 is a good start) |
| `-t`, `--threshold` | entropy treated as "very high" (default 7.2) |
| `-m`, `--min-score` | score at which the exit code becomes 2 (default 3) |
| `-j`, `--json` | JSON output |

**Exit codes:** `0` all files below `--min-score` · `1` error, unreadable path
or no ELF files · `2` at least one file at or above `--min-score`. That makes
it easy to use in scripts and CI pipelines.

## Example

A normal binary (trimmed):

```
File:     /bin/ls
Format:   ELF64 little-endian DYN (x86-64), 142,312 bytes
Entropy:  5.9349  [###############.....]  code-like

Sections:
    # name                   flg        size  entropy                        rating
    5 .gnu.hash              A            80   4.8845  ############........  low, expected: hash table
   16 .text                  AX       82,370   6.2878  ################....  code-like
   18 .rodata                A        20,847   5.3438  #############.......  code-like
   26 .data                  WA          632   1.2009  ###.................  low

Segments:
    # type           flg     filesz  entropy                        rating
    3 LOAD           R-X     85,825   6.2839  ################....  code-like

Verdict:  CLEAN  (score 0)
```

The same binary after `upx ls -o ls_upx`:

```
File:     ./ls_upx
Format:   ELF64 little-endian DYN (x86-64), 63,064 bytes
Entropy:  7.8843  [####################]  very high, structured

Segments:
    # type           flg     filesz  entropy                        rating
    0 LOAD           RW-      4,096   7.2247  ##################..  very high, structured
    1 LOAD           R-X     62,117   7.8889  ####################  very high, structured

Verdict:  LIKELY PACKED/ENCRYPTED  (score 15)
   +5  UPX header found (after program headers and at end of file)
   +2  no section headers (stripped hard or packed)
   +3  whole-file entropy 7.88 >= 7.2 (structured: compressed?)
   +4  executable LOAD segment #1 entropy 7.89 (structured: compressed?)
   +1  static, sectionless binary with few LOAD segments
```

## How the score works

Each kind of warning sign adds points. Only the strongest sign of each kind
counts, so one high-entropy blob is never scored twice.

| Points | Sign |
|---|---|
| 5 | UPX header at the location UPX writes it (the string elsewhere is ignored) |
| 4 | executable section or LOAD segment with very high entropy |
| 3 | whole-file entropy very high, not explained by a single data section |
| 2 | no section headers · writable+executable segment · segment much larger in memory than on disk · headers pointing past end of file · high-entropy data appended after the program |
| 1 | executable bytes that look *random* rather than compressed · high-entropy data section · static binary with no sections · malformed headers |

**0–2** clean · **3–4** suspicious · **5+** likely packed/encrypted

Sections whose content is *meant* to be high-entropy are marked "expected"
and don't count: compressed debug info (`SHF_COMPRESSED`, `.zdebug_*`,
`.gnu_debugdata`), hash tables (`.gnu.hash`, `.hash`) and build IDs.

### Compressed or encrypted?

Both score close to 8.0, so entropy alone can't separate them. For
high-entropy data the tool also runs a **chi-square test** on the byte
distribution. Encrypted (or random) bytes are spread almost perfectly evenly;
compressed output usually isn't. The test only uses 4 KB blocks that are
themselves near 8.0, so padding mixed into the data doesn't skew it. Results
show as `random` or `structured`.

## Built for untrusted input

The tool is meant to be pointed at suspicious files, so:

- every header is bounds-checked before it's read, and truncated or
  malformed tables are reported instead of crashing the scan;
- the work done is bounded by the file size, however the headers are crafted.
  Each byte is counted once, with running totals per section boundary, and a
  hard work budget covers the rest. A file with 65,535 overlapping section
  headers is analysed in about two seconds;
- section names are escaped before printing, so a crafted name can't inject
  terminal escape sequences or crash the output;
- recursive scans only open regular files, so pipes and device files can't
  hang them, and symlinks and hard links aren't scanned twice.

## Accuracy

Tested against a full Ubuntu 24.04 install (`/usr/bin`, `/usr/sbin`,
`/usr/lib`, `/usr/libexec`, `/opt`: 4,448 ELF files): **no false positives**.
That includes libraries that embed compressed data, such as `kheaders.ko` and
gconv's `GB18030.so`, and the `upx` binary itself. Every UPX-packed binary
tested (default, `--best`, `--lzma`; 32- and 64-bit) scored 10–17, including
copies with the `UPX!` markers wiped.

Known limits:

- entropy flags *packing*, not *maliciousness*. Plenty of legitimate software
  is packed, and malware doesn't have to be;
- the `random`/`structured` label is a hint. Strong compressors such as LZMA
  produce output that can look random, and blocks under ~10 KB don't give the
  test enough data;
- a packer that keeps its payload in a normal data section and leaves the code
  readable only scores 1 point for that section. Use `-w` and the section
  table to look closer;
- the `-w` scan can't work with tiny windows: 256 random bytes only average
  ~7.3 bits/byte, so windows under 512 bytes are rejected.

## Running the tests

```bash
python test_elf_entropy.py -v
```

The tests build ELF files in memory, so they need no sample binaries. On Linux
they also check `/bin/ls` and, if `upx` is installed, a UPX-packed copy of it.
GitHub Actions runs them on Linux and Windows for Python 3.9–3.14.

## License

[MIT](LICENSE)
