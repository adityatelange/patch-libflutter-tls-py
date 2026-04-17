#!/usr/bin/env python3
"""
Patch a libflutter.so file to disable Flutter's ssl_verify_peer_cert function.
GitHub: https://github.com/adityatelange/patch-flutter-tls

Usage:
  python3 patch_libflutter_tls.py -i libflutter.so -o libflutter_patched.so

Notes:
 - Supports x86 (i386) and x86_64 without additional dependencies.
 - For ARM/ARM64 payload assembly the script tries to use Keystone (keystone-engine).
   Install with: pip install keystone-engine
 - The script searches for the same patterns that the original Frida script used.
 - It patches every match found in the binary and writes a new file.
"""

import argparse
import struct
import sys
from pathlib import Path

# Try to import Keystone for assembling ARM/ARM64/ARMv7/Thumb payloads.
KS = None
try:
    from keystone import Ks, KS_ARCH_X86, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_32, KS_MODE_64, KS_MODE_LITTLE_ENDIAN, KS_MODE_ARM, KS_MODE_THUMB
    KS = True
except Exception:
    KS = False

# Patterns taken from https://github.com/NVISOsecurity/disable-flutter-tls-verification/blob/4ac95edba90cf48bb8298e6538b6f1e923926dc6/disable-flutter-tls.js#L26-L48
ANDROID_PATTERNS = {
    "arm64": [
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
        "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
        "FF C3 01 D1 FD 7B 01 A9 6A A1 0B 94 08 0A 80 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9"
    ],
    "arm": [
        "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
    ],
    "x64": [
        "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB"
    ],
    "x86": [
        "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01"
    ],
}

# Architecture mapping from ELF e_machine to our pattern keys
EM_TO_ARCH = {
    3: "x86",        # EM_386
    62: "x64",       # EM_X86_64
    40: "arm",       # EM_ARM
    183: "arm64",    # EM_AARCH64
}

def parse_pattern(pattern_str):
    """
    Convert a pattern string like "F? 0F 1C F8" into (values, masks) arrays.
    Each token is a byte represented by two hex nibbles, with '?' wildcard possible in either nibble.
    Returns bytes objects: vals, masks
    """
    tokens = pattern_str.split()
    vals = bytearray()
    masks = bytearray()
    for tok in tokens:
        if len(tok) != 2:
            raise ValueError("Unexpected token length in pattern: %r" % tok)
        hi, lo = tok[0], tok[1]
        val = 0
        mask = 0
        # high nibble
        if hi == '?':
            mask_hi = 0x0
            val_hi = 0x0
        else:
            mask_hi = 0xF
            val_hi = int(hi, 16)
        # low nibble
        if lo == '?':
            mask_lo = 0x0
            val_lo = 0x0
        else:
            mask_lo = 0xF
            val_lo = int(lo, 16)
        mask = (mask_hi << 4) | mask_lo
        val = (val_hi << 4) | val_lo
        vals.append(val)
        masks.append(mask)
    return bytes(vals), bytes(masks)

def find_all_matches(data, vals, masks):
    """
    Naive search for masked pattern matches in data.
    Returns list of offsets.
    """
    matches = []
    plen = len(vals)
    if plen == 0 or len(data) < plen:
        return matches
    # view to speed up indexing
    mv = memoryview(data)
    for i in range(0, len(data) - plen + 1):
        ok = True
        # compare bytes
        for j in range(plen):
            db = mv[i+j]
            mask = masks[j]
            if (db & mask) != (vals[j] & mask):
                ok = False
                break
        if ok:
            matches.append(i)
    return matches

def read_elf_machine(data):
    """
    Return ELF e_machine value (None if not ELF).
    """
    if len(data) < 20:
        return None
    # ELF magic
    if data[0:4] != b'\x7fELF':
        return None
    ei_class = data[4]
    # e_machine is at offset 18 (2 bytes)
    e_machine = struct.unpack_from('<H', data, 18)[0]
    return e_machine

def assemble_patch(arch_key, thumb=False):
    """
    Prepare a small machine-code stub that returns 0 for the function, for each arch.
    Returns bytes of the stub.
    For ARM/ARM64 this uses Keystone if available.
    """
    # x86 (32-bit): mov eax, 0; ret
    if arch_key == "x86":
        return b'\xB8\x00\x00\x00\x00\xC3'  # mov eax,0; ret
    # x64: xor eax,eax; ret
    if arch_key == "x64":
        return b'\x31\xc0\xc3'  # xor eax,eax; ret
    # ARM32
    if arch_key == "arm":
        if not KS:
            raise RuntimeError("Keystone not available: ARM patching requires keystone-engine (pip install keystone-engine)")
        # Use ARM or THUMB depending on 'thumb' flag
        asm = "mov r0, #0; bx lr" if not thumb else "mov r0, #0; bx lr"
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN if not thumb else KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
        encoding, _ = ks.asm(asm)
        return bytes(encoding)
    # ARM64
    if arch_key == "arm64":
        if not KS:
            raise RuntimeError("Keystone not available: ARM64 patching requires keystone-engine (pip install keystone-engine)")
        asm = "mov w0, #0; ret"
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, _ = ks.asm(asm)
        return bytes(encoding)
    raise ValueError("Unsupported arch key: %r" % arch_key)

def arch_nop_bytes(arch_key):
    """
    Return a NOP byte sequence for padding for the arch.
    """
    if arch_key == "x86" or arch_key == "x64":
        return b'\x90'
    if arch_key == "arm":
        # ARM NOP encoding: 0xE1A00000 -> little-endian bytes 00 00 A0 E1
        return b'\x00\x00\xa0\xe1'
    if arch_key == "arm64":
        # ARM64 NOP encoding: 0x1F2003D5 -> little-endian bytes D5 03 20 1F
        return b'\xd5\x03\x20\x1f'
    return b'\x00'

def patch_file(input_path: Path, output_path: Path, force_arch=None, thumb=False):
    data = input_path.read_bytes()
    e_machine = read_elf_machine(data)
    arch_key = None
    if force_arch:
        arch_key = force_arch
        print("[*] Forcing arch key: %s" % arch_key)
    else:
        if e_machine is None:
            print("[!] Input not recognized as ELF - defaulting to x64 patterns.")
            arch_key = "x64"
        else:
            arch_key = EM_TO_ARCH.get(e_machine)
            if arch_key is None:
                print("[!] Unknown ELF machine %d; defaulting to x64 patterns." % e_machine)
                arch_key = "x64"
            else:
                print("[*] Detected architecture: %s (e_machine=%d)" % (arch_key, e_machine))

    patterns = ANDROID_PATTERNS.get(arch_key)
    if not patterns:
        raise RuntimeError("No patterns available for arch %r" % arch_key)

    patched = bytearray(data)
    total_matches = 0
    for pat in patterns:
        vals, masks = parse_pattern(pat)
        matches = find_all_matches(data, vals, masks)
        if not matches:
            continue
        print("[+] Pattern matched (%d hits) for pattern: %s" % (len(matches), pat))
        for off in matches:
            total_matches += 1
            print("    - patching offset 0x%X" % off)
            try:
                stub = assemble_patch(arch_key, thumb=thumb)
            except Exception as e:
                print("    [!] Cannot assemble patch for arch %s: %s" % (arch_key, e))
                print("    [!] Skipping this match.")
                continue
            # Overwrite at offset; preserve file length. Pad with NOPs if stub is shorter than pattern length.
            target_len = len(vals)
            write_len = len(stub)
            if write_len > target_len:
                # stub is larger than matched area; still write stub but warn (may overwrite more)
                print("    [!] Stub (%d bytes) larger than pattern match length (%d). Will overwrite %d bytes." %
                      (write_len, target_len, write_len))
                # ensure we don't go beyond file end
                end = off + write_len
                if end > len(patched):
                    raise RuntimeError("Patch would overflow file size.")
                patched[off:off+write_len] = stub
            else:
                # write stub then pad rest with NOPs
                patched[off:off+write_len] = stub
                pad = target_len - write_len
                if pad > 0:
                    nop = arch_nop_bytes(arch_key)
                    # repeat NOP to fill pad, respecting instruction size (for ARM make pad multiple of 4)
                    if arch_key in ("arm", "arm64"):
                        # round pad up to 4
                        if pad % 4 != 0:
                            pad += (4 - (pad % 4))
                    patched[off+write_len:off+write_len+pad] = nop * (pad // len(nop))
    if total_matches == 0:
        print("[!] No matches were found. The output file will still be written but unchanged.")
    output_path.write_bytes(bytes(patched))
    print("[+] Wrote patched file to:", str(output_path))
    print("[+] Total patched matches:", total_matches)

def main():
    ap = argparse.ArgumentParser(description="Patch libflutter.so to disable Flutter TLS verification.")
    ap.add_argument("-i", "--input", required=True, help="Input .so file (libflutter.so)")
    ap.add_argument("-o", "--output", required=False, help="Output patched .so file (default: <input>.patched.so)")
    ap.add_argument("--arch", required=False, choices=["x86", "x64", "arm", "arm64"], help="Force architecture (optional)")
    ap.add_argument("--thumb", action="store_true", help="If patching ARM, assemble thumb variant (if using keystone)")
    args = ap.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        print("Input file not found:", args.input)
        sys.exit(1)
    out = Path(args.output) if args.output else inp.with_suffix(inp.suffix + ".patched.so")
    try:
        patch_file(inp, out, force_arch=args.arch, thumb=args.thumb)
    except Exception as e:
        print("[!] Error:", e)
        sys.exit(2)

if __name__ == "__main__":
    main()
