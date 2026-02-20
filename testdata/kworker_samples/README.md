# KWorker Process Spoofing Malware Sample

This directory contains test samples for detecting character-by-character string assembly patterns used by the `kworker_pretenders` malware family.

## Sample: kworker_obfuscated_1

Binary ELF x64 compiled with GCC 10.2.1, linked against libcurl-gnutls.

### Obfuscation Technique

The malware uses x86-64 instruction-level character assembly to hide critical strings:
- Strings are NOT stored in the `.rodata` section
- Instead, they're constructed byte-by-byte at runtime using `mov` instructions
- Each character is loaded as an immediate value to memory/registers

### Hidden Strings Reconstructed

From static analysis of x86-64 assembly sequences:

1. **Process Name Spoofing**: `[kworker]`
   - Fake process name to masquerade as legitimate kernel worker thread
   - Used via `prctl(PR_SET_NAME)`
   - Found in assembly sequences with patterns like:
     - `[k` `wo` `rk` `er` `]` loaded separately

2. **Persistence Paths** (Shell initialization):
   - `/etc/profile.d/` + filename patterns
   - `~/.bashrc` 
   - `/etc/bash.bashrc`
   - Used to inject code into shell startup files

3. **Temporary/Lock Files**:
   - `/tmp/.ICE-unix.pid`
   - `/tmp/.X11-unix/`
   - Standard malware locking/communication mechanisms

4. **C2 Communication**:
   - Domain: `http://cunilbs.aemrg` (or similar)
   - Uses libcurl for network communication
   - Character-by-character URL assembly

### Detection Patterns

The malware uses these assembly patterns repeatedly:

```x86asm
; Loading a character with high byte, low byte pattern
mov r/m, 0x6b77      ; 'k' 'w' (reversed due to little-endian)
mov r/m, 0x726f      ; 'r' 'o'  
; etc...
```

The key characteristic is **immediate values that decode to valid ASCII characters** when:
- Read as little-endian byte pairs/quads
- Combined across sequential `mov` instructions targeting the same memory location or registers

### Mitigation/Detection

1. **Stack String Extraction**: Monitor construction of strings via immediate values
2. **Behavioral Flags**: Flag strings like `[kworker]`, suspicious paths `/etc/profile.d/`, and `.ICE-unix` patterns
3. **Statistical Analysis**: Detect frequent 2-4 byte movs with ASCII-decodable immediates
4. **Dynamic Analysis**: Monitor `prctl()` calls changing process names to kernel-like names

### Current Detection Status (stng v0.1.0)

**Stack String Extraction**: ✓ WORKING
- Successfully extracts `.ICE` (part of `/tmp/.ICE-unix.pid`)
- Located at file offset 0x2e5b via `mov dword` instruction (C7 opcode)
- Marked as `StackString` type with High severity

**Suspicious Path Detection**: ✓ WORKING
- Successfully identifies `/proc/self/exe` as suspicious
- Marked as `SuspiciousPath` type with High severity

**Library Indicators**: ✓ DETECTED
- libcurl-gnutls.so.4 (network communication via curl)
- Standard libc functions (fork, sprintf, etc.)

**Known Limitations**:
- Partial string fragments not merged across instructions (e.g., `kworker` might split across multiple 2-byte writes)
- Short strings <4 bytes filtered out by default garbage filter
- Character-by-character construction in `.text` section requires instruction-level analysis

### Test Results

From `tests/test_kworker_obfuscation.rs`:
```
Total strings extracted: 83
Suspicious strings found: 2
Stack-constructed strings found: 1

✓ Found tmp file keyword: .ICE
✓ Found C2 keyword: curl
```

**Recommendations**:
1. For complete string recovery, use `stng --unfiltered` to preserve short fragments
2. For C2 analysis, monitor libcurl function usage patterns
3. For persistence detection, look for profile.d/ and bashrc path patterns in assembly
4. Consider radare2 integration (`stng --r2`) for instruction-level analysis of mov patterns

### Files

- `kworker_obfuscated_1` - Packed binary (23,256 bytes)
  - ELF x64
  - SHA256: `caa69b10b0bfca561dec90cbd1132b6dcb2c8a44d76a272a0b70b5c64776ff6c`
  - Linked against: libcurl-gnutls, libc
  - Compiled: GCC 10.2.1
  - Test case: `tests/test_kworker_obfuscation.rs`

