# Test Fixtures

## brew_agent_xor_region.bin

**Source**: DPRK malware sample (homabrews.org campaign, 2026)
**Size**: 180,224 bytes (176 KB)
**Offset range**: 0x20000 - 0x4c000 from original binary
**MD5**: `1d824b1b3f73ec32187106641dc7274e`

### What is this?

This is a **sanitized, non-executable data region** extracted from the brew_agent malware sample. It contains XOR-encrypted strings but does not include any executable code.

### Why use this instead of the full binary?

1. **Safety**: Not executable - just data
2. **Size**: 176 KB vs 362 KB (50% smaller)
3. **Focus**: Contains only the regions with XOR strings we care about
4. **Portability**: Easier to include in test suite

### What XOR strings does it contain?

Key indicators from the DPRK cryptocurrency theft campaign:
- `set volume output muted true/false` - AppleScript commands to mute audio
- Cryptocurrency wallet paths (Telegram, Exodus, Atomic, etc.)
- `osascript` commands for file manipulation
- Suspicious paths in Application Support directories

### XOR Key

```
fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf
```

### How was it created?

```bash
# Extract bytes 0x20000-0x4c000 from brew_agent
dd if=brew_agent of=brew_agent_xor_region.bin bs=1 skip=$((0x20000)) count=$((0x4c000 - 0x20000))
```

### Expected test results

When scanned with the XOR key, should find:
- Both "muted true" and "muted false" variants
- 100+ XOR-encrypted strings total
- No byte-range overlaps
- No garbage suffixes (null-terminated cleanly)
- Proper classification (ShellCmd, SuspiciousPath, etc.)

### Attribution

Original sample: DPRK APT, homabrews.org campaign (January 2026)
Analysis: Claude Code test suite

## npm-charcode-rot-packer.js

A trimmed capture of the packer used by the compromised `awaitly-*` / `autotel-*`
npm releases (`compromised_lib/awaitly-libsql/22.0.1` and siblings). The
original `package/index.js` is 4.5 MB; this keeps the authentic wrapper and
enough of the payload to reach the AES staging call.

The recipe is three layers deep:

  [char codes].map(c => String.fromCharCode(c)).join("")   ->  rotated text
  Caesar shift of 6                                        ->  JavaScript
  eval                                                     ->  stage 2

Stage 2 then AES-128-GCM-decrypts further blobs with a hardcoded key, and one of
those downloads the Bun runtime and runs the real payload outside Node.

It is a regression fixture for two things that both had to be true for any of it
to be visible: the array spelling of the charcode recipe (the direct
`eval(String.fromCharCode(...))` matcher does not see it), and recovering the
shift rather than assuming ROT13.
