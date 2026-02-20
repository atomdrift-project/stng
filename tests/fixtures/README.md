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
