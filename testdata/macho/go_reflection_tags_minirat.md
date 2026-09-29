# Go reflection tags and multiline literals

Actual x86_64 Mach-O sample, SHA-256 `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d`.
Go 1.25.8, module `alibaba.xyz/minirat`. Hostile remote-command/file-transfer agent; analyze statically only.

Expected extraction:
- Reflection tag `json:"iv"` at file offset `0x33aaeb` (9 bytes).
- Reflection tag `json:"ciphertext"` at `0x34551b` (17 bytes).
- Complete 415-byte LaunchAgent XML literal at `0x2cc5d4`, including ProgramArguments `/bin/zsh`, `-i`, and RunAtLoad.

The tags are reached via __DATA_CONST.__typelink and struct-field Name metadata, not found by scanning arbitrary bytes. The XML already has an instruction-referenced pointer and length; embedded line breaks must not cause the garbage filter to discard it. No sample execution or external endpoint access is needed.
